#include "sniffer.h"
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>

static portMUX_TYPE statsMux = portMUX_INITIALIZER_UNLOCKED;
struct StatsGuard {
  StatsGuard() { portENTER_CRITICAL(&statsMux); }
  ~StatsGuard() { portEXIT_CRITICAL(&statsMux); }
};

static TrafficWindowStats currentStats = {};
static DetectedWifiNetwork detectedWifiNetworks[MAX_DETECTED_SSIDS];
static volatile uint8_t detectedWifiCount = 0;
static RadioFrame radioFrames[RADIO_FRAME_CAPACITY];
static uint8_t radioHead = 0, radioTail = 0, radioCount = 0;
static uint32_t radioSequence = 0, lastRadioSampleMs = 0;
static bool radioSampleStarted = false;
static uint8_t probeMac[6];
static bool probeMacAvailable = false;

// BSSID và kênh của AP mục tiêu được cấu hình trong .env / CLI
static uint8_t targetBssid[6] = {0};
static volatile bool targetBssidFilterActive = false;
static volatile uint8_t targetChannel = 1;

void setTargetNetworkFilter(const uint8_t* bssid, uint8_t channel) {
  if (!bssid) return;

  bool changed = false;
  {
    StatsGuard guard;
    if (memcmp(targetBssid, bssid, 6) != 0 || targetChannel != channel || !targetBssidFilterActive) {
      memcpy(targetBssid, bssid, 6);
      targetChannel = channel;
      targetBssidFilterActive = true;
      changed = true;
    }
  }

  if (changed) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[Sniffer] Khoa bo loc vao mang muc tieu BSSID: %02X:%02X:%02X:%02X:%02X:%02X tren kenh %d!\n",
                  bssid[0], bssid[1], bssid[2],
                  bssid[3], bssid[4], bssid[5],
                  channel);
  }
}

void clearTargetNetworkFilter() {
  if (!targetBssidFilterActive) return;
  StatsGuard guard;
  targetBssidFilterActive = false;
}

bool isTargetNetworkFilterActive() {
  return targetBssidFilterActive;
}

// Tracking ports đơn giản để tính entropy/unique ports mà không tốn RAM
#define PORT_BITMAP_SIZE 256
static uint8_t portHashBitmap[PORT_BITMAP_SIZE / 8];

void IRAM_ATTR wifi_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  // CHỈ BẮT MẠNG ĐÃ ĐƯỢC CẤU HÌNH: Nếu chưa kích hoạt bộ lọc theo BSSID của mạng đích, bỏ qua toàn bộ gói trôi nổi!
  if (!targetBssidFilterActive) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (pkt->rx_ctrl.rx_state != 0 || len < 4) return;
  len -= 4; // ESP-IDF sig_len includes FCS; LINKTYPE_IEEE802_11 does not.

  // 802.11 header tối thiểu phải có 24 bytes để chứa đủ Addr1 (RA), Addr2 (TA), Addr3 (BSSID/DA/SA)
  if (len < 24) return;

  const uint8_t *addr1 = payload + 4;
  const uint8_t *addr2 = payload + 10;
  const uint8_t *addr3 = payload + 16;

  // BỘ LỌC MẠNG ĐÍCH (Target BSSID Filter):
  // Gói tin bắt buộc phải thuộc mạng đã cấu hình (Addr1, Addr2 hoặc Addr3 phải khớp với targetBssid)
  bool belongsToTarget = (memcmp(addr1, targetBssid, 6) == 0 ||
                          memcmp(addr2, targetBssid, 6) == 0 ||
                          memcmp(addr3, targetBssid, 6) == 0);
  if (!belongsToTarget) return; // Loại bỏ hoàn toàn các gói tin từ các mạng Wi-Fi khác xung quanh!

  // Bỏ qua gói tin của chính probe (tránh loopback telemetry MQTT của chính nó)
  if (type == WIFI_PKT_DATA && probeMacAvailable &&
      (memcmp(addr1, probeMac, 6) == 0 || memcmp(addr2, probeMac, 6) == 0))
    return;

  StatsGuard guard;
  currentStats.total_packets++;
  currentStats.total_bytes += len;

  uint8_t fc0 = payload[0];
  uint8_t frameType = (fc0 >> 2) & 0x03;
  uint8_t frameSubtype = (fc0 >> 4) & 0x0F;

  if (frameType == 0) { // Management frame
    currentStats.mgmt_packets++;
    if (frameSubtype == 12) { // 0x0C = Deauthentication
      currentStats.deauth_packets++;
    } else if (frameSubtype == 10) { // 0x0A = Disassociation
      currentStats.disassoc_packets++;
    }
  } else if (frameType == 1) { // Control frame
    currentStats.control_packets++;
  } else if (frameType == 2) { // Data frame
    currentStats.data_packets++;
    if (payload[1] & 0x40) { // Protected Frame bit (WPA2/WPA3)
      currentStats.protected_data_packets++;
    }
  }

  // Wi-Fi task context: fixed-capacity copy only, never serialization/I/O.
  if (type == WIFI_PKT_DATA && len >= 24) {
    uint32_t now = millis();
    if (radioSampleStarted && (uint32_t)(now - lastRadioSampleMs) < RADIO_FRAME_INTERVAL_MS) {
      currentStats.radio_sample_skipped++;
    } else if (radioCount == RADIO_FRAME_CAPACITY) {
      currentStats.radio_queue_dropped++;
    } else {
      RadioFrame& frame = radioFrames[radioTail];
      frame.sequence = radioSequence++;
      frame.uptime_ms = now;
      frame.original_length = len;
      frame.captured_length = len < RADIO_FRAME_MAX_BYTES ? len : RADIO_FRAME_MAX_BYTES;
      frame.rssi = pkt->rx_ctrl.rssi;
      frame.channel = pkt->rx_ctrl.channel;
      memcpy(frame.payload, payload, frame.captured_length);
      radioTail = (radioTail + 1) % RADIO_FRAME_CAPACITY;
      radioCount++;
      lastRadioSampleMs = now;
      radioSampleStarted = true;
    }
  }

  // 1. Trích xuất Tên Mạng WiFi (SSID) chỉ từ Beacon/Probe Response của chính mạng mục tiêu (targetBssid)
  if (type == WIFI_PKT_MGMT && len >= 38) {
    uint8_t frameControl = payload[0];
    if ((frameControl & 0xFC) == 0x80 && memcmp(addr3, targetBssid, 6) == 0) {
      if (payload[36] == 0) {
        uint8_t ssidLen = payload[37];
        if (ssidLen > 0 && ssidLen <= 32 && (38 + ssidLen <= len)) {
          char tempSsid[33];
          bool validAscii = true;
          for (uint8_t i = 0; i < ssidLen; i++) {
            char c = (char)payload[38 + i];
            if (c < 32 || c > 126) {
              validAscii = false;
              break;
            }
            tempSsid[i] = c;
          }
          tempSsid[ssidLen] = '\0';

          if (validAscii && strlen(tempSsid) > 0) {
            StatsGuard mgmtGuard;
            detectedWifiCount = 1;
            strncpy(detectedWifiNetworks[0].ssid, tempSsid, 32);
            detectedWifiNetworks[0].ssid[32] = '\0';
            detectedWifiNetworks[0].rssi = pkt->rx_ctrl.rssi;
            detectedWifiNetworks[0].channel = pkt->rx_ctrl.channel;
            detectedWifiNetworks[0].last_seen_ms = millis();
          }
        }
      }
    }
    return;
  }

  // 2. Phân tích gói Data (802.11 Data Frame)
  if (len < 24) return;
  if (payload[1] & 0x40) return; // Protected frames cannot be parsed as plaintext.
  if (frameType != 2) return;

  uint8_t headerLen = 24;
  if ((payload[0] & 0x80) != 0) headerLen += 2; // QoS control
  if ((payload[1] & 0x03) == 0x03) headerLen += 6; // 4-address frame
  if ((payload[0] & 0x80) && (payload[1] & 0x80)) headerLen += 4; // HT control

  if (len < headerLen + 8) return;

  // LLC/SNAP header (8 bytes): AA AA 03 00 00 00 [Type 2 bytes]
  const uint8_t *llc = payload + headerLen;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
      llc[3] != 0 || llc[4] != 0 || llc[5] != 0) return;
  uint16_t etherType = (llc[6] << 8) | llc[7];

  // Chỉ phân tích gói IPv4 (EtherType = 0x0800)
  if (etherType != 0x0800) return;

  uint8_t ipHeaderStart = headerLen + 8;
  if (len < ipHeaderStart + 20) return;

  const uint8_t *ipHeader = payload + ipHeaderStart;
  uint8_t ipVer = (ipHeader[0] >> 4) & 0x0F;
  if (ipVer != 4) return;

  uint8_t ipHeaderLen = (ipHeader[0] & 0x0F) * 4;
  if (ipHeaderLen < 20 || len < ipHeaderStart + ipHeaderLen) return;
  uint16_t ipLength = ((uint16_t)ipHeader[2] << 8) | ipHeader[3];
  if (ipLength < ipHeaderLen || len < ipHeaderStart + ipLength) return;
  if ((ipHeader[6] & 0x1F) || ipHeader[7]) return; // Non-initial IP fragment.
  uint8_t protocol = ipHeader[9];

  uint8_t transportStart = ipHeaderStart + ipHeaderLen;

  if (protocol == 6) { // TCP
    currentStats.tcp_packets++;
    if (ipLength >= ipHeaderLen + 20) {
      const uint8_t *tcpHeader = payload + transportStart;
      uint16_t dstPort = (tcpHeader[2] << 8) | tcpHeader[3];
      uint8_t flags = tcpHeader[13];

      if (flags & 0x02) currentStats.syn_packets++;
      if (flags & 0x10) currentStats.ack_packets++;

      uint8_t portHash = (uint8_t)((dstPort ^ (dstPort >> 8)) & 0xFF);
      uint8_t byteIdx = portHash / 8;
      uint8_t bitIdx = portHash % 8;
      if (!(portHashBitmap[byteIdx] & (1 << bitIdx))) {
        portHashBitmap[byteIdx] |= (1 << bitIdx);
        currentStats.unique_ports_count++;
      }
    }
  } else if (protocol == 17) { // UDP
    currentStats.udp_packets++;
    if (ipLength >= ipHeaderLen + 8) {
      const uint8_t *udpHeader = payload + transportStart;
      uint16_t dstPort = (udpHeader[2] << 8) | udpHeader[3];

      uint8_t portHash = (uint8_t)((dstPort ^ (dstPort >> 8)) & 0xFF);
      uint8_t byteIdx = portHash / 8;
      uint8_t bitIdx = portHash % 8;
      if (!(portHashBitmap[byteIdx] & (1 << bitIdx))) {
        portHashBitmap[byteIdx] |= (1 << bitIdx);
        currentStats.unique_ports_count++;
      }
    }
  } else if (protocol == 1) { // ICMP
    currentStats.icmp_packets++;
  }
}

void initSniffer(uint8_t initialChannel) {
  esp_wifi_set_promiscuous(false);
  probeMacAvailable = esp_wifi_get_mac(WIFI_IF_STA, probeMac) == ESP_OK;
  esp_wifi_set_channel(initialChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_rx_cb);
  esp_wifi_set_promiscuous(true);
  Serial.printf("[Sniffer] Promiscuous mode bat tren kenh %d!\n", initialChannel);
}

TrafficWindowStats captureAndResetStats() {
  TrafficWindowStats snap;
  StatsGuard guard;
  snap = currentStats;
  currentStats.total_packets = 0;
  currentStats.total_bytes = 0;
  currentStats.tcp_packets = 0;
  currentStats.udp_packets = 0;
  currentStats.icmp_packets = 0;
  currentStats.syn_packets = 0;
  currentStats.ack_packets = 0;
  currentStats.unique_ports_count = 0;
  currentStats.mgmt_packets = 0;
  currentStats.control_packets = 0;
  currentStats.data_packets = 0;
  currentStats.deauth_packets = 0;
  currentStats.disassoc_packets = 0;
  currentStats.protected_data_packets = 0;
  currentStats.radio_queue_dropped = 0;
  currentStats.radio_sample_skipped = 0;
  memset(portHashBitmap, 0, sizeof(portHashBitmap));

  return snap;
}

bool popRadioFrame(RadioFrame* output) {
  if (!output || radioCount == 0) return false;
  StatsGuard guard;
  if (!radioCount) return false;
  *output = radioFrames[radioHead];
  radioHead = (radioHead + 1) % RADIO_FRAME_CAPACITY;
  radioCount--;
  return true;
}

void handleChannelHopping(uint8_t* inoutChannel, unsigned long* inoutLastHopTime) {
  // Hopping bị vô hiệu hóa hoàn toàn để probe luôn cố định tại kênh của AP mục tiêu
  return;
}

uint8_t copyDetectedWifiNetworks(DetectedWifiNetwork* output, uint8_t capacity) {
  if (!output || capacity == 0 || detectedWifiCount == 0) return 0;
  StatsGuard guard;
  uint8_t count = detectedWifiCount < capacity ? detectedWifiCount : capacity;
  memcpy(output, detectedWifiNetworks, count * sizeof(DetectedWifiNetwork));
  return count;
}

void recordGatewayPacketStats(size_t length, uint8_t protocol, bool isSyn, bool isAck, uint16_t srcPort, uint16_t dstPort) {
  StatsGuard guard;
  currentStats.total_packets++;
  currentStats.total_bytes += length;
  currentStats.data_packets++;
  if (protocol == 6) { // TCP
    currentStats.tcp_packets++;
    if (isSyn) currentStats.syn_packets++;
    if (isAck) currentStats.ack_packets++;
  } else if (protocol == 17) { // UDP
    currentStats.udp_packets++;
  } else if (protocol == 1) { // ICMP
    currentStats.icmp_packets++;
  }
  uint16_t p = dstPort > 0 ? dstPort : srcPort;
  if (p > 0) {
    uint8_t portHash = (uint8_t)(p % PORT_BITMAP_SIZE);
    uint8_t byteIdx = portHash / 8;
    uint8_t bitIdx = portHash % 8;
    if (!(portHashBitmap[byteIdx] & (1 << bitIdx))) {
      portHashBitmap[byteIdx] |= (1 << bitIdx);
      currentStats.unique_ports_count++;
    }
  }
}
