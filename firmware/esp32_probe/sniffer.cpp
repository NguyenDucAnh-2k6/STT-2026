#include "sniffer.h"
#include <WiFi.h>

static TrafficWindowStats currentStats = {0, 0, 0, 0, 0, 0, 0, 0};
static DetectedWifiNetwork detectedWifiNetworks[MAX_DETECTED_SSIDS];
static volatile uint8_t detectedWifiCount = 0;

// Tracking ports đơn giản để tính entropy/unique ports mà không tốn RAM
#define PORT_BITMAP_SIZE 256
static uint8_t portHashBitmap[PORT_BITMAP_SIZE / 8];

void IRAM_ATTR wifi_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  currentStats.total_packets++;
  currentStats.total_bytes += len;

  // 1. Trích xuất Tên Mạng WiFi (SSID) từ các khung Management (Beacon / Probe)
  if (type == WIFI_PKT_MGMT && len >= 38) {
    uint8_t frameControl = payload[0];
    if ((frameControl & 0xFC) == 0x80 || (frameControl & 0xFC) == 0x50) {
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
            int foundIdx = -1;
            for (uint8_t i = 0; i < detectedWifiCount; i++) {
              if (strcmp(detectedWifiNetworks[i].ssid, tempSsid) == 0) {
                foundIdx = i;
                break;
              }
            }
            if (foundIdx >= 0) {
              detectedWifiNetworks[foundIdx].rssi = pkt->rx_ctrl.rssi;
              detectedWifiNetworks[foundIdx].channel = pkt->rx_ctrl.channel;
              detectedWifiNetworks[foundIdx].last_seen_ms = millis();
            } else if (detectedWifiCount < MAX_DETECTED_SSIDS) {
              uint8_t idx = detectedWifiCount++;
              strncpy(detectedWifiNetworks[idx].ssid, tempSsid, 32);
              detectedWifiNetworks[idx].ssid[32] = '\0';
              detectedWifiNetworks[idx].rssi = pkt->rx_ctrl.rssi;
              detectedWifiNetworks[idx].channel = pkt->rx_ctrl.channel;
              detectedWifiNetworks[idx].last_seen_ms = millis();
            }
          }
        }
      }
    }
    return;
  }

  // 2. Phân tích gói Data (802.11 Data Frame)
  if (len < 24) return;
  uint8_t frameControl = payload[0];
  uint8_t frameType = (frameControl >> 2) & 0x03;
  if (frameType != 2) return;

  uint8_t headerLen = 24;
  if ((payload[0] & 0x80) != 0) headerLen += 2; // QoS control
  if ((payload[1] & 0x03) == 0x03) headerLen += 6; // 4-address frame

  if (len < headerLen + 8) return;

  // LLC/SNAP header (8 bytes): AA AA 03 00 00 00 [Type 2 bytes]
  const uint8_t *llc = payload + headerLen;
  uint16_t etherType = (llc[6] << 8) | llc[7];

  // Chỉ phân tích gói IPv4 (EtherType = 0x0800)
  if (etherType != 0x0800) return;

  uint8_t ipHeaderStart = headerLen + 8;
  if (len < ipHeaderStart + 20) return;

  const uint8_t *ipHeader = payload + ipHeaderStart;
  uint8_t ipVer = (ipHeader[0] >> 4) & 0x0F;
  if (ipVer != 4) return;

  uint8_t ipHeaderLen = (ipHeader[0] & 0x0F) * 4;
  uint8_t protocol = ipHeader[9];

  uint8_t transportStart = ipHeaderStart + ipHeaderLen;

  if (protocol == 6) { // TCP
    currentStats.tcp_packets++;
    if (len >= transportStart + 20) {
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
    if (len >= transportStart + 8) {
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
  esp_wifi_set_channel(initialChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_rx_cb);
  esp_wifi_set_promiscuous(true);
  Serial.printf("[Sniffer] Promiscuous mode bat tren kenh %d!\n", initialChannel);
}

TrafficWindowStats captureAndResetStats() {
  TrafficWindowStats snap;
  noInterrupts();
  snap = currentStats;
  currentStats.total_packets = 0;
  currentStats.total_bytes = 0;
  currentStats.tcp_packets = 0;
  currentStats.udp_packets = 0;
  currentStats.icmp_packets = 0;
  currentStats.syn_packets = 0;
  currentStats.ack_packets = 0;
  currentStats.unique_ports_count = 0;
  memset(portHashBitmap, 0, sizeof(portHashBitmap));
  interrupts();
  return snap;
}

void handleChannelHopping(uint8_t* inoutChannel, unsigned long* inoutLastHopTime) {
#if SNIFFER_MODE_ALL_NETWORKS
  unsigned long hopInterval = FAST_HOP_INTERVAL_MS;
  bool doHop = true;
#else
  unsigned long hopInterval = HOP_INTERVAL_MS;
  bool doHop = ENABLE_CHANNEL_HOP;
#endif

  if (doHop && (millis() - *inoutLastHopTime > hopInterval)) {
    *inoutLastHopTime = millis();
    *inoutChannel = (*inoutChannel % 13) + 1;
    esp_wifi_set_channel(*inoutChannel, WIFI_SECOND_CHAN_NONE);
  }
}

const DetectedWifiNetwork* getDetectedWifiNetworks() {
  return detectedWifiNetworks;
}

uint8_t getDetectedWifiCount() {
  return detectedWifiCount;
}
