/**
 * @file esp32_probe.ino
 * @brief ESP32 Edge Network Traffic Anomaly Detection Probe
 * 
 * Pipeline:
 *  1. Bắt gói tin WiFi ở chế độ Promiscuous Mode (bắt các khung 802.11).
 *  2. Trích xuất đặc trưng: Tốc độ gói (packet_rate), lưu lượng byte (byte_rate),
 *     tỷ lệ TCP/UDP/ICMP, tỷ lệ cờ SYN, số lượng port đích duy nhất.
 *  3. (Tùy chọn) Chạy bộ suy luận TinyML cục bộ trên ESP32.
 *  4. Đóng gói telemetry JSON và gửi qua Mosquitto MQTT tới Host Server.
 * 
 * Thư viện yêu cầu:
 *  - WiFi (Built-in ESP32)
 *  - PubSubClient by Nick O'Leary
 *  - ArduinoJson by Benoit Blanchon (phiên bản 6.x hoặc 7.x)
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"
#include "config.h"
#include "tinyml_model.h"

// Biến điều khiển MQTT & WiFi
WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Cấu trúc lưu trữ thống kê lưu lượng trong 1 chu kỳ lấy mẫu
struct TrafficWindowStats {
  volatile uint32_t total_packets;
  volatile uint32_t total_bytes;
  volatile uint32_t tcp_packets;
  volatile uint32_t udp_packets;
  volatile uint32_t icmp_packets;
  volatile uint32_t syn_packets;
  volatile uint32_t ack_packets;
  volatile uint32_t unique_ports_count;
};

static TrafficWindowStats currentStats = {0, 0, 0, 0, 0, 0, 0, 0};

// Tracking ports đơn giản để tính entropy/unique ports mà không tốn RAM
#define PORT_BITMAP_SIZE 256
static uint8_t portHashBitmap[PORT_BITMAP_SIZE / 8];

// Timers
unsigned long lastSampleTime = 0;
unsigned long lastHopTime = 0;
uint8_t currentChannel = WIFI_CHANNEL;

// --------------------------------------------------------------------
// PROMISCUOUS PACKET SNIFFER CALLBACK (ESP32 CORE)
// --------------------------------------------------------------------
void IRAM_ATTR wifi_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  currentStats.total_packets++;
  currentStats.total_bytes += len;

  // Khung 802.11 Data Packet chứa LLC/SNAP và IP header
  // Thông thường Header 802.11 chiếm khoảng 24-30 bytes
  if (len > 34) {
    // Tìm IP protocol offset (ước lượng offset IP header cơ bản trên 802.11)
    // 0x0800: IPv4
    for (int offset = 24; offset < len - 20; offset++) {
      if (payload[offset] == 0x45) { // IPv4 Version 4, IHL 5 (0x45)
        uint8_t ipProtocol = payload[offset + 9];
        uint16_t totalIpLen = (payload[offset + 2] << 8) | payload[offset + 3];

        if (ipProtocol == 6) { // TCP
          currentStats.tcp_packets++;
          int tcpOffset = offset + 20;
          if (tcpOffset + 13 < len) {
            uint16_t dstPort = (payload[tcpOffset + 2] << 8) | payload[tcpOffset + 3];
            uint8_t tcpFlags = payload[tcpOffset + 13];

            // Cờ TCP: SYN=0x02, ACK=0x10, SYN-ACK=0x12
            if ((tcpFlags & 0x02) && !(tcpFlags & 0x10)) {
              currentStats.syn_packets++;
            }
            if (tcpFlags & 0x10) {
              currentStats.ack_packets++;
            }

            // Đánh dấu bitmap port
            uint8_t hash = (uint8_t)(dstPort % PORT_BITMAP_SIZE);
            if (!(portHashBitmap[hash / 8] & (1 << (hash % 8)))) {
              portHashBitmap[hash / 8] |= (1 << (hash % 8));
              currentStats.unique_ports_count++;
            }
          }
          break;
        } else if (ipProtocol == 17) { // UDP
          currentStats.udp_packets++;
          int udpOffset = offset + 20;
          if (udpOffset + 4 < len) {
            uint16_t dstPort = (payload[udpOffset + 2] << 8) | payload[udpOffset + 3];
            uint8_t hash = (uint8_t)(dstPort % PORT_BITMAP_SIZE);
            if (!(portHashBitmap[hash / 8] & (1 << (hash % 8)))) {
              portHashBitmap[hash / 8] |= (1 << (hash % 8));
              currentStats.unique_ports_count++;
            }
          }
          break;
        } else if (ipProtocol == 1) { // ICMP
          currentStats.icmp_packets++;
          break;
        }
      }
    }
  }
}

// --------------------------------------------------------------------
// MQTT CONNECTION & UTILITIES
// --------------------------------------------------------------------
void setupWiFi() {
  Serial.println("\n[WiFi] Dang ket noi den WiFi: " WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Ket noi thanh cong! IP: " + WiFi.localIP().toString());
  } else {
    Serial.println("\n[WiFi] Canh bao: Khong the ket noi WiFi, chay che do Promiscuous doc lap.");
  }
}

void reconnectMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("[MQTT] Dang ket noi den Broker " MQTT_BROKER_HOST "...");
    if (mqttClient.connect(MQTT_CLIENT_ID)) {
      Serial.println(" Ket noi thanh cong!");
      // Thông báo trạng thái Online
      mqttClient.publish(TOPIC_DEVICE_STATUS, "{\"status\": \"online\", \"device_id\": \"" MQTT_CLIENT_ID "\"}");
    } else {
      Serial.print(" That bai, ma loi rc=");
      Serial.print(mqttClient.state());
      Serial.println(". Thu lai sau 3 giay...");
      delay(3000);
    }
  }
}

// --------------------------------------------------------------------
// SETUP & LOOP
// --------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("==================================================");
  Serial.println("  EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE ");
  Serial.println("==================================================");

  // Kết nối WiFi & cấu hình MQTT
  setupWiFi();
  mqttClient.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
  mqttClient.setBufferSize(512);

  // Cấu hình ESP32 Promiscuous Mode (Packet Sniffer)
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_rx_cb);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("[Sniffer] Promiscuous mode bat tren kenh %d!\n", currentChannel);

  lastSampleTime = millis();
  lastHopTime = millis();
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    if (!mqttClient.connected()) {
      reconnectMQTT();
    }
    mqttClient.loop();
  }

  // Nhảy kênh WiFi nếu được bật
  if (ENABLE_CHANNEL_HOP && (millis() - lastHopTime > HOP_INTERVAL_MS)) {
    lastHopTime = millis();
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }

  // Hết chu kỳ lấy mẫu -> Đóng gói telemetry và publish
  if (millis() - lastSampleTime >= SAMPLING_WINDOW_MS) {
    unsigned long duration = millis() - lastSampleTime;
    lastSampleTime = millis();

    // Snapshot dữ liệu và reset bộ đếm an toàn
    TrafficWindowStats snap = currentStats;
    currentStats = {0, 0, 0, 0, 0, 0, 0, 0};
    memset(portHashBitmap, 0, sizeof(portHashBitmap));

    // Tính toán các đặc trưng (Features)
    float seconds = duration / 1000.0;
    float packet_rate = (seconds > 0) ? (snap.total_packets / seconds) : 0;
    float byte_rate = (seconds > 0) ? (snap.total_bytes / seconds) : 0;
    float avg_packet_size = (snap.total_packets > 0) ? ((float)snap.total_bytes / snap.total_packets) : 0;

    float syn_ratio = (snap.tcp_packets > 0) ? ((float)snap.syn_packets / snap.tcp_packets) : 0.0;
    float ack_ratio = (snap.tcp_packets > 0) ? ((float)snap.ack_packets / snap.tcp_packets) : 0.0;
    float udp_ratio = (snap.total_packets > 0) ? ((float)snap.udp_packets / snap.total_packets) : 0.0;
    float icmp_ratio = (snap.total_packets > 0) ? ((float)snap.icmp_packets / snap.total_packets) : 0.0;

    // Đóng gói JSON
    StaticJsonDocument<512> doc;
    doc["device_id"] = MQTT_CLIENT_ID;
    doc["timestamp"] = millis();
    doc["channel"] = currentChannel;
    doc["packet_rate"] = round(packet_rate * 100) / 100.0;
    doc["byte_rate"] = round(byte_rate * 100) / 100.0;
    doc["avg_packet_size"] = round(avg_packet_size * 10) / 10.0;
    doc["syn_ratio"] = round(syn_ratio * 1000) / 1000.0;
    doc["ack_ratio"] = round(ack_ratio * 1000) / 1000.0;
    doc["udp_ratio"] = round(udp_ratio * 1000) / 1000.0;
    doc["icmp_ratio"] = round(icmp_ratio * 1000) / 1000.0;
    doc["unique_dst_ports"] = snap.unique_ports_count;
    doc["tcp_count"] = snap.tcp_packets;
    doc["udp_count"] = snap.udp_packets;
    doc["icmp_count"] = snap.icmp_packets;

    // -------------------------------------------------------------
    // Suy luan TinyML truc tiep tren chip ESP32 (Phase 2 On-Device AI)
    // -------------------------------------------------------------
    float feature_vec[8] = {
      packet_rate,
      byte_rate,
      avg_packet_size,
      syn_ratio,
      ack_ratio,
      udp_ratio,
      icmp_ratio,
      (float)snap.unique_ports_count
    };
    int tinyml_class_idx = 0;
    float tinyml_anomaly_score = 0.0f;
    int is_tinyml_anomaly = tinyml_predict_anomaly(feature_vec, &tinyml_class_idx, &tinyml_anomaly_score);
    const char* tinyml_threat_name = tinyml_get_threat_name(tinyml_class_idx);

    bool local_anomaly = (is_tinyml_anomaly == 1);
    const char* local_attack = tinyml_threat_name;

    doc["edge_flag"] = local_anomaly;
    doc["edge_prediction"] = local_attack;
    doc["edge_anomaly_score"] = tinyml_anomaly_score;
    doc["edge_model"] = "TinyML-DecisionTree-v1";

    char jsonBuffer[512];
    serializeJson(doc, jsonBuffer);

    // In Serial giám sát
    Serial.printf("[Telemetry] Pkts/s: %.1f | Bytes/s: %.0f | SYN: %.2f | Ports: %d | Threat: %s\n",
                  packet_rate, byte_rate, syn_ratio, snap.unique_ports_count, local_attack);

    // Gửi qua MQTT
    if (mqttClient.connected()) {
      mqttClient.publish(TOPIC_TRAFFIC_TELEMETRY, jsonBuffer);
      if (local_anomaly) {
        mqttClient.publish(TOPIC_LOCAL_ALERT, jsonBuffer);
      }
    }
  }
}
