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

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiMulti.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "esp_wifi.h"
#include "config.h"
#include "tinyml_model.h"

// Biến điều khiển ngoại vi màn hình OLED SSD1306
#if ENABLE_OLED
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
bool oledReady = false;
#endif

// Biến điều khiển MQTT & WiFi Đa Mạng (WiFiMulti) & UDP Auto-Discovery
WiFiClient espClient;
PubSubClient mqttClient(espClient);
WiFiMulti wifiMulti;
WiFiUDP udpDiscovery;
const uint16_t UDP_DISCOVERY_PORT = 18830;
char currentBrokerHost[64] = MQTT_BROKER_HOST;

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
    // Tim IP protocol offset (trong vung Header 802.11 / LLC SNAP tu offset 24 den toi da 42)
    int maxSearch = (len - 20 < 42) ? (len - 20) : 42;
    for (int offset = 24; offset < maxSearch; offset++) {
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
void checkUdpDiscovery() {
  int packetSize = udpDiscovery.parsePacket();
  if (packetSize > 0) {
    char buf[128];
    int len = udpDiscovery.read(buf, sizeof(buf) - 1);
    if (len > 0) {
      buf[len] = '\0';
      StaticJsonDocument<128> doc;
      DeserializationError err = deserializeJson(doc, buf);
      if (!err && doc.containsKey("broker_ip")) {
        const char* new_ip = doc["broker_ip"];
        if (new_ip && strlen(new_ip) > 6 && strcmp(currentBrokerHost, new_ip) != 0) {
          strncpy(currentBrokerHost, new_ip, sizeof(currentBrokerHost) - 1);
          mqttClient.setServer(currentBrokerHost, MQTT_BROKER_PORT);
          Serial.printf("[AutoDiscovery] Phat hien va cap nhat Broker IP moi qua UDP: %s!\n", currentBrokerHost);
        }
      }
    }
  }
}

void setupWiFi() {
#if SNIFFER_MODE_ALL_NETWORKS
  Serial.println(F("\n=================================================="));
  Serial.println(F(" [Sniffer] CHE DO FULL-SPECTRUM ALL-NETWORKS"));
  Serial.println(F("  * Khong rang buoc AP, radio tu do nhay 13 kenh!"));
  Serial.println(F("  * Bat tron moi goi tin tu tat ca router & thiet bi xung quanh!"));
  Serial.println(F("  * Telemetry duoc day ve Data Lake qua cap USB Serial 115200 baud."));
  Serial.println(F("=================================================="));
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
#if ENABLE_OLED
  if (oledReady) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println(F("AERO EDGE AI SOC"));
    display.drawLine(0, 9, 128, 9, SSD1306_WHITE);
    display.setCursor(0, 14);
    display.println(F("ALL-NETWORKS MODE"));
    display.setCursor(0, 26);
    display.println(F("HOPPING CH 1..13"));
    display.setCursor(0, 38);
    display.println(F("Uplink: USB Serial"));
    display.display();
    delay(1000);
  }
#endif
  return;
#endif

  Serial.println(F("\n[WiFi] Khoi dong WiFiMulti tu dong ket noi AP tot nhat..."));
#if ENABLE_OLED
  if (oledReady) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println(F("AERO EDGE AI SOC"));
    display.drawLine(0, 9, 128, 9, SSD1306_WHITE);
    display.setCursor(0, 14);
    display.print(F("WiFi: "));
    display.println(WIFI_SSID);
    display.setCursor(0, 26);
    display.println(F("Scanning APs..."));
    display.display();
  }
#endif

  WiFi.mode(WIFI_STA);
  wifiMulti.addAP(WIFI_SSID, WIFI_PASSWORD);
  // Đăng ký các AP dự phòng đã biết
  if (String(WIFI_SSID) != "Nokia 5.3") {
    wifiMulti.addAP("Nokia 5.3", "ducanh161106");
  }
  if (String(WIFI_SSID) != "Phong 401") {
    wifiMulti.addAP("Phong 401", "99999999");
  }

  int attempts = 0;
  while (wifiMulti.run() != WL_CONNECTED && attempts < 15) {
    delay(400);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[WiFi] Ket noi thanh cong toi SSID: " + WiFi.SSID() + "! IP: " + WiFi.localIP().toString());
    currentChannel = WiFi.channel();
    udpDiscovery.begin(UDP_DISCOVERY_PORT);
#if ENABLE_OLED
    if (oledReady) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println(F("AERO EDGE AI SOC"));
      display.drawLine(0, 9, 128, 9, SSD1306_WHITE);
      display.setCursor(0, 14);
      display.printf("WiFi: %s [OK]\n", WiFi.SSID().c_str());
      display.setCursor(0, 26);
      display.printf("IP: %s\n", WiFi.localIP().toString().c_str());
      display.setCursor(0, 38);
      display.printf("Broker: %s\n", currentBrokerHost);
      display.display();
      delay(800);
    }
#endif
  } else {
    Serial.println(F("\n[WiFi] Chua ket noi duoc WiFi ngay. ESP32 chay che do Dual-Mode:"));
    Serial.println(F("       * Radio Promiscuous van hoat dong 100% doc lap de bat moi goi tin qua song!"));
    Serial.println(F("       * Du lieu van duoc truyen lien tuc ve Host PC qua cap USB Serial!"));
  }
}

void reconnectMQTT() {
  static unsigned long lastMqttRetry = 0;
  if (!mqttClient.connected()) {
    if (millis() - lastMqttRetry > 4000) {
      lastMqttRetry = millis();
      Serial.printf("[MQTT] Dang ket noi den Broker %s:%d...\n", currentBrokerHost, MQTT_BROKER_PORT);
      if (mqttClient.connect(MQTT_CLIENT_ID)) {
        Serial.println(F("[MQTT] Ket noi thanh cong!"));
        // Thông báo trạng thái Online kèm địa chỉ IP
        String statusMsg = String("{\"status\": \"online\", \"device_id\": \"") + MQTT_CLIENT_ID + "\", \"ip\": \"" + WiFi.localIP().toString() + "\"}";
        mqttClient.publish(TOPIC_DEVICE_STATUS, statusMsg.c_str());
      } else {
        Serial.printf("[MQTT] That bai (rc=%d), se thu lai sau 4s...\n", mqttClient.state());
      }
    }
  }
}

#if ENABLE_OLED
uint8_t activeSclPin = PIN_I2C_SCL;

bool initOLED() {
  uint8_t scl_candidates[] = {PIN_I2C_SCL, 23, 22};

  for (size_t s = 0; s < sizeof(scl_candidates); s++) {
    uint8_t test_scl = scl_candidates[s];
    if (s > 0 && test_scl == scl_candidates[0]) continue; // Không quét lại nếu trùng

    pinMode(PIN_I2C_SDA, INPUT_PULLUP);
    pinMode(test_scl, INPUT_PULLUP);
    Wire.end();
    Wire.begin(PIN_I2C_SDA, test_scl);
    delay(80);
    Wire.setClock(100000); // 100kHz Standard Mode ổn định với dây cắm breadboard

    Serial.printf("[I2C] Dang quet bus tren SDA (GPIO%d) va SCL/SCK (GPIO%d)...\n", PIN_I2C_SDA, test_scl);
    uint8_t detected_addr = 0;
    int dev_count = 0;
    for (uint8_t addr = 1; addr < 127; addr++) {
      Wire.beginTransmission(addr);
      if (Wire.endTransmission() == 0) {
        Serial.printf("[I2C] -> Phat hien thiet bi tai dia chi: 0x%02X (SCL: GPIO%d)!\n", addr, test_scl);
        dev_count++;
        if (addr == 0x3C || addr == 0x3D) {
          detected_addr = addr;
        }
      }
    }

    // Nếu scan không nhận do trễ bus, thử khởi động trực tiếp với địa chỉ chuẩn 0x3C
    if (detected_addr == 0) {
      detected_addr = SCREEN_ADDRESS;
    }

    if (display.begin(SSD1306_SWITCHCAPVCC, detected_addr, false, false)) {
      oledReady = true;
      activeSclPin = test_scl;
      display.ssd1306_command(SSD1306_SETCONTRAST);
      display.ssd1306_command(0xFF);
      display.clearDisplay();
      display.setTextColor(SSD1306_WHITE);
      display.setTextSize(1);
      display.setCursor(0, 0);
      display.println(F("===================="));
      display.println(F("  AERO EDGE AI SOC"));
      display.println(F("  ESP32 SNIFFER OK"));
      display.println(F("===================="));
      display.printf("I2C Addr: 0x%02X\n", detected_addr);
      display.printf("SDA:D%d | SCK:D%d\n", PIN_I2C_SDA, test_scl);
      display.display();
      delay(800);
      Serial.printf("[OLED] Khoi tao SSD1306 THANH CONG tai dia chi 0x%02X (SDA: GPIO%d, SCK: GPIO%d)!\n",
                    detected_addr, PIN_I2C_SDA, test_scl);
      return true;
    }
  }

  Serial.println(F("[OLED] Canh bao: Khong the khoi dong SSD1306!"));
  Serial.println(F("       Kiem tra day: Do (3V3->VDD), Den (GND->GND), Vang (D23->SCK), Xanh (D21->SDA)"));
  Serial.println(F("       Goi y: Neu man hinh cua ban la loai nho 0.91\" (128x32), hay doi SCREEN_HEIGHT thanh 32 trong config.h!"));
  return false;
}
#endif

// --------------------------------------------------------------------
// SETUP & LOOP
// --------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("==================================================");
  Serial.println("  EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE ");
  Serial.println("==================================================");

  // Cấu hình ngoại vi cảnh báo: LED Đỏ, LED Onboard D2 và Còi Chíp Buzzer
  pinMode(PIN_RED_LED, OUTPUT);
  pinMode(2, OUTPUT); // Đèn LED có sẵn trên bo mạch ESP32 (Onboard LED D2)
  pinMode(PIN_BUZZER, OUTPUT);
  digitalWrite(PIN_RED_LED, LOW);
  digitalWrite(2, LOW);
  digitalWrite(PIN_BUZZER, LOW);

  // Khởi tạo màn hình OLED SSD1306 (I2C) NGAY TỨC THÌ để người dùng thấy phản hồi
#if ENABLE_OLED
  initOLED();
#endif

  // Kết nối WiFi & cấu hình MQTT
  setupWiFi();
  mqttClient.setServer(currentBrokerHost, MQTT_BROKER_PORT);
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
#if ENABLE_OLED
  // Tự động quét và kích hoạt OLED nếu cắm sau hoặc khởi động chưa nhận (Auto-Recovery)
  if (!oledReady) {
    static unsigned long lastOledRetry = 0;
    if (millis() - lastOledRetry > 5000) {
      lastOledRetry = millis();
      initOLED();
    }
  }
#endif

#if SNIFFER_MODE_ALL_NETWORKS
  // Chế độ All-Networks: Luôn nhảy tuần tự liên tục 13 kênh (CH 1..13) với tốc độ cao
  if (millis() - lastHopTime > FAST_HOP_INTERVAL_MS) {
    lastHopTime = millis();
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }
#else
  // Chế độ AP-Locked: Duy trì kết nối WiFi đa mạng qua WiFiMulti và Auto-Discovery Broker
  if (wifiMulti.run() == WL_CONNECTED) {
    if (!mqttClient.connected()) {
      checkUdpDiscovery();
      reconnectMQTT();
    } else {
      mqttClient.loop();
    }
  }

  // Nhảy kênh WiFi nếu được bật và khi KHÔNG có kết nối WiFi Station
  if (WiFi.status() != WL_CONNECTED && ENABLE_CHANNEL_HOP && (millis() - lastHopTime > HOP_INTERVAL_MS)) {
    lastHopTime = millis();
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }
#endif

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
    doc["device_ip"] = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : "0.0.0.0";
    doc["timestamp"] = millis();
#if SNIFFER_MODE_ALL_NETWORKS
    doc["channel"] = "HOP(1-13)";
    doc["sniffer_mode"] = "all-networks";
#else
    doc["channel"] = String(currentChannel);
    doc["sniffer_mode"] = "ap-locked";
#endif
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
    // -------------------------------------------------------------
    // Suy luan Edge AI truc tiep tren chip ESP32 (8 dac trung luu luong)
    // -------------------------------------------------------------
    bool local_anomaly = false;
    const char* local_attack = "Normal";
    float tinyml_anomaly_score = 0.05f;

    // 1. Kich ban Port Scanning: nhieu port dich hoac ty le SYN cao tren luong vua
    if (snap.unique_ports_count >= 12 || (syn_ratio > 0.40f && packet_rate > 40.0f)) {
      local_anomaly = true;
      local_attack = "Port_Scanning";
      tinyml_anomaly_score = 0.88f;
    }
    // 2. Kich ban DDoS TCP (SYN Flood): ty le SYN don dap vuot troi
    else if (syn_ratio > 0.60f && packet_rate > 120.0f) {
      local_anomaly = true;
      local_attack = "DDoS_TCP";
      tinyml_anomaly_score = 0.95f;
    }
    // 3. Kich ban DDoS UDP (Volumetric Flood): bang thong lon hoac toc do UDP cuc cao
    else if ((udp_ratio > 0.60f && packet_rate > 350.0f) || (packet_rate > 600.0f && byte_rate > 250000.0f)) {
      local_anomaly = true;
      local_attack = "DDoS_UDP";
      tinyml_anomaly_score = 0.98f;
    }
    // 4. Kich ban DDoS ICMP Flood
    else if (icmp_ratio > 0.50f && packet_rate > 80.0f) {
      local_anomaly = true;
      local_attack = "DDoS_ICMP";
      tinyml_anomaly_score = 0.90f;
    }
    // 5. Kich ban Uploading (Data Exfiltration): bang thong lon nhung ty le SYN rat thap
    else if (byte_rate > 400000.0f && packet_rate > 200.0f && syn_ratio < 0.15f) {
      local_anomaly = true;
      local_attack = "Uploading";
      tinyml_anomaly_score = 0.78f;
    }
    // 6. Luu luong binh thuong (Normal)
    else {
      local_anomaly = false;
      local_attack = "Normal";
      tinyml_anomaly_score = 0.05f;
    }

    doc["edge_flag"] = local_anomaly;
    doc["edge_prediction"] = local_attack;
    doc["edge_anomaly_score"] = tinyml_anomaly_score;
    doc["edge_model"] = "TinyML-EdgeTree-v1";

    char jsonBuffer[512];
    serializeJson(doc, jsonBuffer);

    // -------------------------------------------------------------
    // Dieu khien Ngoai vi: LED Do, Coi Buzzer & Man hinh OLED
    // -------------------------------------------------------------
    if (local_anomaly) {
      // Phat hien bat thuong: Bat ca LED ngoai vi (D4) va LED co san tren ESP32 (D2)
      digitalWrite(PIN_RED_LED, HIGH);
      digitalWrite(2, HIGH);
      // Phat xung ngan an toan tranh sut ap nguon 3.3V (Brownout Reset)
      digitalWrite(PIN_BUZZER, HIGH);
      delay(25);
      digitalWrite(PIN_BUZZER, LOW);
    } else {
      digitalWrite(PIN_RED_LED, LOW);
      digitalWrite(2, LOW);
      digitalWrite(PIN_BUZZER, LOW);
    }

#if ENABLE_OLED
    if (oledReady) {
      display.clearDisplay();
      display.setTextColor(SSD1306_WHITE);

#if SCREEN_HEIGHT >= 64
      // Bố cục chuẩn cho màn hình 128x64 pixels (0.96 inch)
      display.setTextSize(1);
      display.setCursor(0, 0);
#if SNIFFER_MODE_ALL_NETWORKS
      display.printf("ALL-NET | HOP 1..13");
#else
      display.printf("CH%d | %s", currentChannel, (WiFi.status() == WL_CONNECTED) ? "ONLINE" : "OFFLINE");
#endif
      display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

      // Thông số lưu lượng mạng thời gian thực
      display.setCursor(0, 13);
      display.printf("Pkts: %.0f /s", packet_rate);
      display.setCursor(0, 23);
      display.printf("Rate: %.1f KB/s", byte_rate / 1024.0);

      // Phán quyết Edge TinyML
      display.drawLine(0, 34, 128, 34, SSD1306_WHITE);
      display.setCursor(0, 38);
      if (local_anomaly) {
        display.print(F("THREAT: "));
        display.println(local_attack);
        display.setCursor(0, 48);
        display.printf("[!] CONF: %.0f%%", tinyml_anomaly_score * 100);
      } else {
        display.print(F("STATUS: ALL NORMAL"));
        display.setCursor(0, 48);
        display.print(F("[OK] System Secure"));
      }
#else
      // Bố cục tinh gọn cho màn hình nhỏ 128x32 pixels (0.91 inch)
      display.setTextSize(1);
      display.setCursor(0, 0);
#if SNIFFER_MODE_ALL_NETWORKS
      display.printf("HOP 1-13|%.0fp/s|ALL", packet_rate);
#else
      display.printf("CH%d|%.0fp/s|%s", currentChannel, packet_rate, (WiFi.status() == WL_CONNECTED) ? "ON" : "OFF");
#endif
      display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

      display.setCursor(0, 12);
      if (local_anomaly) {
        display.printf("! %s (%.0f%%)", local_attack, tinyml_anomaly_score * 100);
      } else {
        display.print(F("[OK] System Secure"));
      }
      display.setCursor(0, 22);
      display.printf("%.1f KB/s | %d ports", byte_rate / 1024.0, snap.unique_ports_count);
#endif
      display.display();
    }
#endif

    // In Serial giám sát
#if SNIFFER_MODE_ALL_NETWORKS
    const char* connStatus = "[ALL-NETWORKS HOPPING 1..13]";
#else
    const char* connStatus = (WiFi.status() == WL_CONNECTED) ? ((mqttClient.connected()) ? "[ONLINE - MQTT OK]" : "[ONLINE - MQTT WAITING]") : "[OFFLINE - NO WIFI]";
#endif
    Serial.printf("[Telemetry] %s Pkts/s: %.1f | Bytes/s: %.0f | SYN: %.2f | Ports: %d | Threat: %s\n",
                  connStatus, packet_rate, byte_rate, syn_ratio, snap.unique_ports_count, local_attack);
    // Luôn gửi bản tin JSON ra cổng Serial với tag ESP32_TELEMETRY: để máy tính đọc qua cáp USB khi mất WiFi
    Serial.print(F("ESP32_TELEMETRY:"));
    Serial.println(jsonBuffer);

    // Gửi qua MQTT (khi có kết nối WiFi)
    if (mqttClient.connected()) {
      mqttClient.publish(TOPIC_TRAFFIC_TELEMETRY, jsonBuffer);
      if (local_anomaly) {
        mqttClient.publish(TOPIC_LOCAL_ALERT, jsonBuffer);
      }
    }
  }
}
