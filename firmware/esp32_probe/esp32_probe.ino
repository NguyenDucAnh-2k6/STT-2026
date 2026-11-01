/**
 * @file esp32_probe.ino
 * @brief ESP32 Edge Network Traffic Anomaly Detection Probe (Modular Architecture)
 * 
 * Pipeline:
 *  1. Sniffer: Bắt gói tin WiFi thô ở chế độ Promiscuous Mode (khung 802.11).
 *  2. Feature Extraction: Trích xuất tốc độ gói, dung lượng byte, cờ TCP SYN/ACK, port count.
 *  3. Local packet extraction -> exported scaling -> classifier/anomaly inference.
 *     Optional host TShark dissection preserves the wider lake schema.
 *  4. Telemetry Uplink: Phát dữ liệu qua MQTT và USB Serial (JSON).
 *  5. Peripherals: Điều khiển LED Đỏ/Xanh, Còi Buzzer và màn hình OLED SSD1306.
 *  6. Host-Gateway Hardware Security Dongle: Nhận lệnh qua Serial từ Host Gateway.
 */

#include <Arduino.h>
#include <ArduinoJson.h>
#include "config.h"
#include "led_buzzer.h"
#include "oled_display.h"
#include "sniffer.h"
#include "edge_inference.h"
#include "mqtt_handler.h"
#include "gateway_manager.h"

static unsigned long lastSampleTime = 0;
static unsigned long lastHopTime = 0;
static uint8_t currentChannel = WIFI_CHANNEL;

// Quản lý trạng thái Host-Gateway Dongle qua USB Serial
static unsigned long lastHostGatewayMsgMs = 0;
static bool hostGatewayActive = false;
static char hostSerialBuf[384];
static size_t hostSerialIdx = 0;

static void handleHostGatewayLine(const char* line) {
  if (strcmp(line, "HOST_PING") == 0) {
    lastHostGatewayMsgMs = millis();
    hostGatewayActive = true;
    Serial.println(F("[ESP32] PONG:HOST_GATEWAY_READY"));
    return;
  }

  bool isAlert = (strncmp(line, "HOST_ALERT:", 11) == 0);
  bool isStats = (strncmp(line, "HOST_STATS:", 11) == 0);

  if (isAlert || isStats) {
    const char* jsonStart = strchr(line, '{');
    if (jsonStart) {
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, jsonStart);
      if (!err) {
        lastHostGatewayMsgMs = millis();
        hostGatewayActive = true;
        const char* threat = doc["threat"] | (isAlert ? "Threat" : "Normal");
        float score = doc["score"] | (isAlert ? 0.99f : 0.0f);
        float rate = doc["rate"] | 0.0f;
        float bytes = doc["bytes"] | 0.0f;

        setAlertState(isAlert);
        updateOledHostGateway(rate, bytes, isAlert, threat, score);
      }
    }
  }
}

static void processHostGatewayCommands() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (hostSerialIdx > 0) {
        hostSerialBuf[hostSerialIdx] = '\0';
        handleHostGatewayLine(hostSerialBuf);
        hostSerialIdx = 0;
      }
    } else {
      if (hostSerialIdx < sizeof(hostSerialBuf) - 1) {
        hostSerialBuf[hostSerialIdx++] = c;
      } else {
        hostSerialIdx = 0; // Tránh tràn bộ đệm
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);

  Serial.println(F("\n========================================================"));
  Serial.println(F("  AERO EDGE AI - SOC PROBE STARTING UP (MODULAR FIRMWARE)"));
  Serial.println(F("========================================================"));

  // 1. Khởi tạo ngoại vi phần cứng: LED, Buzzer & OLED
  initLedBuzzer();
  bool oledOk = initOledDisplay();
  showOledStartup(false);

  // 2. Khởi tạo theo chế độ hoạt động (Sniffer Mode vs Gateway Mode)
#if CURRENT_PROBE_MODE == PROBE_MODE_GATEWAY
  initGatewayMode();
  initEdgeInference();
  initMqttClientConfig(); // Cấu hình Broker để khi ngắt USB cắm nguồn ngoài vẫn phát MQTT qua Wi-Fi
  // Khong goi initSniffer o che do Gateway vi goi tin tu SoftAP da di truc tiep
  // vao lwIP netif hook. Bat promiscuous o day se gay mat beacon SoftAP va loi bat tay WPA2.
  Serial.println(F("[System] Da khoi dong o CHE DO MICRO-GATEWAY (SoftAP + NAT + ML Monitor)!\n"));
#else
  initMqttAndWiFi(false);
  initEdgeInference();
  initSniffer(currentChannel);
  Serial.println(F("[System] Da khoi dong o CHE DO PROMISCUOUS SNIFFER!\n"));
#endif

  lastSampleTime = millis();
  lastHopTime = millis();
}

void loop() {
  // Luôn kiểm tra các lệnh điều khiển gửi từ Host Gateway (Laptop) qua USB Serial
  processHostGatewayCommands();

#if CURRENT_PROBE_MODE != PROBE_MODE_GATEWAY
  sendRadioFrame(); // Serialize owned samples outside the Wi-Fi callback (chi dung cho Sniffer mode).
#endif

#if CURRENT_PROBE_MODE == PROBE_MODE_GATEWAY
  maintainGatewayLoop();
  maintainMqttLoop(false);
#else
  // A. Duy trì kết nối MQTT và WiFi
  maintainMqttLoop(false);

  // B. Khóa bộ lọc vào mạng Wi-Fi mục tiêu ngay khi kết nối thành công
  static bool wasConnected = false;
  static unsigned long lastFilterSync = 0;
  bool nowConnected = isWiFiConnected();

  if (nowConnected) {
    if (!wasConnected || (millis() - lastFilterSync > 10000)) {
      lastFilterSync = millis();
      uint8_t* bssid = WiFi.BSSID();
      uint8_t ch = WiFi.channel();
      if (bssid != nullptr && ch > 0) {
        currentChannel = ch;
        setTargetNetworkFilter(bssid, ch);
        wasConnected = true;
      }
    }
  } else {
    if (wasConnected) {
      clearTargetNetworkFilter();
      wasConnected = false;
    }
  }
#endif

  // C. Chu kỳ lấy mẫu thống kê và suy luận Edge AI
  unsigned long now = millis();
  if (now - lastSampleTime >= SAMPLING_WINDOW_MS) {
    float windowSeconds = (now - lastSampleTime) / 1000.0f;
    lastSampleTime = now;

    if (isWiFiConnected()) currentChannel = WiFi.channel();

    // 1. Thu thập snapshot số liệu thống kê từ Sniffer
    TrafficWindowStats snap = captureAndResetStats();

    // 2. Tính toán các chỉ số dẫn xuất thời gian thực
    float packet_rate = snap.total_packets / windowSeconds;
    float byte_rate = snap.total_bytes / windowSeconds;
    float avg_packet_size = (snap.total_packets > 0) ? ((float)snap.total_bytes / snap.total_packets) : 0.0f;

    float syn_ratio = (snap.tcp_packets > 0) ? ((float)snap.syn_packets / snap.tcp_packets) : 0.0f;
    float ack_ratio = (snap.tcp_packets > 0) ? ((float)snap.ack_packets / snap.tcp_packets) : 0.0f;
    float udp_ratio = (snap.total_packets > 0) ? ((float)snap.udp_packets / snap.total_packets) : 0.0f;
    float icmp_ratio = (snap.total_packets > 0) ? ((float)snap.icmp_packets / snap.total_packets) : 0.0f;

    // 3. Thực thi suy luận TinyML / TFLite trực tiếp trên chip
    EdgeInferenceResult inf = getLatestEdgeInference();

    // 4 & 5. Điều khiển ngoại vi: LED cảnh báo, Còi Buzzer & Màn hình OLED
    // Nếu Host-Gateway trên Laptop đang gửi số liệu realtime thì để Host Gateway làm chủ OLED & Còi
    if (hostGatewayActive && (millis() - lastHostGatewayMsgMs < 4000)) {
      // Host-Gateway đang điều khiển OLED và còi qua Serial, không ghi đè giao diện
    } else {
      hostGatewayActive = false;
      setAlertState(inf.is_anomaly);
      updateOledMetrics(
          packet_rate,
          byte_rate,
          currentChannel,
          isWiFiConnected(),
          inf.is_anomaly,
          inf.threat_name,
          inf.anomaly_score,
          snap.unique_ports_count
      );
    }

    // 6. Đóng gói và phát bản tin Telemetry qua MQTT & USB Serial
    sendTelemetryData(
        snap,
        packet_rate,
        byte_rate,
        avg_packet_size,
        syn_ratio,
        ack_ratio,
        udp_ratio,
        icmp_ratio,
        currentChannel,
        inf,
        (uint32_t)(windowSeconds * 1000.0f)
    );
  }

  delay(2);
}
