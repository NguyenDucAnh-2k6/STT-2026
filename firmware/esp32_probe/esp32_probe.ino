/**
 * @file esp32_probe.ino
 * @brief ESP32 Edge Network Traffic Anomaly Detection Probe (Modular Architecture)
 * 
 * Pipeline:
 *  1. Sniffer: Bắt gói tin WiFi thô ở chế độ Promiscuous Mode (khung 802.11).
 *  2. Feature Extraction: Trích xuất tốc độ gói, dung lượng byte, cờ TCP SYN/ACK, port count.
 *  3. Edge AI Inference: Suy luận trực tiếp trên chip qua TinyML / TFLite (56 đặc trưng Edge-IIoTset).
 *  4. Telemetry Uplink: Phát dữ liệu qua MQTT và USB Serial (JSON).
 *  5. Peripherals: Điều khiển LED Đỏ/Xanh, Còi Buzzer và màn hình OLED SSD1306.
 */

#include <Arduino.h>
#include "config.h"
#include "led_buzzer.h"
#include "oled_display.h"
#include "sniffer.h"
#include "edge_inference.h"
#include "mqtt_handler.h"

static unsigned long lastSampleTime = 0;
static unsigned long lastHopTime = 0;
static uint8_t currentChannel = WIFI_CHANNEL;

void setup() {
  Serial.begin(115200);
  delay(100);

  Serial.println(F("\n========================================================"));
  Serial.println(F("  AERO EDGE AI - SOC PROBE STARTING UP (MODULAR FIRMWARE)"));
  Serial.println(F("========================================================"));

  // 1. Khởi tạo ngoại vi phần cứng: LED, Buzzer & OLED
  initLedBuzzer();
  bool oledOk = initOledDisplay();
  showOledStartup(SNIFFER_MODE_ALL_NETWORKS);

  // 2. Khởi tạo mạng & MQTT
  initMqttAndWiFi(SNIFFER_MODE_ALL_NETWORKS);

  // 3. Khởi tạo bộ suy luận Edge AI TinyML
  initEdgeInference();

  // 4. Khởi tạo Promiscuous Packet Sniffer
  initSniffer(currentChannel);

  lastSampleTime = millis();
  lastHopTime = millis();
  Serial.println(F("[System] He thong khoi dong thanh cong va san sang bat luu luong!\n"));
}

void loop() {
  // A. Duy trì kết nối MQTT và lắng nghe điều khiển cấu hình từ xa
  maintainMqttLoop(SNIFFER_MODE_ALL_NETWORKS);

  // B. Xử lý nhảy kênh Wi-Fi định kỳ
  handleChannelHopping(&currentChannel, &lastHopTime);

  // C. Chu kỳ lấy mẫu thống kê và suy luận Edge AI
  unsigned long now = millis();
  if (now - lastSampleTime >= SAMPLING_WINDOW_MS) {
    float windowSeconds = (now - lastSampleTime) / 1000.0f;
    lastSampleTime = now;

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
    EdgeInferenceResult inf = runEdgeInference(snap, packet_rate, byte_rate, avg_packet_size);

    // 4. Điều khiển ngoại vi: LED cảnh báo & Còi Buzzer
    setAlertState(inf.is_anomaly);

    // 5. Cập nhật giao diện màn hình OLED
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
        inf
    );
  }
}
