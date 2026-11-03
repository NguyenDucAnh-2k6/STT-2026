#ifndef CONFIG_H
#define CONFIG_H

// ====================================================================
// EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE CONFIGURATION
// ====================================================================

// --- WiFi & MQTT Broker Settings ---
// Tự động nạp từ credentials.h (đã được .gitignore chặn để không bị lộ mật
// khẩu)
#if __has_include("credentials.h")
#include "credentials.h"
#else
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define MQTT_BROKER_HOST "192.168.1.100"
#endif

#ifndef MQTT_BROKER_PORT
#define MQTT_BROKER_PORT 1883
#endif
#ifndef MQTT_CLIENT_ID
#define MQTT_CLIENT_ID "ESP32-EdgeProbe-01"
#endif
#ifndef MQTT_AUTO_DISCOVERY
#define MQTT_AUTO_DISCOVERY 0
#endif

// --- MQTT Topics ---
#define TOPIC_TRAFFIC_TELEMETRY "edge/telemetry/traffic"
#define TOPIC_DEVICE_STATUS "edge/nodes/status"
#define TOPIC_LOCAL_ALERT "edge/alerts/high_priority"

// --- Telemetry & Sampling Settings ---
// Cửa sổ lấy mẫu thống kê gói tin (milliseconds)
#define SAMPLING_WINDOW_MS 2000

// Bounded radio samples for host-side dissection (115200 baud USB budget).
#define RADIO_FRAME_CAPACITY 4
#define RADIO_FRAME_MAX_BYTES 2048
#define RADIO_FRAME_INTERVAL_MS 750
#define TOPIC_RADIO_FRAMES "edge/telemetry/radio"

// --- Chế độ hoạt động của ESP32 (Operating Mode) ---
// PROBE_MODE_SNIFFER (0): Chế độ mặc định - Cảm biến Promiscuous Sniffer ngoài không khí (L2 Wireless WIDS).
// PROBE_MODE_GATEWAY (1): Chế độ Micro-Gateway - Tự phát SoftAP + NAT chuyển tiếp ra Internet,
//                         đồng thời chạy Machine Learning giám sát toàn bộ gói tin đi qua CPU (Monitor-only, không drop).
#define PROBE_MODE_SNIFFER 0
#define PROBE_MODE_GATEWAY 1
#define CURRENT_PROBE_MODE PROBE_MODE_SNIFFER

// --- Cấu hình Gateway SoftAP (Dành cho PROBE_MODE_GATEWAY) ---
#define GATEWAY_AP_SSID "AERO-Security-Gateway"
#define GATEWAY_AP_PASSWORD "ducanh123"
#define GATEWAY_AP_CHANNEL 1
#define GATEWAY_AP_MAX_CLIENTS 4      // Cho phép laptop kết nối mượt mà, chống lỗi handshake WPA2
#define GATEWAY_DEFENSE_ACTIVE false  // Chưa đưa ra quyết định phòng thủ (Monitor Mode: PASS toàn bộ)

// --- Chế độ dò sóng mạng (Sniffer Mode) ---
// SNIFFER_MODE_ALL_NETWORKS:
//  - false: Khóa cố định vào AP Wi-Fi mục tiêu (WIFI_SSID) và BSSID tương ứng.
//           Chế độ promiscuous bắt toàn bộ mạng trôi nổi over-the-air đã được tắt hoàn toàn
//           để đảm bảo ESP32 chỉ phân tích lưu lượng thuộc mạng được cấu hình trong .env / CLI.
#define SNIFFER_MODE_ALL_NETWORKS false
#define FAST_HOP_INTERVAL_MS 300

// Kênh WiFi ban đầu (sẽ tự động đồng bộ theo kênh thực tế của AP mục tiêu khi kết nối thành công)
#define WIFI_CHANNEL 1
#define ENABLE_CHANNEL_HOP false
#define HOP_INTERVAL_MS 5000

// Ngưỡng phát hiện bất thường cục bộ (Rule-based / TinyML threshold)
#define LOCAL_SYN_ALERT_THRESHOLD 0.75 // Tỷ lệ gói SYN > 75% cảnh báo tức thời
#define LOCAL_PKT_RATE_THRESHOLD 1500  // Số gói/s vượt quá 1500

// --- Hardware Peripherals (OLED, Red LED, Buzzer) ---
#define ENABLE_OLED true // Bật/tắt màn hình OLED SSD1306 (I2C)
#define SCREEN_WIDTH 128 // Chiều rộng OLED (pixels)
#define SCREEN_HEIGHT                                                          \
  64 // Chiều cao OLED (pixels):
     // - Màn hình 0.96 inch thông dụng: 64
     // - Màn hình nhỏ 0.91 inch: ĐỔI THÀNH 32 (tránh đen màn hình do sai
     // multiplex)

#define OLED_RESET                                                             \
  -1 // Reset pin (-1 nếu dùng chung reset ESP32, hoặc GPIO 16 trên bo mạch
     // Heltec WiFi Kit 32)
#define SCREEN_ADDRESS 0x3C // Địa chỉ I2C SSD1306 mặc định (0x3C hoặc 0x3D)
#define OLED_I2C_ADDR SCREEN_ADDRESS // Bí danh tương thích

// --- Sơ đồ chân I2C phần cứng trên ESP32 ---
// Khớp chính xác với màu dây cắm thực tế của bạn:
// - Đỏ   : ESP32 3V3 -> OLED VDD
// - Đen  : ESP32 GND -> OLED GND
// - Vàng : ESP32 D23 -> OLED SCK (SCL)
// - Xanh : ESP32 D21 -> OLED SDA
#define PIN_I2C_SDA 21 // Chân SDA I2C OLED (GPIO 21 - Dây xanh)
#define PIN_I2C_SCL 23 // Chân SCL/SCK I2C OLED (GPIO 23 - Dây vàng)
#define PIN_OLED_SDA PIN_I2C_SDA // Bí danh tương thích
#define PIN_OLED_SCL PIN_I2C_SCL // Bí danh tương thích

#define PIN_RED_LED 4 // Đèn LED đỏ ngoại vi cảnh báo tấn công (GPIO 4)
#define PIN_BUZZER 19 // Còi chíp Buzzer báo động âm thanh (GPIO 19)

// --- Đèn LED Onboard tích hợp trên bo mạch ESP32 (Sáng xanh/Lam) ---
// Hầu hết bo mạch ESP32 (DevKit v1, NodeMCU-32S) tích hợp sẵn LED xanh tại
// GPIO 2. Quy ước mức logic: Active HIGH (HIGH = Bật sáng, LOW = Tắt hoàn
// toàn). Nếu bo mạch của bạn nối LED dạng Active LOW (ngược lại), hãy đổi giá
// trị bên dưới thành false.
#define PIN_ONBOARD_LED 2 // Chân LED có sẵn trên chip ESP32 (GPIO 2)
#define ONBOARD_LED_ACTIVE_HIGH true

#endif // CONFIG_H
