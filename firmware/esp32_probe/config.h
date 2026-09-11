#ifndef CONFIG_H
#define CONFIG_H

// ====================================================================
// EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE CONFIGURATION
// ====================================================================

// --- WiFi & MQTT Broker Settings ---
// Tự động nạp từ credentials.h (đã được .gitignore chặn để không bị lộ mật khẩu)
#if __has_include("credentials.h")
  #include "credentials.h"
#else
  #define WIFI_SSID "YOUR_WIFI_SSID"
  #define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
  #define MQTT_BROKER_HOST "192.168.1.100"
#endif

#define MQTT_BROKER_PORT 1883
#define MQTT_CLIENT_ID "ESP32-EdgeProbe-01"

// --- MQTT Topics ---
#define TOPIC_TRAFFIC_TELEMETRY "edge/telemetry/traffic"
#define TOPIC_DEVICE_STATUS "edge/nodes/status"
#define TOPIC_LOCAL_ALERT "edge/alerts/high_priority"

// --- Telemetry & Sampling Settings ---
// Cửa sổ lấy mẫu thống kê gói tin (milliseconds)
#define SAMPLING_WINDOW_MS 2000

// Kênh WiFi cần lắng nghe (1 - 13). 0 = tự động nhảy kênh (Channel Hopping)
#define WIFI_CHANNEL 1
#define ENABLE_CHANNEL_HOP true
#define HOP_INTERVAL_MS 5000

// Ngưỡng phát hiện bất thường cục bộ (Rule-based / TinyML threshold)
#define LOCAL_SYN_ALERT_THRESHOLD 0.75 // Tỷ lệ gói SYN > 75% cảnh báo tức thời
#define LOCAL_PKT_RATE_THRESHOLD 1500  // Số gói/s vượt quá 1500

// --- Hardware Peripherals (OLED, Red LED, Buzzer) ---
#define ENABLE_OLED true        // Bật/tắt màn hình OLED SSD1306 (I2C)
#define SCREEN_WIDTH 128        // Chiều rộng OLED (pixels)
#define SCREEN_HEIGHT 64        // Chiều cao OLED (pixels)
#define OLED_RESET -1           // Reset pin (-1 nếu dùng chung reset ESP32)
#define SCREEN_ADDRESS 0x3C     // Địa chỉ I2C SSD1306 (0x3C hoặc 0x3D)

#define PIN_I2C_SDA 21          // Chân SDA I2C OLED (GPIO 21)
#define PIN_I2C_SCL 22          // Chân SCL I2C OLED (GPIO 22)

#define PIN_RED_LED 4           // Đèn LED đỏ cảnh báo tấn công (GPIO 4)
#define PIN_BUZZER  19          // Còi chíp Buzzer báo động âm thanh (GPIO 19)

#endif // CONFIG_H
