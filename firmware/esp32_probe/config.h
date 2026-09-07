#ifndef CONFIG_H
#define CONFIG_H

// ====================================================================
// EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE CONFIGURATION
// ====================================================================

// --- WiFi Settings ---
// Thay đổi thông tin mạng WiFi cục bộ của bạn
#define WIFI_SSID           "Your_WiFi_SSID"
#define WIFI_PASSWORD       "Your_WiFi_Password"

// --- MQTT Broker Settings ---
// Địa chỉ IP của máy host chạy Mosquitto Broker (ví dụ: 192.168.1.100)
#define MQTT_BROKER_HOST    "192.168.1.100"
#define MQTT_BROKER_PORT    1883
#define MQTT_CLIENT_ID      "ESP32-EdgeProbe-01"

// --- MQTT Topics ---
#define TOPIC_TRAFFIC_TELEMETRY "edge/telemetry/traffic"
#define TOPIC_DEVICE_STATUS     "edge/nodes/status"
#define TOPIC_LOCAL_ALERT       "edge/alerts/high_priority"

// --- Telemetry & Sampling Settings ---
// Cửa sổ lấy mẫu thống kê gói tin (milliseconds)
#define SAMPLING_WINDOW_MS  2000

// Kênh WiFi cần lắng nghe (1 - 13). 0 = tự động nhảy kênh (Channel Hopping)
#define WIFI_CHANNEL        1
#define ENABLE_CHANNEL_HOP  true
#define HOP_INTERVAL_MS     5000

// Ngưỡng phát hiện bất thường cục bộ (Rule-based / TinyML threshold)
#define LOCAL_SYN_ALERT_THRESHOLD  0.75   // Tỷ lệ gói SYN > 75% cảnh báo tức thời
#define LOCAL_PKT_RATE_THRESHOLD   1500   // Số gói/s vượt quá 1500

#endif // CONFIG_H
