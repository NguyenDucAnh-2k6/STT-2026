#ifndef MQTT_HANDLER_H
#define MQTT_HANDLER_H

#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include "sniffer.h"
#include "edge_inference.h"

#include "config.h"

void sendRadioFrame();

// Khởi tạo WiFi, UDP Discovery và MQTT Client (dành cho Sniffer Mode)
void initMqttAndWiFi(bool allNetworksMode);

// Khởi tạo cấu hình MQTT Broker độc lập (dành cho Gateway Mode khi WiFi do Gateway quản lý)
void initMqttClientConfig();

// Phát bản tin suy luận và cảnh báo qua MQTT từ Gateway Mode (khi cắm nguồn độc lập ngoài)
bool publishGatewayPrediction(const char* jsonBuffer);
bool publishGatewayAlert(const char* jsonBuffer);

// Duy trì kết nối MQTT và xử lý các tin nhắn điều khiển từ UI
void maintainMqttLoop(bool allNetworksMode);

// Kiểm tra gói UDP Broadcast Beacon từ máy tính (Auto-Discovery)
void checkUdpDiscovery();

// Đóng gói và phát bản tin Telemetry qua MQTT & USB Serial
void sendTelemetryData(
    const TrafficWindowStats& snap,
    float packet_rate,
    float byte_rate,
    float avg_packet_size,
    float syn_ratio,
    float ack_ratio,
    float udp_ratio,
    float icmp_ratio,
    uint8_t channel,
    const EdgeInferenceResult& inf,
    uint32_t window_ms
);

// Trạng thái kết nối
bool isWiFiConnected();
bool isMqttConnected();

#endif // MQTT_HANDLER_H
