#ifndef GATEWAY_MANAGER_H
#define GATEWAY_MANAGER_H

#include <Arduino.h>
#include <WiFi.h>
#include "config.h"
#include "edge_inference.h"
#include "packet_features.h"

// Thống kê luồng lưu lượng chuyển tiếp qua Gateway
struct GatewayMetrics {
  uint32_t total_forwarded_packets;
  uint32_t total_forwarded_bytes;
  uint32_t tcp_packets;
  uint32_t udp_packets;
  uint32_t icmp_packets;
  uint32_t anomaly_detections;
  float latest_entropy;
  char latest_threat[32];
  float latest_confidence;
};

// Khởi tạo chế độ Micro-Gateway: Phát SoftAP (cho Laptop) + Kết nối STA (ra Internet) + Kích hoạt NAPT
void initGatewayMode();

// Kiểm tra xem chế độ Gateway có đang kích hoạt không
bool isGatewayModeActive();

// Số lượng thiết bị đang kết nối vào SoftAP của Gateway (tối đa 1 theo cấu hình)
uint8_t getGatewayClientCount();

// Duy trì vòng lặp Gateway: kiểm tra trạng thái STA, NAT, và in heartbeat
void maintainGatewayLoop();

// Bắt và suy luận máy học trên gói tin đi qua CPU của Gateway (khung 802.11 hoặc IP thô)
// Lưu ý: Chế độ Giám sát thuần túy (Monitor Mode), KHÔNG THỰC HIỆN DROP gói tin!
void inspectGatewayPacket(const uint8_t* frameData, size_t length);

// Bắt và suy luận trực tiếp trên gói tin IPv4 đã giải mã từ lwIP TCP/IP stack
void inspectGatewayIpPacket(const uint8_t* ipData, size_t length);

// Lấy chỉ số đo lường lưu lượng của Gateway
GatewayMetrics getGatewayMetrics();

#endif // GATEWAY_MANAGER_H
