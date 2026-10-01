#ifndef SNIFFER_H
#define SNIFFER_H

#include <Arduino.h>
#include "esp_wifi.h"
#include "config.h"

#define MAX_DETECTED_SSIDS 16

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

// Cấu trúc mạng Wi-Fi phát hiện được qua sóng over-the-air
struct DetectedWifiNetwork {
  char ssid[33];
  int8_t rssi;
  uint8_t channel;
  uint32_t last_seen_ms;
};

// Khởi tạo Promiscuous Sniffer
void initSniffer(uint8_t initialChannel);

// Chụp snapshot số liệu thống kê chu kỳ hiện tại và reset bộ đếm
TrafficWindowStats captureAndResetStats();

// Thực hiện nhảy kênh Wi-Fi nếu bật Channel Hopping
void handleChannelHopping(uint8_t* inoutChannel, unsigned long* inoutLastHopTime);

// Truy xuất danh sách các mạng Wi-Fi phát hiện được
const DetectedWifiNetwork* getDetectedWifiNetworks();
uint8_t getDetectedWifiCount();

#endif // SNIFFER_H
