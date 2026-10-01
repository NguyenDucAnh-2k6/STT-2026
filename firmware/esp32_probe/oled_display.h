#ifndef OLED_DISPLAY_H
#define OLED_DISPLAY_H

#include <Arduino.h>
#include "config.h"

// Khởi tạo màn hình OLED SSD1306 (I2C)
bool initOledDisplay();

// Hiển thị màn hình khởi động ban đầu
void showOledStartup(bool allNetworksMode);

// Hiển thị chỉ số đo lường thời gian thực và phán quyết an ninh
void updateOledMetrics(
    float packet_rate,
    float byte_rate,
    uint8_t currentChannel,
    bool isWifiConnected,
    bool local_anomaly,
    const char* local_attack,
    float anomaly_score,
    uint32_t unique_ports
);

#endif // OLED_DISPLAY_H
