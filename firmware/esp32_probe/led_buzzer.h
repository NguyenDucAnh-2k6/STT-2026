#ifndef LED_BUZZER_H
#define LED_BUZZER_H

#include <Arduino.h>
#include "config.h"

// Khởi tạo GPIO cho LED Đỏ, LED Xanh Onboard và Còi Buzzer
void initLedBuzzer();

// Cập nhật trạng thái đèn và còi theo phán quyết bất thường
void setAlertState(bool isAnomaly);

// Tắt toàn bộ đèn và còi
void turnOffAlerts();

#endif // LED_BUZZER_H
