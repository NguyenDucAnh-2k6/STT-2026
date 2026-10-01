#include "led_buzzer.h"

// Định nghĩa mức logic cho LED Onboard (GPIO 2)
#if ONBOARD_LED_ACTIVE_HIGH
  #define ONBOARD_LED_ON  HIGH
  #define ONBOARD_LED_OFF LOW
#else
  #define ONBOARD_LED_ON  LOW
  #define ONBOARD_LED_OFF HIGH
#endif

void initLedBuzzer() {
  pinMode(PIN_RED_LED, OUTPUT);
  pinMode(PIN_ONBOARD_LED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);

  digitalWrite(PIN_RED_LED, LOW);
  digitalWrite(PIN_ONBOARD_LED, ONBOARD_LED_OFF);
  digitalWrite(PIN_BUZZER, LOW);
}

void setAlertState(bool isAnomaly) {
  if (isAnomaly) {
    digitalWrite(PIN_RED_LED, HIGH);
    digitalWrite(PIN_ONBOARD_LED, ONBOARD_LED_ON); // Chỉ sáng xanh khi vượt ngưỡng
    // Phát xung ngắn an toàn tránh sụt áp nguồn 3.3V (Brownout Reset)
    digitalWrite(PIN_BUZZER, HIGH);
    delay(25);
    digitalWrite(PIN_BUZZER, LOW);
  } else {
    turnOffAlerts();
  }
}

void turnOffAlerts() {
  digitalWrite(PIN_RED_LED, LOW);
  digitalWrite(PIN_ONBOARD_LED, ONBOARD_LED_OFF);
  digitalWrite(PIN_BUZZER, LOW);
}
