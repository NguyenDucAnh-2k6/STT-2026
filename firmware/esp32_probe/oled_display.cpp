#include "oled_display.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#if ENABLE_OLED
static Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
static bool oledReady = false;
#endif

bool initOledDisplay() {
#if ENABLE_OLED
  Wire.begin(PIN_I2C_SDA, PIN_I2C_SCL);
  if (display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    oledReady = true;
    display.clearDisplay();
    display.display();
    return true;
  }
  Serial.println(F("[OLED] Khong tim thay man hinh SSD1306 tai dia chi 0x3C, kiem tra ket noi I2C."));
  oledReady = false;
  return false;
#else
  return false;
#endif
}

void showOledStartup(bool allNetworksMode) {
#if ENABLE_OLED
  if (!oledReady) return;
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(F("AERO EDGE AI SOC"));
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);
  display.setCursor(0, 14);
  if (allNetworksMode) {
    display.println(F("ALL-NETWORKS MODE"));
    display.setCursor(0, 26);
    display.println(F("HOPPING CH 1..13"));
  } else {
    display.println(F("AP-LOCKED MODE"));
    display.setCursor(0, 26);
    display.println(F("CONNECTING WIFI..."));
  }
  display.setCursor(0, 38);
  display.println(F("Uplink: USB/MQTT"));
  display.display();
  delay(800);
#endif
}

void updateOledMetrics(
    float packet_rate,
    float byte_rate,
    uint8_t currentChannel,
    bool isWifiConnected,
    bool local_anomaly,
    const char* local_attack,
    float anomaly_score,
    uint32_t unique_ports
) {
#if ENABLE_OLED
  if (!oledReady) return;
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

#if SCREEN_HEIGHT >= 64
  // Màn hình 128x64 pixels (0.96 inch)
  display.setTextSize(1);
  display.setCursor(0, 0);
#if SNIFFER_MODE_ALL_NETWORKS
  display.printf("ALL-NET | HOP 1..13");
#else
  display.printf("CH%d | %s", currentChannel, isWifiConnected ? "ONLINE" : "OFFLINE");
#endif
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  display.setCursor(0, 13);
  display.printf("Pkts: %.0f /s", packet_rate);
  display.setCursor(0, 23);
  display.printf("Rate: %.1f KB/s", byte_rate / 1024.0);

  display.drawLine(0, 34, 128, 34, SSD1306_WHITE);
  display.setCursor(0, 38);
  if (local_anomaly) {
    display.print(F("THREAT: "));
    display.print(local_attack);
    display.setCursor(0, 48);
    display.printf("! ALERT (%.0f%%)", anomaly_score * 100);
  } else {
    display.print(F("STATUS: ALL NORMAL"));
    display.setCursor(0, 48);
    display.print(F("[OK] System Secure"));
  }
#else
  // Màn hình 128x32 pixels (0.91 inch)
  display.setTextSize(1);
  display.setCursor(0, 0);
#if SNIFFER_MODE_ALL_NETWORKS
  display.printf("HOP 1-13|%.0fp/s|ALL", packet_rate);
#else
  display.printf("CH%d|%.0fp/s|%s", currentChannel, packet_rate, isWifiConnected ? "ON" : "OFF");
#endif
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  display.setCursor(0, 12);
  if (local_anomaly) {
    display.printf("! %s (%.0f%%)", local_attack, anomaly_score * 100);
  } else {
    display.print(F("[OK] System Secure"));
  }
  display.setCursor(0, 22);
  display.printf("%.1f KB/s | %d ports", byte_rate / 1024.0, (int)unique_ports);
#endif

  display.display();
#endif
}
