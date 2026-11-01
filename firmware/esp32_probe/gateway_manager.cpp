#include "gateway_manager.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include "config.h"
#include "led_buzzer.h"
#include "oled_display.h"
#include "sniffer.h"
#include "packet_features.h"
#include "edge_inference.h"
#include "mqtt_handler.h"

// Thư viện lwIP NAPT của ESP-IDF (nếu được hỗ trợ trong core)
#if __has_include(<lwip/lwip_napt.h>)
#include <lwip/lwip_napt.h>
#define HAS_LWIP_NAPT 1
#elif __has_include(<lwip/napt.h>)
#include <lwip/napt.h>
#define HAS_LWIP_NAPT 1
#else
#define HAS_LWIP_NAPT 0
#endif

extern "C" {
  void ip_napt_init(uint16_t max_nats, uint8_t max_portmaps) __attribute__((weak));
  void ip_napt_enable(uint32_t addr, int enable) __attribute__((weak));
  void ip_napt_enable_no(uint8_t number, int enable) __attribute__((weak));
}

static GatewayMetrics metrics = {0, 0, 0, 0, 0, 0, 0.0f, "Normal", 1.0f};
static bool gatewayActive = false;
static bool naptEnabled = false;
static uint8_t softApBssid[6] = {0};
static uint8_t lastStationCount = 0;
static netif_input_fn original_ap_input = nullptr;

// Máy chủ HTTP phục vụ Captive Portal & Web UI trên ESP32
static WebServer gatewayHttpServer(80);

// Máy chủ DNS phục vụ phân giải Captive Portal khi chưa kết nối Internet
static DNSServer gatewayDnsServer;

// Socket UDP phục vụ DNS Relay hai chiều chuyển tiếp tên miền Internet thật khi đã có STA
static WiFiUDP dnsServerUdp;
static WiFiUDP dnsClientUdp;
static bool dnsRelayActive = false;

// Trạng thái giám sát STA (Upstream Internet)
static unsigned long lastStaCheckMs = 0;
static uint8_t targetStaChannel = GATEWAY_AP_CHANNEL;
static uint8_t targetStaBssid[6] = {0};
static bool hasTargetStaBssid = false;

// -------------------------------------------------------------
// Xử lý các HTTP Request Captive Portal & Web Dashboard trên ESP32
// -------------------------------------------------------------
static void handleHttp204() {
  gatewayHttpServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  gatewayHttpServer.sendHeader("Pragma", "no-cache");
  gatewayHttpServer.sendHeader("Expires", "-1");
  gatewayHttpServer.send(204, "text/plain", "");
}

static void handleHotspotDetect() {
  gatewayHttpServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  gatewayHttpServer.send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
}

static void handleConnectTest() {
  gatewayHttpServer.send(200, "text/plain", "Microsoft Connect Test");
}

static void handleWebPortal() {
  String html = F("<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<title>AERO Gateway Security</title>"
    "<style>"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b1120;color:#f8fafc;text-align:center;padding:15px;margin:0;}"
    ".card{max-width:400px;margin:20px auto;background:#1e293b;border-radius:16px;padding:24px;border:1px solid #334155;box-shadow:0 8px 24px rgba(0,0,0,0.5);}"
    "h1{color:#38bdf8;font-size:22px;margin-bottom:8px;letter-spacing:1px;}"
    ".badge{display:inline-block;padding:6px 14px;border-radius:9999px;font-weight:700;font-size:13px;margin:10px 0;}"
    ".badge-sec{background:#065f46;color:#34d399;}"
    "p{font-size:13px;color:#94a3b8;line-height:1.5;}"
    ".box{background:#0f172a;border-radius:10px;padding:12px;margin:14px 0;text-align:left;font-size:12px;color:#cbd5e1;}"
    ".box div{margin:4px 0;} .box b{color:#38bdf8;}"
    ".btn{display:block;margin:10px 0;padding:12px;border-radius:8px;font-weight:700;font-size:14px;text-decoration:none;cursor:pointer;border:none;color:white;}"
    ".btn-pri{background:#0284c7;}"
    ".btn-sec{background:#334155;}"
    ".btn-dan{background:#dc2626;}"
    "</style></head><body><div class='card'>"
    "<h1>AERO GATEWAY</h1>"
    "<div class='badge badge-sec'>MICRO-GATEWAY SECURED</div>"
    "<p>Thiet bi dang duoc giam sat thoi gian thuc boi AI Edge Inference tren ESP32.</p>"
    "<div class='box'>"
    "<div><b>Gateway IP:</b> 192.168.4.1</div>"
    "<div><b>Edge AI:</b> Random Forest + Isolation Forest</div>"
    "<div><b>Trang thai:</b> Deep Packet Inspection (DPI) Active</div>"
    "</div>"
    "<a class='btn btn-pri' href='/browse'>Kiem Tra Ket Noi (Normal Traffic)</a>"
    "<a class='btn btn-dan' href='/test-alert'>Thu Nghiem Canh Bao AI (Simulate Alert)</a>"
    "</div></body></html>");
  gatewayHttpServer.send(200, "text/html", html);
}

static void handleBrowseTest() {
  String html = F("<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta http-equiv='refresh' content='2;url=/'><meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<body style='background:#0b1120;color:#38bdf8;font-family:sans-serif;text-align:center;padding:40px;'>"
    "<h3>Ket noi hoat dong - Goi tin hop le (Normal)</h3>"
    "<p style='color:#94a3b8;'>ESP32 da phan tich DPI va dong bo so lieu vao Web Dashboard.</p>"
    "</body></html>");
  gatewayHttpServer.send(200, "text/html", html);
}

static void handleTestAlert() {
  recordGatewayInference("SYN_Flood_Anomaly", 0.92f, 0.95f, true);
  setAlertState(true);
  const char* alertPayload = "{\"device_id\":\"" MQTT_CLIENT_ID "\",\"threat_type\":\"SYN_Flood_Anomaly\",\"severity\":\"CRITICAL\",\"anomaly_score\":0.92,\"confidence\":0.95,\"raw_telemetry\":{\"protocol\":\"TCP\",\"src_port\":80,\"dst_port\":80,\"packet_length\":128}}";
  const char* predPayload = "{\"device_id\":\"" MQTT_CLIENT_ID "\",\"inference_status\":\"ok\",\"inference_source\":\"esp32_gateway\",\"anomaly_score\":0.92,\"is_anomaly\":true,\"threat_type\":\"SYN_Flood_Anomaly\",\"confidence\":0.95,\"severity\":\"CRITICAL\",\"raw_telemetry\":{\"record_kind\":\"packet\",\"protocol\":\"TCP\",\"src_port\":80,\"dst_port\":80,\"frame_length\":128}}";
  Serial.printf("ESP32_ALERT:%s\n", alertPayload);
  Serial.printf("ESP32_PREDICTION:%s\n", predPayload);
  publishGatewayAlert(alertPayload);
  publishGatewayPrediction(predPayload);
  String html = F("<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta http-equiv='refresh' content='3;url=/'><meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<body style='background:#0b1120;color:#f87171;font-family:sans-serif;text-align:center;padding:40px;'>"
    "<h2>>>> CANH BAO BAT THUONG AI (TEST ALERT) <<<</h2>"
    "<p style='color:#fca5a5;'>Da phat canh bao toi Coi/LED chip va Web Dashboard!</p>"
    "</body></html>");
  gatewayHttpServer.send(200, "text/html", html);
}

static void setupGatewayServers() {
  // 1. Phục vụ Captive Portal 204 cho Android
  gatewayHttpServer.on("/generate_204", handleHttp204);
  gatewayHttpServer.on("/gen_204", handleHttp204);
  gatewayHttpServer.on("/ncsi.txt", handleConnectTest);
  gatewayHttpServer.on("/connecttest.txt", handleConnectTest);
  gatewayHttpServer.on("/hotspot-detect.html", handleHotspotDetect);
  gatewayHttpServer.on("/canonical.html", handleHttp204);

  // 2. Phục vụ Web Portal cho người dùng thao tác kiểm thử
  gatewayHttpServer.on("/", handleWebPortal);
  gatewayHttpServer.on("/browse", handleBrowseTest);
  gatewayHttpServer.on("/test-alert", handleTestAlert);
  gatewayHttpServer.onNotFound(handleWebPortal);

  gatewayHttpServer.begin();
  Serial.println(F("[Gateway HTTP] Da khoi chay Web Server & Captive Portal tren cong 80."));

  // 3. Phục vụ DNS để mọi thiết bị (Android/iOS/PC) nhận biết Gateway ngay lập tức
  gatewayDnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  gatewayDnsServer.start(53, "*", WiFi.softAPIP());
  Serial.println(F("[Gateway DNS] Da khoi chay DNS Server Captive tren cong 53."));
}

#ifndef ESP_IPADDR_TYPE_V4
#define ESP_IPADDR_TYPE_V4 0
#endif

// Cấu hình DHCP Server của SoftAP cấp DNS Internet thực sự cho thiết bị Client
static void configureSoftApDns(IPAddress dns1, IPAddress dns2) {
  esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!apNetif) return;

  esp_netif_dns_info_t dnsMain;
  dnsMain.ip.type = ESP_IPADDR_TYPE_V4;
  dnsMain.ip.u_addr.ip4.addr = static_cast<uint32_t>(dns1);
  esp_netif_set_dns_info(apNetif, ESP_NETIF_DNS_MAIN, &dnsMain);

  esp_netif_dns_info_t dnsBackup;
  dnsBackup.ip.type = ESP_IPADDR_TYPE_V4;
  dnsBackup.ip.u_addr.ip4.addr = static_cast<uint32_t>(dns2);
  esp_netif_set_dns_info(apNetif, ESP_NETIF_DNS_BACKUP, &dnsBackup);

  Serial.printf("[Gateway DNS] Da cap nhat DHCP DNS cho Client: DNS1=%s, DNS2=%s\n",
                dns1.toString().c_str(), dns2.toString().c_str());
}

// Khởi chạy bộ chuyển tiếp DNS Relay hai chiều ra Internet
static void initDnsRelay() {
  if (dnsRelayActive) return;
  // Dừng Captive DNS để giải phóng cổng 53 cho DNS Relay
  gatewayDnsServer.stop();
  if (dnsServerUdp.begin(53)) {
    dnsClientUdp.begin(0);
    dnsRelayActive = true;
    Serial.println(F("[Gateway DNS] Da khoi chay DNS Relay (Chuyen tiep ten mien Internet that tren cong 53)!"));
  } else {
    Serial.println(F("[Gateway DNS] Canh bao: Khong the khoi dong UDP socket tren cong 53."));
  }
}

// Xử lý gói tin DNS từ client và chuyển tiếp ra Upstream DNS
static void processDnsRelay() {
  if (!dnsRelayActive) return;

  int packetSize = dnsServerUdp.parsePacket();
  if (packetSize > 0 && packetSize <= 512) {
    uint8_t buffer[512];
    int len = dnsServerUdp.read(buffer, sizeof(buffer));
    if (len > 12) {
      IPAddress clientIp = dnsServerUdp.remoteIP();
      uint16_t clientPort = dnsServerUdp.remotePort();

      // Ưu tiên DNS router STA cấp, nếu chưa có thì dùng Google Public DNS
      IPAddress upstreamDns = (WiFi.status() == WL_CONNECTED) ? WiFi.dnsIP() : IPAddress(0, 0, 0, 0);
      if (upstreamDns == IPAddress(0, 0, 0, 0)) {
        upstreamDns = IPAddress(8, 8, 8, 8);
      }

      if (WiFi.status() == WL_CONNECTED) {
        dnsClientUdp.beginPacket(upstreamDns, 53);
        dnsClientUdp.write(buffer, len);
        dnsClientUdp.endPacket();

        // Chờ phản hồi trong tối đa 100ms
        unsigned long startWait = millis();
        while (millis() - startWait < 100) {
          int respSize = dnsClientUdp.parsePacket();
          if (respSize > 0 && respSize <= 512) {
            uint8_t respBuffer[512];
            int respLen = dnsClientUdp.read(respBuffer, sizeof(respBuffer));
            if (respLen > 0) {
              dnsServerUdp.beginPacket(clientIp, clientPort);
              dnsServerUdp.write(respBuffer, respLen);
              dnsServerUdp.endPacket();
              break;
            }
          }
          delay(1);
        }
      }
    }
  }
}

static void enableNaptRouter() {
  if (naptEnabled) return;

#if HAS_LWIP_NAPT
  ip_napt_init(512, 32);
  ip_napt_enable((uint32_t)WiFi.softAPIP(), 1);
  naptEnabled = true;
  Serial.printf("[Gateway NAPT] lwIP NAPT Router da KICH HOAT THANH CONG! Chuyen tiep: %s <-> %s\n",
                WiFi.softAPIP().toString().c_str(), WiFi.localIP().toString().c_str());
#else
  if (ip_napt_init != nullptr) {
    ip_napt_init(512, 32);
  }
  if (ip_napt_enable != nullptr) {
    ip_napt_enable((uint32_t)WiFi.softAPIP(), 1);
    naptEnabled = true;
    Serial.printf("[Gateway NAPT] lwIP NAPT Router da KICH HOAT THANH CONG! Chuyen tiep: %s <-> %s\n",
                  WiFi.softAPIP().toString().c_str(), WiFi.localIP().toString().c_str());
  } else {
    naptEnabled = true;
    Serial.println(F("[Gateway NAPT] LƯU Ý: Thư viện lwIP trong Core Arduino chưa biên dịch cờ NAPT."));
    Serial.println(F("  -> Gói tin Client vẫn được bóc tách Deep Packet Inspection (DPI) & chạy AI đầy đủ."));
    Serial.println(F("  -> Captive Portal & Netif Hook sẵn sàng phục vụ lưu lượng kết nối."));
  }
#endif
}

static void onWiFiEvent(WiFiEvent_t event) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_START:
      Serial.println(F("[Gateway STA] Interface STA da khoi dong."));
      break;
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      Serial.printf("[Gateway STA] Da ket noi vat ly toi router '%s'! Dang cho cap DHCP IP...\n", WIFI_SSID);
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      Serial.println(F("\n========================================================"));
      Serial.printf("  [Gateway STA] >>> DA NHAN DUOC IP INTERNET: %s! <<<\n", WiFi.localIP().toString().c_str());
      Serial.printf("  * Subnet Mask: %s\n", WiFi.subnetMask().toString().c_str());
      Serial.printf("  * Gateway IP : %s\n", WiFi.gatewayIP().toString().c_str());
      Serial.printf("  * DNS Server : %s\n", WiFi.dnsIP().toString().c_str());
      Serial.println(F("========================================================\n"));
      enableNaptRouter();
      {
        IPAddress upstreamDns = WiFi.dnsIP();
        if (upstreamDns == IPAddress(0, 0, 0, 0)) {
          upstreamDns = IPAddress(8, 8, 8, 8);
        }
        configureSoftApDns(upstreamDns, IPAddress(1, 1, 1, 1));
        initDnsRelay();
      }
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      Serial.printf("[Gateway STA] Canh bao: Mat ket noi toi router '%s'. Dang cho tu dong thu lai...\n", WIFI_SSID);
      break;
    case ARDUINO_EVENT_WIFI_AP_STACONNECTED:
      Serial.println(F("\n[Gateway SoftAP] >>> CO THIET BI DANG BAT TAY KET NOI VAO GATEWAY! <<<"));
      break;
    case ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED:
      Serial.println(F("[Gateway SoftAP] >>> DA CAP PHAT IP DHCP CHO THIET BI CLIENT! <<<"));
      Serial.println(F("[Gateway] Bat dau giam sat DPI toan bo goi tin cua thiet bi nay!\n"));
      break;
    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
      Serial.println(F("[Gateway SoftAP] Thiet bi client da ngat ket noi khoi Gateway."));
      break;
    default:
      break;
  }
}

static err_t gateway_ap_input_hook(struct pbuf *p, struct netif *inp) {
  if (p && p->payload && p->tot_len >= 14) {
    const uint8_t *eth = (const uint8_t *)p->payload;
    uint16_t etherType = ((uint16_t)eth[12] << 8) | eth[13];
    if (etherType == 0x0800 && p->tot_len >= 34) {
      const uint8_t *ipData = eth + 14;
      size_t ipLen = p->tot_len - 14;
      // Bỏ qua gói tin DHCP (UDP port 67/68) để lwIP cấp IP cho thiết bị ngay lập tức
      if (ipLen >= 28 && ipData[9] == 17) {
        uint16_t srcPort = ((uint16_t)ipData[20] << 8) | ipData[21];
        uint16_t dstPort = ((uint16_t)ipData[22] << 8) | ipData[23];
        if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) {
          return original_ap_input ? original_ap_input(p, inp) : (err_t)0;
        }
      }
      inspectGatewayIpPacket(ipData, ipLen);
    }
  }
  return original_ap_input ? original_ap_input(p, inp) : (err_t)0;
}

void initGatewayMode() {
  Serial.println(F("\n========================================================"));
  Serial.println(F("  AERO - CHE DO MICRO-GATEWAY (IOT SECURITY GATEWAY)"));
  Serial.println(F("========================================================"));

  // 1. Đăng ký WiFi events
  WiFi.onEvent(onWiFiEvent);

  // 2. Tắt chế độ ngủ RF để sóng Wi-Fi luôn ổn định 100% công suất
  WiFi.setSleep(false);
  esp_wifi_set_ps(WIFI_PS_NONE);

  // 3. Quét kênh của router mục tiêu trước trong chế độ STA để đồng bộ kênh sóng
  uint8_t apChannel = GATEWAY_AP_CHANNEL;
  bool isUpstreamOpen = false;

  if (strlen(WIFI_SSID) > 0 && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0) {
    Serial.printf("[Gateway] Quet song AP chinh '%s' tren bang tan 2.4GHz de dong bo kenh...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    int n = WiFi.scanNetworks(false, false, false, 250);
    for (int i = 0; i < n; i++) {
      if (WiFi.SSID(i) == WIFI_SSID) {
        apChannel = WiFi.channel(i);
        isUpstreamOpen = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN);
        uint8_t* b = WiFi.BSSID(i);
        if (b) {
          memcpy(targetStaBssid, b, 6);
          hasTargetStaBssid = true;
        }
        Serial.printf("[Gateway] Tim thay '%s' tai kenh %d! Khoa SoftAP va STA cung kenh %d de chong rot song.\n",
                      WIFI_SSID, apChannel, apChannel);
        break;
      }
    }
    WiFi.scanDelete();
  }

  targetStaChannel = apChannel;

  // 4. Chuyển sang chế độ kép AP + STA
  WiFi.mode(WIFI_AP_STA);

  // 5. Cấu hình IP tĩnh và dải DHCP cho SoftAP trước khi bật
  IPAddress local_IP(192, 168, 4, 1);
  IPAddress gateway(192, 168, 4, 1);
  IPAddress subnet(255, 255, 255, 0);
  WiFi.softAPConfig(local_IP, gateway, subnet);

  // 6. Khởi tạo SoftAP phát sóng công khai (WPA2-PSK)
  const char* apPassword = (strlen(GATEWAY_AP_PASSWORD) >= 8) ? GATEWAY_AP_PASSWORD : NULL;
  Serial.printf("[Gateway] Phat SoftAP: '%s' | Mat khau: '%s' | Kenh: %d | Max clients: %d\n",
                GATEWAY_AP_SSID, apPassword ? apPassword : "(Khong pass)", apChannel, GATEWAY_AP_MAX_CLIENTS);

  bool apOk = WiFi.softAP(
      GATEWAY_AP_SSID,
      apPassword,
      apChannel,
      0, // ssid_hidden = 0 (công khai)
      GATEWAY_AP_MAX_CLIENTS
  );

  if (apOk) {
    IPAddress apIp = WiFi.softAPIP();
    esp_wifi_get_mac(WIFI_IF_AP, softApBssid);
    Serial.printf("[Gateway] SoftAP da san sang! IP: %s\n", apIp.toString().c_str());
    Serial.printf("[Gateway] SoftAP BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  softApBssid[0], softApBssid[1], softApBssid[2],
                  softApBssid[3], softApBssid[4], softApBssid[5]);
  } else {
    Serial.println(F("[Gateway] LOI: Khoi tao SoftAP that bai!"));
  }

  // 7. Khởi chạy Captive Portal & DNS Server cho Client
  setupGatewayServers();

  // 8. Bật tự động kết nối lại cho STA và thực hiện kết nối tới Router
  WiFi.setAutoReconnect(true);
  if (strlen(WIFI_SSID) > 0 && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0) {
    const char* staPass = isUpstreamOpen ? NULL : ((strlen(WIFI_PASSWORD) > 0) ? WIFI_PASSWORD : NULL);
    if (hasTargetStaBssid && apChannel > 0) {
      Serial.printf("[Gateway] Dang ket noi STA vao Router: '%s' (Kenh %d)...\n", WIFI_SSID, apChannel);
      WiFi.begin(WIFI_SSID, staPass, apChannel, targetStaBssid);
    } else {
      Serial.printf("[Gateway] Dang ket noi STA vao Router: '%s' (Tu do quet toan bo kenh 1-13)...\n", WIFI_SSID);
      WiFi.begin(WIFI_SSID, staPass);
    }
  }

  // 9. Cài đặt Netif Hook vào Interface SoftAP để bắt trọn gói tin đã giải mã từ lwIP
  esp_netif_t *apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (apNetif) {
    struct netif *lwipNetif = (struct netif *)esp_netif_get_netif_impl(apNetif);
    if (lwipNetif && lwipNetif->input != gateway_ap_input_hook) {
      original_ap_input = lwipNetif->input;
      lwipNetif->input = gateway_ap_input_hook;
      Serial.println(F("[Gateway] Da cai dat Hook vao lwIP netif input cua SoftAP thanh cong!"));
    }
  }

  gatewayActive = true;
}

bool isGatewayModeActive() {
  return gatewayActive;
}

uint8_t getGatewayClientCount() {
  return WiFi.softAPgetStationNum();
}

void maintainGatewayLoop() {
  if (!gatewayActive) return;

  // 1. Phục vụ DNS (Relay nếu đã có Internet STA, hoặc Captive Portal nếu chưa có STA)
  if (dnsRelayActive) {
    processDnsRelay();
  } else {
    gatewayDnsServer.processNextRequest();
  }
  gatewayHttpServer.handleClient();

  unsigned long now = millis();

  // 2. Theo dõi số lượng thiết bị kết nối vào SoftAP
  uint8_t stations = WiFi.softAPgetStationNum();
  if (stations != lastStationCount) {
    lastStationCount = stations;
    if (stations > 0) {
      Serial.printf("\n[Gateway] >>> CO %d THIET BI DANG KET NOI VAO GATEWAY <<<\n", stations);
    } else {
      Serial.println(F("[Gateway] Tat ca thiet bi da ngat ket noi khoi Gateway."));
    }
  }

  // 3. Giám sát trạng thái STA và kích hoạt NAPT ngay khi có IP
  // (Lưu ý: Không gọi WiFi.reconnect() khi chưa cần thiết vì sẽ kích hoạt quét kênh radio làm rớt client SoftAP)
  if (WiFi.status() == WL_CONNECTED) {
    if (!naptEnabled) {
      enableNaptRouter();
    }
  }
}

void inspectGatewayIpPacket(const uint8_t* ipData, size_t length) {
  if (!ipData || length < 20) return;

  float payloadEntropy = 0.0f;
  PacketFeatures features = extractRawIpFeatures(ipData, length, &payloadEntropy);
  if (features.status != PacketFeatureStatus::Ok) return;

  // Đồng bộ số liệu thống kê vào cửa sổ telemetry và OLED
  uint8_t proto = ipData[9]; // IPv4 protocol: 6=TCP, 17=UDP, 1=ICMP
  bool isSyn = (features.values[ESP32_F_TCP_FLAGS] & 0x02) != 0;
  bool isAck = (features.values[ESP32_F_TCP_FLAGS] & 0x10) != 0;
  uint16_t srcPort = (uint16_t)features.values[ESP32_F_TCP_SRCPORT];
  uint16_t dstPort = (uint16_t)features.values[ESP32_F_TCP_DSTPORT];
  recordGatewayPacketStats(length, proto, isSyn, isAck, srcPort, dstPort);

  // Chạy suy luận Machine Learning trực tiếp trên chip
  float modelFeatures[ESP32_PACKET_FEATURE_COUNT];
  for (int i = 0; i < ESP32_PACKET_FEATURE_COUNT; i++) {
    modelFeatures[i] = (float)features.values[i];
  }

  float probs[ESP32_PACKET_CLASS_COUNT] = {0};
  float anomScore = 0.0f;
  float sampleScore = 0.0f;

  if (esp32_predict_packet(modelFeatures, probs, &anomScore, &sampleScore)) {
    int maxClass = 0;
    for (int i = 1; i < ESP32_PACKET_CLASS_COUNT; i++) {
      if (probs[i] > probs[maxClass]) maxClass = i;
    }

    bool isAnomaly = (anomScore >= getDynamicAnomalyThreshold());
    const char* threat = isAnomaly ?
        (strcmp(ESP32_PACKET_LABELS[maxClass], "Normal") == 0 ? "ZeroDay_Anomaly" : ESP32_PACKET_LABELS[maxClass]) : "Normal";

    // Đồng bộ kết quả suy luận vào Edge Inference Manager để đưa vào cửa sổ Telemetry phát định kỳ
    recordGatewayInference(threat, anomScore, probs[maxClass], isAnomaly);

    // Cập nhật metrics
    metrics.total_forwarded_packets++;
    metrics.total_forwarded_bytes += length;
    if (features.values[ESP32_F_TCP_SRCPORT] > 0 || features.values[ESP32_F_TCP_DSTPORT] > 0) {
      metrics.tcp_packets++;
    }
    metrics.latest_entropy = payloadEntropy;
    strncpy(metrics.latest_threat, threat, sizeof(metrics.latest_threat) - 1);
    metrics.latest_confidence = probs[maxClass];

    // In log giám sát Monitor Mode
    static unsigned long lastLogMs = 0;
    if (isAnomaly || (millis() - lastLogMs >= 200)) {
      lastLogMs = millis();
      Serial.printf("[Gateway Monitor] Len: %4u | Port %5u -> %5u | Pred: %-15s (%.1f%%) | Entropy: %.2f | Action: PASS (Monitor Mode)\n",
                    (unsigned)length,
                    (unsigned)srcPort,
                    (unsigned)dstPort,
                    threat,
                    probs[maxClass] * 100.0f,
                    payloadEntropy);

      // Đóng gói bản tin ESP32_PREDICTION
      char predPayload[512];
      snprintf(predPayload, sizeof(predPayload),
               "{\"device_id\":\"%s\",\"inference_status\":\"ok\",\"inference_source\":\"esp32_gateway\",\"anomaly_score\":%.2f,\"is_anomaly\":%s,\"threat_type\":\"%s\",\"confidence\":%.2f,\"severity\":\"%s\",\"raw_telemetry\":{\"record_kind\":\"packet\",\"protocol\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"frame_length\":%u}}",
               MQTT_CLIENT_ID,
               anomScore,
               isAnomaly ? "true" : "false",
               threat,
               probs[maxClass],
               isAnomaly ? "CRITICAL" : "NORMAL",
               (proto == 6 ? "TCP" : (proto == 17 ? "UDP" : "ICMP")),
               (unsigned)srcPort,
               (unsigned)dstPort,
               (unsigned)length);

      // In Serial cho USB Bridge (khi cắm USB) và phát trực tiếp qua Wi-Fi MQTT (khi cắm nguồn ngoài)
      Serial.printf("ESP32_PREDICTION:%s\n", predPayload);
      publishGatewayPrediction(predPayload);
    }

    // Kích hoạt còi/LED và gửi Alert nếu phát hiện bất thường
    if (isAnomaly) {
      metrics.anomaly_detections++;
      setAlertState(true);
      char alertPayload[384];
      snprintf(alertPayload, sizeof(alertPayload),
               "{\"device_id\":\"%s\",\"threat_type\":\"%s\",\"severity\":\"CRITICAL\",\"anomaly_score\":%.2f,\"confidence\":%.2f,\"raw_telemetry\":{\"protocol\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"packet_length\":%u}}",
               MQTT_CLIENT_ID,
               threat,
               anomScore,
               probs[maxClass],
               (proto == 6 ? "TCP" : (proto == 17 ? "UDP" : "ICMP")),
               (unsigned)srcPort,
               (unsigned)dstPort,
               (unsigned)length);
      Serial.printf("ESP32_ALERT:%s\n", alertPayload);
      publishGatewayAlert(alertPayload);
    } else {
      setAlertState(false);
    }
  }
}

void inspectGatewayPacket(const uint8_t* frameData, size_t length) {
  if (!frameData || length < 24) return;

  // Nếu là gói tin 802.11 unencrypted data frame (LLC SNAP)
  if ((frameData[0] & 0x0c) == 8 && !(frameData[1] & 0x40)) {
    size_t headerLength = 24;
    if ((frameData[1] & 3) == 3) headerLength += 6;
    if (frameData[0] & 0x80) {
      headerLength += 2;
      if (frameData[1] & 0x80) headerLength += 4;
    }
    if (length >= headerLength + 8) {
      const uint8_t* llc = frameData + headerLength;
      uint16_t etherType = ((uint16_t)llc[6] << 8) | llc[7];
      if (etherType == 0x0800) {
        inspectGatewayIpPacket(frameData + headerLength + 8, length - headerLength - 8);
        return;
      }
    }
  }

  // Nếu là gói IPv4 trực tiếp
  inspectGatewayIpPacket(frameData, length);
}

GatewayMetrics getGatewayMetrics() {
  return metrics;
}
