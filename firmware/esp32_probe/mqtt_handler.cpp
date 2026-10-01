#include "mqtt_handler.h"
#include <WiFiMulti.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>

static WiFiClient espClient;
static PubSubClient mqttClient(espClient);
static WiFiMulti wifiMulti;
static WiFiUDP udpDiscovery;
static const uint16_t UDP_DISCOVERY_PORT = 18830;
static char currentBrokerHost[64] = MQTT_BROKER_HOST;

static void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, "edge/config/threshold") == 0) {
    char msg[length + 1];
    memcpy(msg, payload, length);
    msg[length] = '\0';
    StaticJsonDocument<128> doc;
    DeserializationError error = deserializeJson(doc, msg);
    if (!error && doc.containsKey("threshold")) {
      float newThresh = doc["threshold"].as<float>();
      setDynamicAnomalyThreshold(newThresh);
      Serial.printf("[MQTT] Da cap nhat Anomaly Threshold tu UI: %.2f\n", newThresh);
    }
  }
}

void initMqttAndWiFi(bool allNetworksMode) {
  if (allNetworksMode) {
    Serial.println(F("\n=================================================="));
    Serial.println(F(" [Sniffer] CHE DO FULL-SPECTRUM ALL-NETWORKS"));
    Serial.println(F("  * Khong rang buoc AP, radio tu do nhay 13 kenh!"));
    Serial.println(F("  * Bat tron moi goi tin tu tat ca router & thiet bi xung quanh!"));
    Serial.println(F("  * Telemetry duoc day ve Data Lake qua cap USB Serial 115200 baud."));
    Serial.println(F("=================================================="));
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    return;
  }

  Serial.println(F("\n[WiFi] Khoi dong WiFiMulti tu dong ket noi AP tot nhat..."));
  WiFi.mode(WIFI_STA);
  wifiMulti.addAP(WIFI_SSID, WIFI_PASSWORD);

#ifdef BACKUP_WIFI_SSID
  wifiMulti.addAP(BACKUP_WIFI_SSID, BACKUP_WIFI_PASSWORD);
#endif

  mqttClient.setServer(currentBrokerHost, MQTT_BROKER_PORT);
  mqttClient.setCallback(onMqttMessage);
  mqttClient.setBufferSize(1024);

  udpDiscovery.begin(UDP_DISCOVERY_PORT);
  Serial.printf("[UDP Discovery] Lắng nghe Broker Beacon tren cong %d...\n", UDP_DISCOVERY_PORT);
}

void checkUdpDiscovery() {
  int packetSize = udpDiscovery.parsePacket();
  if (packetSize) {
    char packetBuffer[256];
    int len = udpDiscovery.read(packetBuffer, sizeof(packetBuffer) - 1);
    if (len > 0) {
      packetBuffer[len] = '\0';
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, packetBuffer);
      if (!err && doc.containsKey("broker_ip")) {
        const char* newBroker = doc["broker_ip"];
        if (strcmp(currentBrokerHost, newBroker) != 0) {
          strncpy(currentBrokerHost, newBroker, sizeof(currentBrokerHost) - 1);
          currentBrokerHost[sizeof(currentBrokerHost) - 1] = '\0';
          Serial.printf("\n[UDP Discovery] >>> Phat hien Broker IP moi: %s! <<<\n", currentBrokerHost);
          mqttClient.disconnect();
          mqttClient.setServer(currentBrokerHost, MQTT_BROKER_PORT);
        }
      }
    }
  }
}

static void reconnectMqtt() {
  static unsigned long lastReconnectAttempt = 0;
  unsigned long now = millis();
  if (now - lastReconnectAttempt > 5000) {
    lastReconnectAttempt = now;
    Serial.printf("[MQTT] Dang ket noi den Broker tai %s:%d...\n", currentBrokerHost, MQTT_BROKER_PORT);
    String clientId = String(MQTT_CLIENT_ID) + "-" + String(random(0xffff), HEX);
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println(F("[MQTT] Ket noi thanh cong!"));
      StaticJsonDocument<128> doc;
      doc["device_id"] = MQTT_CLIENT_ID;
      doc["status"] = "online";
      doc["ip"] = WiFi.localIP().toString();
      doc["edge_model"] = TINYML_CLASSIFIER_NAME;
      char buf[128];
      serializeJson(doc, buf);
      mqttClient.publish(TOPIC_DEVICE_STATUS, buf, true);
      mqttClient.subscribe("edge/config/threshold");
      Serial.println(F("[MQTT] Da subscribe topic: edge/config/threshold"));
    } else {
      Serial.printf("[MQTT] That bai, rc=%d. Thu lai sau 5s...\n", mqttClient.state());
    }
  }
}

void maintainMqttLoop(bool allNetworksMode) {
  if (allNetworksMode) return;

  if (wifiMulti.run() == WL_CONNECTED) {
    checkUdpDiscovery();
    if (!mqttClient.connected()) {
      reconnectMqtt();
    } else {
      mqttClient.loop();
    }
  }
}

bool isWiFiConnected() {
  return WiFi.status() == WL_CONNECTED;
}

bool isMqttConnected() {
  return mqttClient.connected();
}

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
    const EdgeInferenceResult& inf
) {
  StaticJsonDocument<1536> doc;
  doc["device_id"] = MQTT_CLIENT_ID;
  doc["device_ip"] = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : "0.0.0.0";
  doc["timestamp"] = millis();

#if SNIFFER_MODE_ALL_NETWORKS
  doc["channel"] = "HOP(1-13)";
  doc["sniffer_mode"] = "all-networks";
#else
  doc["channel"] = String(channel);
  doc["sniffer_mode"] = "ap-locked";
#endif

  doc["packet_rate"] = round(packet_rate * 100) / 100.0;
  doc["byte_rate"] = round(byte_rate * 100) / 100.0;
  doc["avg_packet_size"] = round(avg_packet_size * 10) / 10.0;
  doc["syn_ratio"] = round(syn_ratio * 1000) / 1000.0;
  doc["ack_ratio"] = round(ack_ratio * 1000) / 1000.0;
  doc["udp_ratio"] = round(udp_ratio * 1000) / 1000.0;
  doc["icmp_ratio"] = round(icmp_ratio * 1000) / 1000.0;
  doc["unique_dst_ports"] = snap.unique_ports_count;
  doc["tcp_count"] = snap.tcp_packets;
  doc["udp_count"] = snap.udp_packets;
  doc["icmp_count"] = snap.icmp_packets;

  // Đóng gói danh sách mạng WiFi (SSID)
  JsonArray netArr = doc.createNestedArray("scanned_networks");
  const DetectedWifiNetwork* nets = getDetectedWifiNetworks();
  uint8_t netCount = getDetectedWifiCount();
  uint8_t exportCount = (netCount < 5) ? netCount : 5;
  for (uint8_t i = 0; i < exportCount; i++) {
    JsonObject nObj = netArr.createNestedObject();
    nObj["ssid"] = nets[i].ssid;
    nObj["rssi"] = nets[i].rssi;
    nObj["channel"] = nets[i].channel;
  }
  doc["wifi_networks_count"] = netCount;

  // Kết quả Edge AI
  doc["edge_flag"] = inf.is_anomaly;
  doc["edge_prediction"] = inf.threat_name;
  doc["edge_model"] = String(TINYML_CLASSIFIER_NAME) + " + " + String(TINYML_ANOMALY_DETECTOR_NAME);
  doc["edge_features_count"] = inf.features_count;

  char jsonBuffer[2048];
  serializeJson(doc, jsonBuffer, sizeof(jsonBuffer));

  // In Serial giám sát cho USB Bridge
  Serial.printf("[Telemetry] Pkts/s: %.1f | Bytes/s: %.0f | Threat: %s (Score: %.2f)\n",
                packet_rate, byte_rate, inf.threat_name, inf.anomaly_score);
  Serial.print(F("ESP32_TELEMETRY:"));
  Serial.println(jsonBuffer);

  // Gửi qua MQTT (khi có kết nối WiFi)
  if (mqttClient.connected()) {
    mqttClient.publish(TOPIC_TRAFFIC_TELEMETRY, jsonBuffer);
    if (inf.is_anomaly) {
      mqttClient.publish(TOPIC_LOCAL_ALERT, jsonBuffer);
    }
  }
}
