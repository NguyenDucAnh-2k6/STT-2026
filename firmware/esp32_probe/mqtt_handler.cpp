#include "mqtt_handler.h"
#include <WiFiMulti.h>
#include <WiFiUdp.h>
#include <ArduinoJson.h>
#include "led_buzzer.h"

static WiFiClient espClient;
static PubSubClient mqttClient(espClient);
static WiFiMulti wifiMulti;
static WiFiUDP udpDiscovery;
static const uint16_t UDP_DISCOVERY_PORT = 18830;
static char currentBrokerHost[64] = MQTT_BROKER_HOST;
static uint32_t probeBootId() {
  static const uint32_t id = esp_random();
  return id;
}

static void publishLocalAlert(const RadioFrame& frame, const EdgeInferenceResult& inf) {
  if (!mqttClient.connected() || !inf.inference_valid || !inf.is_anomaly) return;
  char packetId[128];
  snprintf(packetId, sizeof(packetId), "%s:%lu:native:%lu", MQTT_CLIENT_ID,
           (unsigned long)probeBootId(), (unsigned long)frame.sequence);
  StaticJsonDocument<768> alert;
  alert["device_id"] = MQTT_CLIENT_ID;
  alert["packet_id"] = static_cast<const char*>(packetId);
  alert["inference_status"] = "ok";
  alert["inference_source"] = "esp32";
  alert["is_anomaly"] = true;
  alert["anomaly_score"] = inf.anomaly_score;
  alert["threat_type"] = inf.threat_name;
  alert["confidence"] = inf.confidence;
  alert["edge_model_version"] = ESP32_PACKET_MODEL_ID;
  alert["severity"] = (inf.anomaly_score > .85f || strcmp(inf.threat_name, "DDoS_TCP") == 0 ||
      strcmp(inf.threat_name, "DDoS_UDP") == 0 || strcmp(inf.threat_name, "Port_Scanning") == 0)
      ? "CRITICAL" : (inf.anomaly_score > .65f ? "HIGH" : "MEDIUM");
  JsonObject raw = alert.createNestedObject("raw_telemetry");
  raw["record_kind"] = "packet";
  raw["capture_backend"] = "esp32_native";
  raw["protocol"] = "Unknown";
  raw["frame_length"] = frame.original_length;
  char buffer[1024];
  if (!alert.overflowed() && measureJson(alert) < sizeof(buffer)) {
    serializeJson(alert, buffer, sizeof(buffer));
    if (!mqttClient.publish(TOPIC_LOCAL_ALERT, buffer)) Serial.println(F("[Edge AI] Alert publish failed"));
  } else Serial.println(F("[Edge AI] Alert JSON overflow"));
}

void sendRadioFrame() {
  static RadioFrame frame;
  if (!popRadioFrame(&frame)) return;
  EdgeInferenceResult inf = runPacketEdgeInference(frame);
  setAlertState(inf.inference_valid && inf.is_anomaly);
  publishLocalAlert(frame, inf);
  static char hex[RADIO_FRAME_MAX_BYTES * 2 + 1];
  static char buffer[RADIO_FRAME_MAX_BYTES * 2 + 2304];
  const char* digits = "0123456789abcdef";
  for (uint16_t i = 0; i < frame.captured_length; i++) {
    hex[2 * i] = digits[frame.payload[i] >> 4];
    hex[2 * i + 1] = digits[frame.payload[i] & 15];
  }
  hex[2 * frame.captured_length] = '\0';
  StaticJsonDocument<2304> doc;
  doc["schema_version"] = 1;
  doc["record_kind"] = "radio_frame";
  doc["device_id"] = MQTT_CLIENT_ID;
  doc["boot_id"] = probeBootId();
  doc["sequence"] = frame.sequence;
  doc["timestamp"] = frame.uptime_ms;
  doc["timestamp_kind"] = "uptime_ms";
  doc["linktype"] = 105;
  doc["fcs_included"] = false;
  doc["original_length"] = frame.original_length;
  doc["captured_length"] = frame.captured_length;
  doc["rssi"] = frame.rssi;
  doc["channel"] = frame.channel;
  doc["sample_interval_ms"] = RADIO_FRAME_INTERVAL_MS;
  doc["frame_hex"] = static_cast<const char*>(hex);
  doc["edge_inference_status"] = inf.inference_valid ? "ok" : "unavailable";
  doc["edge_error"] = inf.status_reason;
  doc["edge_input_profile"] = ESP32_PACKET_PROFILE;
  doc["edge_model_version"] = ESP32_PACKET_MODEL_ID;
  doc["edge_model"] = inf.edge_model_name;
  doc["edge_features_count"] = inf.features_count;
  doc["edge_prediction"] = inf.threat_name;
  doc["edge_threshold"] = getDynamicAnomalyThreshold();
  doc["edge_latency_ms"] = inf.latency_us / 1000.0f;
  if (inf.inference_valid) {
    doc["edge_flag"] = inf.is_anomaly;
    doc["edge_anomaly_score"] = inf.anomaly_score;
    doc["edge_confidence"] = inf.confidence;
    JsonObject probabilities = doc.createNestedObject("edge_class_probabilities");
    for (int i = 0; i < ESP32_PACKET_CLASS_COUNT; i++) probabilities[ESP32_PACKET_LABELS[i]] = inf.class_probabilities[i];
    JsonObject rawFeatures = doc.createNestedObject("edge_raw_features");
    for (int i = 0; i < ESP32_PACKET_FEATURE_COUNT; i++) rawFeatures[ESP32_PACKET_FEATURE_NAMES[i]] = inf.raw_features[i];
  } else {
    doc["edge_flag"] = nullptr;
    doc["edge_anomaly_score"] = nullptr;
    doc["edge_confidence"] = nullptr;
  }
  if (doc.overflowed() || measureJson(doc) >= sizeof(buffer)) {
    Serial.println(F("[Radio] JSON overflow; sample dropped"));
    return;
  }
  serializeJson(doc, buffer, sizeof(buffer));
  Serial.print(F("ESP32_RADIO:"));
  Serial.println(buffer);
  if (inf.inference_valid) {
    Serial.printf("[Edge AI] %s | Score %.4f | Confidence %.1f%% | %.3f ms\n",
                  inf.threat_name, inf.anomaly_score, inf.confidence * 100, inf.latency_us / 1000.0f);
  }
  if (mqttClient.connected() && !mqttClient.publish(TOPIC_RADIO_FRAMES, buffer))
    Serial.println(F("[Radio] MQTT publish failed; USB copy already emitted"));
}

static void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, "edge/config/threshold") == 0) {
    if (length > 127) return;
    char msg[128];
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
  if (!mqttClient.setBufferSize(RADIO_FRAME_MAX_BYTES * 2 + 2432)) Serial.println(F("[MQTT] Buffer allocation failed"));
  mqttClient.setSocketTimeout(1);

  if (MQTT_AUTO_DISCOVERY) udpDiscovery.begin(UDP_DISCOVERY_PORT);
  Serial.printf("[UDP Discovery] Lắng nghe Broker Beacon tren cong %d...\n", UDP_DISCOVERY_PORT);
}

void checkUdpDiscovery() {
  if (!MQTT_AUTO_DISCOVERY) return;
  int packetSize = udpDiscovery.parsePacket();
  if (packetSize) {
    char packetBuffer[256];
    int len = udpDiscovery.read(packetBuffer, sizeof(packetBuffer) - 1);
    if (len > 0) {
      packetBuffer[len] = '\0';
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, packetBuffer);
      if (!err && doc["broker_ip"].is<const char*>() && doc["service"] == "AeroEdge") {
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
      StaticJsonDocument<256> doc;
      doc["device_id"] = MQTT_CLIENT_ID;
      doc["status"] = "online";
      doc["ip"] = WiFi.localIP().toString();
      doc["edge_model"] = ESP32_PACKET_MODEL_ID;
      char buf[384];
      if (!doc.overflowed() && measureJson(doc) < sizeof(buf)) {
        serializeJson(doc, buf, sizeof(buf));
        if (!mqttClient.publish(TOPIC_DEVICE_STATUS, buf, true)) Serial.println(F("[MQTT] Status publish failed"));
      }
      mqttClient.subscribe("edge/config/threshold");
      Serial.println(F("[MQTT] Da subscribe topic: edge/config/threshold"));
    } else {
      Serial.printf("[MQTT] That bai, rc=%d. Thu lai sau 5s...\n", mqttClient.state());
    }
  }
}

void maintainMqttLoop(bool allNetworksMode) {
  if (allNetworksMode) return;

  if (wifiMulti.run(250) == WL_CONNECTED) {
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
    const EdgeInferenceResult& inf,
    uint32_t window_ms
) {
  StaticJsonDocument<2048> doc;
  doc["device_id"] = MQTT_CLIENT_ID;
  doc["device_ip"] = (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : "0.0.0.0";
  static uint32_t sequence = 0;
  doc["boot_id"] = probeBootId();
  doc["sequence"] = sequence++;
  doc["timestamp"] = millis();
  doc["timestamp_kind"] = "uptime_ms";
  doc["schema_version"] = 2;
  doc["probe_type"] = "esp32";
  doc["record_kind"] = "window";
  doc["feature_semantics"] = "window-v1";
  doc["capture_backend"] = "wifi_promiscuous";
  doc["window_ms"] = window_ms;
  doc["label_verified"] = false;
  doc["label_source"] = "unverified";
  doc["edge_inference_status"] = inf.inference_valid ? "ok" : "unavailable";
  doc["protocol_features_available"] = false;
  doc["unique_dst_ports_kind"] = "hashed_estimate";
  doc["total_packets"] = snap.total_packets;
  doc["total_bytes"] = snap.total_bytes;
  static uint64_t observedPackets = 0;
  observedPackets += snap.total_packets;
  doc["captured_packets"] = observedPackets;
  doc["capture_id"] = String(probeBootId());
  doc["radio_queue_dropped"] = snap.radio_queue_dropped;
  doc["radio_sample_skipped"] = snap.radio_sample_skipped;
  doc["radio_sample_interval_ms"] = RADIO_FRAME_INTERVAL_MS;
  doc["radio_capture_version"] = 1;

#if SNIFFER_MODE_ALL_NETWORKS
  doc["channel"] = channel;
  doc["sniffer_mode"] = "all-networks";
#else
  doc["channel"] = channel;
  doc["sniffer_mode"] = "ap-locked";
#endif

  doc["packet_rate"] = round(packet_rate * 100) / 100.0;
  doc["byte_rate"] = round(byte_rate * 100) / 100.0;
  doc["avg_packet_size"] = round(avg_packet_size * 10) / 10.0;
  // Encrypted Wi-Fi payloads prevent complete transport measurements.
  // Observed plaintext counts are separate from unavailable total-traffic ratios.
  doc["observed_tcp_count"] = snap.tcp_packets;
  doc["observed_udp_count"] = snap.udp_packets;
  doc["observed_icmp_count"] = snap.icmp_packets;
  doc["observed_unique_port_buckets"] = snap.unique_ports_count;

  // Đóng gói danh sách mạng WiFi (SSID)
  JsonArray netArr = doc.createNestedArray("scanned_networks");
  DetectedWifiNetwork nets[5];
  uint8_t exportCount = copyDetectedWifiNetworks(nets, 5);
  for (uint8_t i = 0; i < exportCount; i++) {
    JsonObject nObj = netArr.createNestedObject();
    nObj["ssid"] = nets[i].ssid;
    nObj["rssi"] = nets[i].rssi;
    nObj["channel"] = nets[i].channel;
  }
  doc["wifi_networks_count"] = exportCount;

  // Kết quả Edge AI
  if (inf.inference_valid) doc["edge_flag"] = inf.is_anomaly;
  else doc["edge_flag"] = nullptr;
  doc["edge_prediction"] = inf.threat_name;
  doc["edge_model"] = inf.edge_model_name;
  doc["edge_features_count"] = inf.features_count;

  char jsonBuffer[2048];
  if (doc.overflowed() || measureJson(doc) >= sizeof(jsonBuffer)) {
    Serial.println(F("[Telemetry] JSON overflow; dropped window"));
    return;
  }
  serializeJson(doc, jsonBuffer, sizeof(jsonBuffer));

  // In Serial giám sát cho USB Bridge
  if (inf.inference_valid) {
    Serial.printf("[Telemetry] Pkts/s: %.1f | Bytes/s: %.0f | Threat: %s (Score: %.2f)\n",
                  packet_rate, byte_rate, inf.threat_name, inf.anomaly_score);
  } else {
    Serial.printf("[Telemetry] Pkts/s: %.1f | Bytes/s: %.0f | Local inference: N/A\n",
                  packet_rate, byte_rate);
  }
  Serial.print(F("ESP32_TELEMETRY:"));
  Serial.println(jsonBuffer);

  // Gửi qua MQTT (khi có kết nối WiFi)
  if (mqttClient.connected()) {
    if (!mqttClient.publish(TOPIC_TRAFFIC_TELEMETRY, jsonBuffer))
      Serial.println(F("[MQTT] Telemetry publish failed"));
    if (!mqttClient.publish("edge/telemetry/window", jsonBuffer))
      Serial.println(F("[MQTT] Window publish failed"));
  }
}
