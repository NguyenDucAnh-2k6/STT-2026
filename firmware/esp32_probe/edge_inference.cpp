#include "edge_inference.h"
#include "tinyml_model.h"

#if defined(TINYML_IN_FEATURES) && (TINYML_IN_FEATURES == 14)
#define EDGE_USE_WIRELESS_MODEL 1
#endif

#ifdef EDGE_USE_WIRELESS_MODEL
static float dynamicAnomalyThreshold = TINYML_ANOMALY_THRESHOLD;
#else
static float dynamicAnomalyThreshold = ESP32_PACKET_THRESHOLD;
#endif

static EdgeInferenceResult latestResult = {};
static bool hasResult = false;

static EdgeInferenceResult unavailable(const char* reason) {
  EdgeInferenceResult result = {};
#ifdef EDGE_USE_WIRELESS_MODEL
  result.features_count = 14;
  result.classes_count = TINYML_NUM_CLASSES;
  result.feature_names = WIRELESS_FEATURE_NAMES;
  result.class_labels = TINYML_CLASS_NAMES;
  result.threat_name = "Unknown";
  result.edge_model_name = TINYML_CLASSIFIER_NAME " + " TINYML_ANOMALY_DETECTOR_NAME;
  result.edge_profile = "awid3-wifi-v1";
#ifdef TINYML_MODEL_ID
  result.edge_model_id = TINYML_MODEL_ID;
#else
  result.edge_model_id = (strcmp(TINYML_CLASSIFIER_NAME, "RandomForestClassifier") == 0)
      ? "e054fbe54abb4b9abdeb9f38e5a55dbe"
      : "c02de90fb05b4eca866efed48f3fa130";
#endif
#else
  result.features_count = ESP32_PACKET_FEATURE_COUNT;
  result.classes_count = ESP32_PACKET_CLASS_COUNT;
  result.feature_names = ESP32_PACKET_FEATURE_NAMES;
  result.class_labels = ESP32_PACKET_LABELS;
  result.threat_name = "Unknown";
  result.edge_model_name = ESP32_PACKET_MODEL_NAME;
  result.edge_profile = ESP32_PACKET_PROFILE;
  result.edge_model_id = ESP32_PACKET_MODEL_ID;
#endif
  result.status_reason = reason;
  return result;
}

void initEdgeInference() {
#ifdef EDGE_USE_WIRELESS_MODEL
  dynamicAnomalyThreshold = TINYML_ANOMALY_THRESHOLD;
  latestResult = unavailable("awaiting_packet");
  Serial.printf("[EdgeInference] Local profile: awid3-wifi-v1 | 14 features | AWID3 Wireless WIDS Model\n");
#else
  dynamicAnomalyThreshold = ESP32_PACKET_THRESHOLD;
  latestResult = unavailable("awaiting_packet");
  Serial.printf("[EdgeInference] Local profile: %s | %d features | Model: %s\n",
                ESP32_PACKET_PROFILE, ESP32_PACKET_FEATURE_COUNT, ESP32_PACKET_MODEL_ID);
#endif
}

void setDynamicAnomalyThreshold(float threshold) {
  if (!isfinite(threshold) || threshold < 0.0f || threshold > 1.0f) return;
  dynamicAnomalyThreshold = threshold;
  Serial.printf("[EdgeInference] Cap nhat Anomaly Threshold: %.2f\n", threshold);
}

float getDynamicAnomalyThreshold() {
  return dynamicAnomalyThreshold;
}

EdgeInferenceResult runPacketEdgeInference(const RadioFrame& frame) {
  uint32_t startedUs = micros();
  EdgeInferenceResult result = unavailable("processing");
  result.sequence = frame.sequence;
  result.inferred_at_ms = millis();

#ifdef EDGE_USE_WIRELESS_MODEL
  float wirelessFeatures[14];
  if (extractWirelessFeatures(frame.payload, frame.captured_length, frame.original_length, frame.rssi, frame.channel, wirelessFeatures)) {
    float confidence = 1.0f;
    int pred_class = tinyml_predict_classifier_proba(wirelessFeatures, result.class_probabilities, &confidence);
    bool is_anom = false;
    float anom_score = tinyml_predict_anomaly(wirelessFeatures, &is_anom);

    result.features_count = 14;
    result.classes_count = TINYML_NUM_CLASSES;
    result.feature_names = WIRELESS_FEATURE_NAMES;
    result.class_labels = TINYML_CLASS_NAMES;
    result.confidence = confidence;
    result.anomaly_score = anom_score;
    result.is_anomaly = (anom_score >= dynamicAnomalyThreshold);
    const char* pred_name = tinyml_get_threat_name(pred_class);
    result.threat_name = result.is_anomaly ?
        (strcmp(pred_name, "Normal") == 0 ? "ZeroDay_Anomaly" : pred_name) : "Normal";
    result.edge_model_name = TINYML_CLASSIFIER_NAME " + " TINYML_ANOMALY_DETECTOR_NAME;
    result.edge_profile = "awid3-wifi-v1";
#ifdef TINYML_MODEL_ID
    result.edge_model_id = TINYML_MODEL_ID;
#else
    result.edge_model_id = (strcmp(TINYML_CLASSIFIER_NAME, "RandomForestClassifier") == 0)
        ? "e054fbe54abb4b9abdeb9f38e5a55dbe"
        : "c02de90fb05b4eca866efed48f3fa130";
#endif
    result.inference_valid = true;
    result.status_reason = "ok";

    for (int i = 0; i < 14; i++) {
      result.raw_features[i] = (uint32_t)wirelessFeatures[i];
    }
  } else {
    result = unavailable("malformed_frame");
  }
#else
  PacketFeatures features = extractPacketFeatures(frame.payload, frame.captured_length, frame.original_length);
  result = unavailable(packetFeatureStatusName(features.status));
  if (features.status == PacketFeatureStatus::Ok) {
    memcpy(result.raw_features, features.values, sizeof(result.raw_features));
    float modelFeatures[ESP32_PACKET_FEATURE_COUNT];
    for (int i = 0; i < ESP32_PACKET_FEATURE_COUNT; i++) modelFeatures[i] = (float)features.values[i];
    float scoreSample = 0;
    if (esp32_predict_packet(modelFeatures, result.class_probabilities, &result.anomaly_score, &scoreSample)) {
      int classIndex = 0;
      for (int i = 1; i < ESP32_PACKET_CLASS_COUNT; i++) {
        if (result.class_probabilities[i] > result.class_probabilities[classIndex]) classIndex = i;
      }
      result.confidence = result.class_probabilities[classIndex];
      result.is_anomaly = result.anomaly_score >= dynamicAnomalyThreshold;
      result.threat_name = result.is_anomaly ?
          (strcmp(ESP32_PACKET_LABELS[classIndex], "Normal") == 0 ? "ZeroDay_Anomaly" : ESP32_PACKET_LABELS[classIndex]) : "Normal";
      result.inference_valid = true;
      result.status_reason = "ok";
    } else result.status_reason = "invalid_model_output";
  }
#endif

  result.latency_us = (uint32_t)(micros() - startedUs);
  latestResult = result;
  hasResult = true;
  return result;
}

EdgeInferenceResult getLatestEdgeInference() {
  if (!hasResult) return unavailable("awaiting_packet");
  if ((uint32_t)(millis() - latestResult.inferred_at_ms) > 5000) return unavailable("stale_packet");
  return latestResult;
}

void recordGatewayInference(const char* threat, float anomScore, float confidence, bool isAnomaly) {
  latestResult.threat_name = threat;
  latestResult.anomaly_score = anomScore;
  latestResult.confidence = confidence;
  latestResult.is_anomaly = isAnomaly;
  latestResult.inference_valid = true;
  latestResult.status_reason = "ok";
  latestResult.inferred_at_ms = millis();
  latestResult.sequence++;
  hasResult = true;
}
