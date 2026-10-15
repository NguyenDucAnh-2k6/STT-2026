#include "edge_inference.h"

static float dynamicAnomalyThreshold = ESP32_PACKET_THRESHOLD;
static EdgeInferenceResult latestResult = {};
static bool hasResult = false;

static EdgeInferenceResult unavailable(const char* reason) {
  EdgeInferenceResult result = {};
  result.features_count = ESP32_PACKET_FEATURE_COUNT;
  result.threat_name = "Unknown";
  result.edge_model_name = ESP32_PACKET_MODEL_NAME;
  result.status_reason = reason;
  return result;
}

void initEdgeInference() {
  dynamicAnomalyThreshold = ESP32_PACKET_THRESHOLD;
  latestResult = unavailable("awaiting_packet");
  Serial.printf("[EdgeInference] Local profile: %s | %d features | Model: %s\n",
                ESP32_PACKET_PROFILE, ESP32_PACKET_FEATURE_COUNT, ESP32_PACKET_MODEL_ID);
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
  PacketFeatures features = extractPacketFeatures(frame.payload, frame.captured_length, frame.original_length);
  EdgeInferenceResult result = unavailable(packetFeatureStatusName(features.status));
  result.sequence = frame.sequence;
  result.inferred_at_ms = millis();
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
