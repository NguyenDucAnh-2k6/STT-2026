#ifndef EDGE_INFERENCE_H
#define EDGE_INFERENCE_H

#include <Arduino.h>
#include "sniffer.h"
#include "packet_features.h"

struct EdgeInferenceResult {
  float anomaly_score;
  bool is_anomaly;
  bool inference_valid;
  const char* threat_name;
  float confidence;
  const char* edge_model_name;
  uint16_t features_count;
  float class_probabilities[ESP32_PACKET_CLASS_COUNT];
  uint32_t raw_features[ESP32_PACKET_FEATURE_COUNT];
  const char* status_reason;
  uint32_t sequence;
  uint32_t inferred_at_ms;
  uint32_t latency_us;
};

// Khởi tạo bộ suy luận TinyML / TFLite trên chip
void initEdgeInference();

// Cập nhật ngưỡng phán quyết bất thường động
void setDynamicAnomalyThreshold(float threshold);
float getDynamicAnomalyThreshold();

EdgeInferenceResult runPacketEdgeInference(const RadioFrame& frame);
EdgeInferenceResult getLatestEdgeInference();

#endif // EDGE_INFERENCE_H
