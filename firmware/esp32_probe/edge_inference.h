#ifndef EDGE_INFERENCE_H
#define EDGE_INFERENCE_H

#include <Arduino.h>
#include "sniffer.h"
#include "packet_features.h"
#include "wireless_features.h"

struct EdgeInferenceResult {
  float anomaly_score;
  bool is_anomaly;
  bool inference_valid;
  const char* threat_name;
  float confidence;
  const char* edge_model_name;
  const char* edge_profile;
  const char* edge_model_id;
  uint16_t features_count;
  uint16_t classes_count;
  const char* const* feature_names;
  const char* const* class_labels;
  float class_probabilities[16];
  uint32_t raw_features[16];
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
void recordGatewayInference(const char* threat, float anomScore, float confidence, bool isAnomaly);

#endif // EDGE_INFERENCE_H
