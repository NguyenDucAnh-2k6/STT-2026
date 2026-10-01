#ifndef EDGE_INFERENCE_H
#define EDGE_INFERENCE_H

#include <Arduino.h>
#include "sniffer.h"
#include "tinyml_model.h"

struct EdgeInferenceResult {
  float anomaly_score;
  bool is_anomaly;
  const char* threat_name;
  float confidence;
  const char* edge_model_name;
  uint16_t features_count;
};

// Khởi tạo bộ suy luận TinyML / TFLite trên chip
void initEdgeInference();

// Cập nhật ngưỡng phán quyết bất thường động
void setDynamicAnomalyThreshold(float threshold);
float getDynamicAnomalyThreshold();

// Thực thi suy luận cục bộ trên vector 56 đặc trưng Edge-IIoTset
EdgeInferenceResult runEdgeInference(
    const TrafficWindowStats& snap,
    float packet_rate,
    float byte_rate,
    float avg_packet_size
);

#endif // EDGE_INFERENCE_H
