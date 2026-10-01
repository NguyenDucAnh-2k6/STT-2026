#include "edge_inference.h"

static float dynamicAnomalyThreshold = TINYML_ANOMALY_THRESHOLD;

void initEdgeInference() {
  dynamicAnomalyThreshold = TINYML_ANOMALY_THRESHOLD;
  Serial.printf("[EdgeInference] Khoi tao TinyML: %s + %s (%d features)\n",
                TINYML_CLASSIFIER_NAME, TINYML_ANOMALY_DETECTOR_NAME, TINYML_IN_FEATURES);
}

void setDynamicAnomalyThreshold(float threshold) {
  dynamicAnomalyThreshold = threshold;
  Serial.printf("[EdgeInference] Cap nhat Anomaly Threshold: %.2f\n", threshold);
}

float getDynamicAnomalyThreshold() {
  return dynamicAnomalyThreshold;
}

EdgeInferenceResult runEdgeInference(
    const TrafficWindowStats& snap,
    float packet_rate,
    float byte_rate,
    float avg_packet_size
) {
  EdgeInferenceResult res;
  res.features_count = TINYML_IN_FEATURES;

  float raw_features[TINYML_IN_FEATURES];
  memset(raw_features, 0, sizeof(raw_features));

  // Ánh xạ các đặc trưng từ Promiscuous Sniffer vào vector chuẩn Edge-IIoTset
  raw_features[25] = avg_packet_size;                            // tcp.len
  raw_features[20] = (snap.syn_packets > 0) ? 1.0f : 0.0f;       // tcp.connection.syn
  raw_features[24] = (snap.ack_packets > 0) ? 1.0f : 0.0f;       // tcp.flags.ack
  raw_features[23] = (snap.syn_packets > 0) ? 2.0f : ((snap.ack_packets > 0) ? 16.0f : 0.0f); // tcp.flags
  raw_features[30] = (snap.udp_packets > 0) ? 53.0f : 0.0f;      // udp.port
  raw_features[31] = (snap.udp_packets > 0) ? packet_rate : 0.0f; // udp.stream
  raw_features[2]  = (snap.icmp_packets > 0) ? 1.0f : 0.0f;      // icmp.checksum
  raw_features[3]  = (snap.icmp_packets > 0) ? packet_rate : 0.0f;// icmp.seq_le

  bool raw_anomaly_flag = false;
  float score = tinyml_predict_anomaly(raw_features, &raw_anomaly_flag);
  float conf = 1.0f;
  int pred_idx = tinyml_predict_classifier(raw_features, &conf);
  const char* threat = tinyml_get_threat_name(pred_idx);

  // TÔN TRỌNG TRIỆT ĐỂ NGƯỠNG ANOMALY SCORE DO NGƯỜI DÙNG KÉO TRÊN UI / THIẾT LẬP
  bool is_exceeded = (score >= dynamicAnomalyThreshold);
  if (is_exceeded) {
    res.is_anomaly = true;
    res.threat_name = (strcmp(threat, "Normal") == 0 || strcmp(threat, "normal") == 0) ? "Anomaly" : threat;
  } else {
    res.is_anomaly = false;
    res.threat_name = "Normal";
  }

  res.anomaly_score = score;
  res.confidence = conf;
  res.edge_model_name = TINYML_CLASSIFIER_NAME;
  return res;
}
