#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Real-time Inference Engine
==============================================================
Lắng nghe luồng telemetry từ thiết bị biên (ESP32 hoặc Simulator) qua MQTT.
Chạy suy luận mô hình học máy (Isolation Forest + Decision Classifier) theo thời gian thực
với độ trễ cực thấp (< 2ms).
Gửi cảnh báo tức thì khi phát hiện tấn công mạng.
"""

import os
import sys
import time
import json
import argparse
import numpy as np
import joblib
import paho.mqtt.client as mqtt

FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "syn_ratio",
    "ack_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_dst_ports"
]

LABEL_NAMES = ["Normal", "SYN_Flood", "Port_Scan", "Volumetric_DDoS", "Data_Exfiltration"]

class AnomalyInferenceEngine:
    def __init__(self, models_dir: str, anomaly_threshold: float = 0.55):
        self.models_dir = models_dir
        self.anomaly_threshold = anomaly_threshold
        self.scaler = None
        self.iso_forest = None
        self.classifier = None
        self.metadata = {}
        self.load_models()

    def load_models(self):
        scaler_path = os.path.join(self.models_dir, "scaler.joblib")
        iso_path = os.path.join(self.models_dir, "isolation_forest.joblib")
        clf_path = os.path.join(self.models_dir, "attack_classifier.joblib")
        meta_path = os.path.join(self.models_dir, "model_metadata.json")

        if not (os.path.exists(scaler_path) and os.path.exists(iso_path) and os.path.exists(clf_path)):
            print(f"[InferenceEngine] Khong tim thay models tai {self.models_dir}!")
            print("  -> Vui long chay: python ml_engine/train.py truoc.")
            sys.exit(1)

        self.scaler = joblib.load(scaler_path)
        self.iso_forest = joblib.load(iso_path)
        self.classifier = joblib.load(clf_path)

        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        print("[InferenceEngine] Da load thanh cong Isolation Forest & Decision Classifier!")

    def predict(self, telemetry: dict) -> dict:
        """
        Dự đoán bất thường từ gói dữ liệu telemetry
        """
        start_time = time.perf_counter()

        # Trích xuất vector đặc trưng
        try:
            raw_features = np.array([[
                float(telemetry.get("packet_rate", 0.0)),
                float(telemetry.get("byte_rate", 0.0)),
                float(telemetry.get("avg_packet_size", 0.0)),
                float(telemetry.get("syn_ratio", 0.0)),
                float(telemetry.get("ack_ratio", 0.0)),
                float(telemetry.get("udp_ratio", 0.0)),
                float(telemetry.get("icmp_ratio", 0.0)),
                float(telemetry.get("unique_dst_ports", 0.0))
            ]], dtype=np.float32)
        except Exception as e:
            return {"error": f"Invalid telemetry format: {e}"}

        # 1. Dự đoán bất thường bằng Isolation Forest
        scaled_features = self.scaler.transform(raw_features)
        score_sample = self.iso_forest.score_samples(scaled_features)[0]
        
        # Chuẩn hóa anomaly score trong khoảng [0.0, 1.0] (Càng cao càng nguy hiểm)
        score_min = self.metadata.get("isolation_score_min", -0.75)
        score_max = self.metadata.get("isolation_score_max", -0.35)
        # Điểm score_samples: âm hơn = bất thường hơn
        normalized_score = 1.0 - (score_sample - score_min) / (score_max - score_min + 1e-8)
        normalized_score = float(np.clip(normalized_score, 0.0, 1.0))

        # 2. Phân loại loại hình lưu lượng bằng Decision Tree
        class_idx = int(self.classifier.predict(raw_features)[0])
        class_proba = self.classifier.predict_proba(raw_features)[0]
        attack_type = LABEL_NAMES[class_idx]
        confidence = float(class_proba[class_idx])

        # Đánh giá xem có phải Anomaly hay không
        is_anomaly = bool(normalized_score >= self.anomaly_threshold or attack_type != "Normal")
        
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Xác định mức độ nghiêm trọng (Severity)
        if not is_anomaly:
            severity = "NORMAL"
        elif normalized_score > 0.85 or attack_type in ["Volumetric_DDoS", "SYN_Flood"]:
            severity = "CRITICAL"
        elif normalized_score > 0.65:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "device_id": telemetry.get("device_id", "unknown-probe"),
            "timestamp": telemetry.get("timestamp", int(time.time() * 1000)),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(normalized_score, 4),
            "severity": severity,
            "threat_type": attack_type,
            "confidence": round(confidence, 4),
            "latency_ms": round(latency_ms, 2),
            "raw_telemetry": telemetry
        }

def main():
    parser = argparse.ArgumentParser(description="Edge AI Real-time Anomaly Inference Service")
    parser.add_argument("--broker", default="127.0.0.1", help="MQTT Broker IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT Broker Port (default: 1883)")
    parser.add_argument("--threshold", type=float, default=0.55, help="Anomaly Score Threshold (default: 0.55)")
    args = parser.parse_args()

    models_dir = os.path.join(os.path.dirname(__file__), "models")
    engine = AnomalyInferenceEngine(models_dir=models_dir, anomaly_threshold=args.threshold)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="EdgeAI-Host-Inference-Engine")

    def on_connect(c, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[InferenceService] Da ket noi den MQTT Broker {args.broker}:{args.port}")
            client.subscribe("edge/telemetry/traffic")
            print("[InferenceService] Da subscribe topic: 'edge/telemetry/traffic'")
        else:
            print(f"[InferenceService] Ket noi broker that bai, ma loi rc={rc}")

    def on_message(c, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            result = engine.predict(payload)

            # Publish kết quả dự đoán cho Dashboard
            res_json = json.dumps(result)
            client.publish("edge/telemetry/prediction", res_json)

            # Nếu phát hiện bất thường nghiêm trọng, bắn cảnh báo
            if result.get("is_anomaly", False):
                client.publish("edge/alerts/high_priority", res_json)
                print(f" [!!! ALERT - {result['severity']} !!!] {result['threat_type']} "
                      f"(Score: {result['anomaly_score']:.2f} | Conf: {result['confidence']*100:.1f}%) "
                      f"from Node: {result['device_id']} [Latency: {result['latency_ms']}ms]")
            else:
                print(f" [OK] Normal Traffic (Score: {result['anomaly_score']:.2f}) "
                      f"Pkts/s: {payload.get('packet_rate', 0)} [Latency: {result['latency_ms']}ms]")

        except Exception as e:
            print(f"[InferenceService] Loi xu ly packet: {e}")

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(args.broker, args.port, keepalive=60)
        print("==================================================")
        print(f"  EDGE AI INFERENCE SERVICE DANG CHAY...")
        print(f"  - Broker: {args.broker}:{args.port}")
        print(f"  - Nguong canh bao Anomaly: {args.threshold}")
        print("==================================================")
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[InferenceService] Dang dung dich vu...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
