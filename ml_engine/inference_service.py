#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Real-time Inference Service
==============================================================
Chỉ dẫn module:
- Module này thực hiện suy luận thời gian thực cho luồng lưu lượng mạng:
  1. Kết nối đến MQTT Broker (Mosquitto hoặc Embedded Broker), lắng nghe topic:
     'edge/telemetry/traffic' từ thiết bị biên (ESP32) hoặc Simulator.
  2. Trích xuất vector đặc trưng bằng TrafficFeaturePreprocessor.
  3. Suy luận song song 2 tầng:
     - Tầng 1: Bộ phát hiện bất thường Unsupervised (Anomaly Score [0.0 - 1.0]).
     - Tầng 2: Bộ phân loại đa lớp (Attack Classifier xác định cụ thể loại tấn công).
  4. Đánh giá mức độ nguy hiểm (Severity: NORMAL, MEDIUM, HIGH, CRITICAL).
  5. Đẩy kết quả suy luận lên topic 'edge/telemetry/prediction' và
     phát cảnh báo khẩn cấp lên 'edge/alerts/high_priority'.
- Thời gian trích xuất & suy luận: < 1.5ms mỗi gói tin.

Cú pháp sử dụng dòng lệnh:
    python ml_engine/inference_service.py --broker 127.0.0.1 --port 1883 --threshold 0.55
"""

import os
import sys
import time
import json
import argparse
from typing import Dict, Any, Optional

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path khi gọi trực tiếp
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Đảm bảo UTF-8 hoặc an toàn mã hóa trên Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import joblib
import paho.mqtt.client as mqtt

from ml_engine.config.schema import (
    FEATURE_NAMES,
    LABEL_NAMES,
    DEFAULT_ANOMALY_THRESHOLD
)
from ml_engine.preprocessing import (
    TrafficFeaturePreprocessor,
    EdgeTrafficPreprocessor
)


class AnomalyInferenceEngine:
    """
    Bộ động cơ suy luận học máy nhận diện mối đe dọa mạng thời gian thực.
    """

    def __init__(
        self,
        models_dir: Optional[str] = None,
        anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD
    ):
        if models_dir is None:
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            models_dir = os.path.join(root_dir, "ml_engine", "models")

        self.models_dir: str = models_dir
        self.anomaly_threshold: float = anomaly_threshold
        self.preprocessor: Optional[TrafficFeaturePreprocessor] = None
        self.anomaly_detector: Any = None
        self.classifier: Any = None
        self.metadata: Dict[str, Any] = {}

        self.load_models()

    def load_models(self):
        """Nạp các mô hình học máy và preprocessor từ đĩa."""
        scaler_path = os.path.join(self.models_dir, "scaler.joblib")
        iso_path = os.path.join(self.models_dir, "isolation_forest.joblib")
        clf_path = os.path.join(self.models_dir, "attack_classifier.joblib")
        meta_path = os.path.join(self.models_dir, "model_metadata.json")

        if not (os.path.exists(scaler_path) and os.path.exists(iso_path) and os.path.exists(clf_path)):
            print(f"[InferenceEngine] [Loi] Khong tim thay du cac file models tai: {self.models_dir}")
            print("  -> Vui long chay huan luyen truoc: python ml_engine/train.py")
            sys.exit(1)

        # Nạp scaler / preprocessor
        preprocessor_path = os.path.join(self.models_dir, "preprocessor.joblib")
        if os.path.exists(preprocessor_path):
            self.preprocessor = EdgeTrafficPreprocessor.load(preprocessor_path)
        else:
            raw_scaler = joblib.load(scaler_path)
            if isinstance(raw_scaler, (TrafficFeaturePreprocessor, EdgeTrafficPreprocessor)):
                self.preprocessor = raw_scaler
            else:
                self.preprocessor = TrafficFeaturePreprocessor(scaler=raw_scaler)

        self.anomaly_detector = joblib.load(iso_path)
        self.classifier = joblib.load(clf_path)

        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                print(f"[InferenceEngine] Canh bao doc metadata: {e}")

        clf_type = self.metadata.get("classifier_type", type(self.classifier).__name__)
        det_type = self.metadata.get("anomaly_detector_type", type(self.anomaly_detector).__name__)
        print(f"[InferenceEngine] Da load thanh cong: [{clf_type}] + [{det_type}]!")

    def predict(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dự đoán trạng thái an toàn / bất thường từ gói dữ liệu telemetry.

        Parameters:
        -----------
        telemetry : dict
            Dữ liệu gói tin mạng với các chỉ số trích xuất.

        Returns:
        --------
        dict:
            Chi tiết kết quả suy luận kèm nhãn tấn công và độ trễ tính toán.
        """
        start_time = time.perf_counter()

        # 1. Trích xuất đặc trưng
        try:
            raw_features = self.preprocessor.extract_features(telemetry)
        except Exception as e:
            return {
                "error": f"Invalid telemetry format: {e}",
                "raw_telemetry": telemetry
            }

        # 2. Suy luận Anomaly Detector (Tầng 1)
        scaled_features = self.preprocessor.transform(raw_features)
        
        # Lấy hàm score_samples
        if hasattr(self.anomaly_detector, "score_samples"):
            score_sample = float(self.anomaly_detector.score_samples(scaled_features)[0])
        elif hasattr(self.anomaly_detector, "underlying_estimator") and hasattr(self.anomaly_detector.underlying_estimator, "score_samples"):
            score_sample = float(self.anomaly_detector.underlying_estimator.score_samples(scaled_features)[0])
        else:
            score_sample = 0.0

        # Chuẩn hóa anomaly score trong khoảng [0.0, 1.0] (Càng cao càng nguy hiểm)
        score_min = self.metadata.get("isolation_score_min", -0.75)
        score_max = self.metadata.get("isolation_score_max", -0.35)
        if score_max == score_min:
            score_max = score_min + 1.0

        normalized_score = 1.0 - (score_sample - score_min) / (score_max - score_min + 1e-8)
        normalized_score = float(np.clip(normalized_score, 0.0, 1.0))

        # 3. Phân loại dạng tấn công (Tầng 2)
        if hasattr(self.classifier, "predict_proba"):
            proba = self.classifier.predict_proba(scaled_features)[0]
            class_idx = int(np.argmax(proba))
            confidence = float(proba[class_idx])
        else:
            class_idx = int(self.classifier.predict(scaled_features)[0])
            confidence = 1.0

        labels_list = self.metadata.get("labels", LABEL_NAMES)
        attack_type = labels_list[class_idx] if 0 <= class_idx < len(labels_list) else f"Class_{class_idx}"

        # 4. Tính toán phân phối xác suất cho tất cả các lớp
        class_probabilities = {}
        top_probabilities = {}
        if hasattr(self.classifier, "predict_proba") and proba is not None:
            for idx, p in enumerate(proba):
                label_name = labels_list[idx] if idx < len(labels_list) else f"Class_{idx}"
                class_probabilities[label_name] = round(float(p), 4)
            # Lấy Top 5 xác suất cao nhất
            sorted_probs = sorted(class_probabilities.items(), key=lambda item: item[1], reverse=True)[:5]
            top_probabilities = {k: round(v * 100, 1) for k, v in sorted_probs}
        else:
            top_probabilities = {attack_type: 100.0}

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

        edge_pred = telemetry.get("edge_prediction", "Normal")
        edge_flag = bool(telemetry.get("edge_flag", False))

        return {
            "device_id": telemetry.get("device_id", "unknown-probe"),
            "timestamp": telemetry.get("timestamp", int(time.time() * 1000)),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(normalized_score, 4),
            "severity": severity,
            "threat_type": attack_type,
            "confidence": round(confidence, 4),
            "latency_ms": round(latency_ms, 2),
            "class_probabilities": class_probabilities,
            "top_probabilities": top_probabilities,
            "edge_prediction": edge_pred,
            "edge_flag": edge_flag,
            "raw_telemetry": telemetry
        }


def start_mqtt_inference_service(
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    threshold: float = DEFAULT_ANOMALY_THRESHOLD,
    models_dir: Optional[str] = None
):
    """Khởi động MQTT listener và xử lý suy luận thời gian thực."""
    engine = AnomalyInferenceEngine(models_dir=models_dir, anomaly_threshold=threshold)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="EdgeAI-Host-Inference-Engine")

    def on_connect(c, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[InferenceService] Da ket noi den MQTT Broker {broker_host}:{broker_port}")
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

            top_items = list(result.get("top_probabilities", {}).items())[:3]
            top_str = ", ".join([f"{k}: {v:.1f}%" for k, v in top_items])
            edge_info = f" | Edge TinyML: {result.get('edge_prediction', 'Normal')}"

            # Nếu phát hiện bất thường nghiêm trọng, bắn cảnh báo
            if result.get("is_anomaly", False):
                client.publish("edge/alerts/high_priority", res_json)
                print(f" [!!! ALERT - {result['severity']} !!!] Host: {result['threat_type']} ({result['confidence']*100:.1f}%){edge_info} "
                      f"[Score: {result['anomaly_score']:.2f} | Latency: {result['latency_ms']}ms]")
                if top_str:
                    print(f"      └─ Top Probs: [{top_str}]")
            else:
                print(f" [OK] Host: Normal ({result['confidence']*100:.1f}%){edge_info} (Score: {result['anomaly_score']:.2f}) [Latency: {result['latency_ms']}ms]")
                if top_str:
                    print(f"      └─ Top Probs: [{top_str}]")

        except Exception as e:
            print(f"[InferenceService] Loi xu ly packet: {e}")

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(broker_host, broker_port, keepalive=60)
        print("=" * 60)
        print("  EDGE AI REAL-TIME INFERENCE SERVICE DANG CHAY...")
        print(f"  - Broker: {broker_host}:{broker_port}")
        print(f"  - Nguong canh bao Anomaly: {threshold}")
        print("=" * 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[InferenceService] Dang dung dich vu...")
    finally:
        client.disconnect()


def main():
    parser = argparse.ArgumentParser(description="Edge AI Real-time Anomaly Inference Service")
    parser.add_argument("--broker", default="127.0.0.1", help="MQTT Broker IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT Broker Port (default: 1883)")
    parser.add_argument("--threshold", type=float, default=DEFAULT_ANOMALY_THRESHOLD, help="Anomaly Score Threshold (default: 0.55)")
    parser.add_argument("--models-dir", default=None, help="Thu muc chua cac file mo hinh .joblib")
    args = parser.parse_args()

    start_mqtt_inference_service(
        broker_host=args.broker,
        broker_port=args.port,
        threshold=args.threshold,
        models_dir=args.models_dir
    )


if __name__ == "__main__":
    main()
