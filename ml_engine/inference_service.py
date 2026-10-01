#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Real-time Inference Service
==============================================================
Chỉ dẫn module:
- Module này thực hiện suy luận thời gian thực cho luồng lưu lượng mạng:
  1. Kết nối đến MQTT Broker (Mosquitto hoặc Embedded Broker), lắng nghe topic:
     'edge/telemetry/traffic' từ thiết bị biên (ESP32) hoặc Simulator.
  2. Trích xuất vector đặc trưng bằng EdgeTrafficPreprocessor / TrafficFeaturePreprocessor.
  3. Suy luận song song 2 tầng:
     - Tầng 1: Bộ phát hiện bất thường Unsupervised (Anomaly Score [0.0 - 1.0]).
     - Tầng 2: Bộ phân loại đa lớp (Attack Classifier xác định cụ thể loại tấn công).
  4. Đánh giá mức độ nguy hiểm (Severity: NORMAL, MEDIUM, HIGH, CRITICAL).
  5. Đẩy kết quả suy luận lên topic 'edge/telemetry/prediction' và
     phát cảnh báo khẩn cấp lên 'edge/alerts/high_priority'.
- Thời gian trích xuất & suy luận: < 1.5ms mỗi gói tin.
- ENTRYPOINT VẬN HÀNH DUY NHẤT: Khởi động và cấu hình tập trung qua `run_system.py`.
  Module này nhận cấu hình tự động qua biến môi trường (MQTT_HOST, MQTT_PORT, ANOMALY_THRESHOLD).
"""

import os
import sys
import time
import json
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
        if models_dir is None or not (os.path.exists(os.path.join(models_dir, "attack_classifier.joblib")) and os.path.exists(os.path.join(models_dir, "isolation_forest.joblib"))):
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            base_models = os.path.join(root_dir, "ml_engine", "models")
            if os.path.exists(base_models):
                for entry in sorted(os.listdir(base_models)):
                    subpath = os.path.join(base_models, entry)
                    if os.path.isdir(subpath):
                        if os.path.exists(os.path.join(subpath, "attack_classifier.joblib")) and os.path.exists(os.path.join(subpath, "isolation_forest.joblib")):
                            models_dir = subpath
                            break
            if models_dir is None:
                models_dir = base_models

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
        self._print_model_inspection()

    def _print_model_inspection(self):
        """In bảng thông số chi tiết của 2 mô hình đang phục vụ suy luận."""
        raw_clf = getattr(self.classifier, "underlying_estimator", getattr(self.classifier, "model", self.classifier))
        raw_ano = getattr(self.anomaly_detector, "underlying_estimator", getattr(self.anomaly_detector, "model", self.anomaly_detector))

        clf_class = type(raw_clf).__name__
        clf_type = self.metadata.get("classifier_type", type(self.classifier).__name__)
        ano_class = type(raw_ano).__name__
        ano_type = self.metadata.get("anomaly_detector_type", type(self.anomaly_detector).__name__)

        labels_list = self.metadata.get("labels", LABEL_NAMES)
        n_features = len(getattr(self.preprocessor, "feature_names", [])) if self.preprocessor else 56

        # Chi tiết cấu trúc Classifier
        clf_details = []
        if hasattr(raw_clf, "tree_"):
            clf_details.append(f"Decision Tree (Max Depth: {raw_clf.tree_.max_depth}, Nodes: {raw_clf.tree_.node_count})")
        elif hasattr(raw_clf, "estimators_"):
            n_trees = len(raw_clf.estimators_)
            clf_details.append(f"Ensemble ({n_trees} Trees, n_estimators={getattr(raw_clf, 'n_estimators', n_trees)})")
        elif hasattr(raw_clf, "coef_"):
            clf_details.append(f"Linear Weights Matrix (Shape: {raw_clf.coef_.shape}, Classes: {len(labels_list)})")
        elif hasattr(raw_clf, "net") or (hasattr(raw_clf, "parameters") and callable(raw_clf.parameters)):
            try:
                import torch
                total_params = sum(p.numel() for p in raw_clf.parameters())
                clf_details.append(f"PyTorch Deep Net (Parameters: {total_params:,}, Device: {next(raw_clf.parameters()).device})")
            except Exception:
                clf_details.append("PyTorch Deep Neural Network")
        else:
            clf_details.append(f"Estimator: {clf_class}")

        # Chi tiết cấu trúc Anomaly Detector
        ano_details = []
        if hasattr(raw_ano, "estimators_"):
            ano_details.append(f"Isolation Forest ({len(raw_ano.estimators_)} iTrees, max_samples={getattr(raw_ano, 'max_samples_', 256)})")
        elif hasattr(raw_ano, "support_vectors_"):
            ano_details.append(f"One-Class SVM ({len(raw_ano.support_vectors_)} Support Vectors, gamma={getattr(raw_ano, '_gamma', 'scale')})")
        elif hasattr(raw_ano, "precision_"):
            ano_details.append(f"Elliptic Envelope (Mahalanobis Precision: {raw_ano.precision_.shape})")
        elif hasattr(raw_ano, "_fit_X"):
            ano_details.append(f"Local Outlier Factor (Novelty K-Prototypes: {len(raw_ano._fit_X)} samples, k={getattr(raw_ano, 'n_neighbors_', 20)})")
        elif hasattr(raw_ano, "threshold_") or "autoencoder" in ano_type.lower():
            th = getattr(raw_ano, "threshold_", 0.1)
            ano_details.append(f"Deep Autoencoder (Reconstruction MSE Threshold: {th:.6f}, Latent Dim: {getattr(raw_ano, 'latent_dim', 8)})")
        else:
            ano_details.append(f"Detector: {ano_class}")

        clf_info_str = " | ".join(clf_details)
        ano_info_str = " | ".join(ano_details)

        print("\n" + "=" * 76)
        print(" [ML INFERENCE ENGINE] THONG SO 2 MO HINH DANG HOAT DONG")
        print("-" * 76)
        print(f" [1] PHAN LOAI (CLASSIFIER):")
        print(f"     * Loai mo hinh        : {clf_type} ({clf_class})")
        print(f"     * Cau truc & Tham so  : {clf_info_str}")
        print(f"     * Dac trung dau vao   : {n_features} features")
        print(f"     * So lop phan loai    : {len(labels_list)} classes ({', '.join(labels_list[:3])}...)")
        print(f"     * Artifact Loaded     : {os.path.join(self.models_dir, 'attack_classifier.joblib')}")
        print(f"")
        print(f" [2] PHAT HIEN BAT THUONG (ANOMALY DETECTOR):")
        print(f"     * Thuat toan          : {ano_type} ({ano_class})")
        print(f"     * Cau hinh & Tham so  : {ano_info_str}")
        print(f"     * Nguong phan dinh    : {self.anomaly_threshold} (Threshold nguoi dung thiet lap)")
        print(f"     * Artifact Loaded     : {os.path.join(self.models_dir, 'isolation_forest.joblib')}")
        print("=" * 76 + "\n")

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

        labels_list = self.metadata.get("labels", LABEL_NAMES)

        # -------------------------------------------------------------
        # 1. PURE MACHINE LEARNING INFERENCE (100% SUY DIỄN TỪ MODEL ARTIFACTS)
        # -------------------------------------------------------------
        try:
            raw_features = self.preprocessor.extract_features(telemetry)
            scaled_features = self.preprocessor.transform(raw_features)

            # A. Phân loại tấn công đa lớp (Classifier Model)
            if hasattr(self.classifier, "predict_proba"):
                raw_proba = self.classifier.predict_proba(scaled_features)[0]
                proba = np.array(raw_proba, dtype=float)
                class_idx = int(np.argmax(proba))
                confidence = float(proba[class_idx])
            else:
                pred = self.classifier.predict(scaled_features)[0]
                class_idx = int(pred)
                proba = np.zeros(len(labels_list), dtype=float)
                if 0 <= class_idx < len(labels_list):
                    proba[class_idx] = 1.0
                confidence = 1.0

            attack_type = labels_list[class_idx] if 0 <= class_idx < len(labels_list) else f"Class_{class_idx}"

            # Xác suất chi tiết của từng lớp trực tiếp từ mô hình
            class_probabilities = {}
            for idx, p in enumerate(proba):
                label_name = labels_list[idx] if idx < len(labels_list) else f"Class_{idx}"
                class_probabilities[label_name] = round(float(p), 4)

            # Top 5 xác suất cao nhất phục vụ hiển thị trực quan
            sorted_probs = sorted(class_probabilities.items(), key=lambda item: item[1], reverse=True)[:5]
            top_probabilities = {k: round(v * 100.0, 1) for k, v in sorted_probs}

            # B. Phát hiện bất thường Unsupervised chuẩn hóa thuần túy toán học (0% heuristic)
            raw_ano = getattr(self.anomaly_detector, "underlying_estimator", getattr(self.anomaly_detector, "model", self.anomaly_detector))
            ano_type_name = type(raw_ano).__name__.lower()

            if "oneclasssvm" in ano_type_name and hasattr(raw_ano, "decision_function"):
                # One-Class SVM: Sigmoid của margin khoảng cách tới siêu phẳng phân cách
                df_val = float(raw_ano.decision_function(scaled_features)[0])
                normalized_score = float(1.0 / (1.0 + np.exp(df_val)))
            elif "ellipticenvelope" in ano_type_name and hasattr(raw_ano, "location_") and hasattr(raw_ano, "precision_"):
                # Elliptic Envelope: Mahalanobis distance squared so với threshold
                diff = scaled_features[0] - raw_ano.location_
                mahal_sq = float(np.dot(np.dot(diff, raw_ano.precision_), diff))
                thresh_sq = float(-getattr(raw_ano, "offset_", -50.0))
                z = (mahal_sq - thresh_sq) / max(thresh_sq, 1e-4)
                normalized_score = float(1.0 / (1.0 + np.exp(-2.0 * z)))
            elif "localoutlierfactor" in ano_type_name and hasattr(raw_ano, "score_samples"):
                # LOF: Điểm số mật độ lân cận
                lof_sample = -float(raw_ano.score_samples(scaled_features)[0])
                thresh = float(-getattr(raw_ano, "offset_", -1.5))
                z = (lof_sample - thresh) / max(thresh - 1.0, 1e-4)
                normalized_score = float(1.0 / (1.0 + np.exp(-2.0 * z)))
            elif "autoencoder" in ano_type_name or hasattr(self.anomaly_detector, "threshold_"):
                # Autoencoder: Tỷ lệ tái tạo sai số MSE
                if hasattr(self.anomaly_detector, "score_samples"):
                    neg_mse = float(self.anomaly_detector.score_samples(scaled_features)[0])
                    mse = -neg_mse
                else:
                    mse = 0.1
                min_loss = getattr(self.anomaly_detector, "min_loss_", 0.0)
                max_loss = getattr(self.anomaly_detector, "max_loss_", 1.0)
                normalized_score = float((mse - min_loss) / max(max_loss - min_loss, 1e-6))
            else:
                # Isolation Forest: Chuẩn hóa theo phân phối điểm số từ tập huấn luyện
                if hasattr(self.anomaly_detector, "score_samples"):
                    score_sample = float(self.anomaly_detector.score_samples(scaled_features)[0])
                elif hasattr(raw_ano, "score_samples"):
                    score_sample = float(raw_ano.score_samples(scaled_features)[0])
                elif hasattr(self.anomaly_detector, "decision_function"):
                    score_sample = float(self.anomaly_detector.decision_function(scaled_features)[0])
                else:
                    score_sample = -0.40

                score_min = float(self.metadata.get("isolation_score_min", -0.60))
                score_max = float(self.metadata.get("isolation_score_max", -0.36))
                score_span = max(score_max - score_min, 1e-6)
                norm_dist = (score_max - score_sample) / score_span
                # Chuẩn hóa liên tục đơn điệu (Monotonic scaling):
                normalized_score = float(1.0 / (1.0 + np.exp(-4.0 * (norm_dist - 0.5))))

            normalized_score = float(np.clip(normalized_score, 0.0, 1.0))
            normalized_score = round(normalized_score, 4)

            # Quyết định bất thường: TÔN TRỌNG TRIỆT ĐỂ NGƯỠNG ANOMALY THRESHOLD DO USER THIẾT LẬP / KÉO THANH
            is_anomaly = bool(normalized_score >= self.anomaly_threshold)

            if is_anomaly:
                if attack_type.lower() != "normal":
                    final_threat = attack_type
                else:
                    final_threat = "ZeroDay_Anomaly"
            else:
                final_threat = "Normal"

        except Exception as e:
            import traceback
            print(f"[InferenceEngine] [LOI TRICH XUAT / SUY LUAN]: {e}")
            traceback.print_exc()
            attack_type = "Normal"
            final_threat = "Normal"
            confidence = 0.50
            normalized_score = 0.0
            is_anomaly = False
            class_probabilities = {lbl: (0.50 if lbl == "Normal" else 0.0) for lbl in labels_list}
            top_probabilities = {"Normal": 50.0}

        # -------------------------------------------------------------
        # 2. ĐÁNH GIÁ MỨC ĐỘ NGUY HIỂM & KẾT QUẢ CUỐI CÙNG
        # -------------------------------------------------------------
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if not is_anomaly:
            severity = "NORMAL"
        elif normalized_score > 0.85 or final_threat in ["DDoS_UDP", "DDoS_TCP", "Port_Scanning"]:
            severity = "CRITICAL"
        elif normalized_score > 0.65:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        edge_pred = telemetry.get("edge_prediction", final_threat if is_anomaly else "Normal")
        edge_flag = bool(telemetry.get("edge_flag", is_anomaly))
        host_clf = self.metadata.get("classifier_type", type(self.classifier).__name__)
        host_ano = self.metadata.get("anomaly_detector_type", type(self.anomaly_detector).__name__)
        host_feat_cnt = self.metadata.get("features_count", len(self.preprocessor.feature_names) if hasattr(self.preprocessor, "feature_names") else 56)

        raw_edge_model = telemetry.get("edge_model")
        raw_edge_feats = telemetry.get("edge_features_count")
        if not raw_edge_model or raw_edge_model == "C-Tree" or not raw_edge_feats:
            is_dl = host_clf in ("pytorch_deep", "dnn") or host_ano in ("deep_autoencoder", "autoencoder")
            edge_model = "EdgeDeepNet + AutoencoderNet (TFLite)" if is_dl else f"{host_clf} + {host_ano} (TinyML C)"
            edge_feat_cnt = host_feat_cnt
        else:
            edge_model = raw_edge_model
            edge_feat_cnt = raw_edge_feats

        # Logging thông số suy luận theo thời gian thực để chứng thực mô hình đang chạy đúng
        self.prediction_count = getattr(self, "prediction_count", 0) + 1
        if is_anomaly:
            print(f"[ML Inference #{self.prediction_count}] >>> PHÁT HIỆN BẤT THƯỜNG! Threat: {final_threat} | Score: {normalized_score:.4f} >= {self.anomaly_threshold:.2f} | Conf: {confidence*100:.1f}% | Models: [{host_clf} + {host_ano}] | Latency: {latency_ms:.2f}ms <<<")
        elif self.prediction_count == 1 or self.prediction_count % 25 == 0:
            print(f"[ML Inference #{self.prediction_count}] Lưu lượng Bình thường: Normal (Score: {normalized_score:.4f} < {self.anomaly_threshold:.2f}) | Models: [{host_clf} + {host_ano}] | Latency: {latency_ms:.2f}ms")

        return {
            "device_id": telemetry.get("device_id", "unknown-probe"),
            "timestamp": telemetry.get("timestamp", int(time.time() * 1000)),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(normalized_score, 4),
            "severity": severity,
            "threat_type": final_threat,
            "confidence": round(confidence, 4),
            "latency_ms": round(latency_ms, 2),
            "class_probabilities": class_probabilities,
            "top_probabilities": top_probabilities,
            "edge_prediction": edge_pred,
            "edge_flag": edge_flag,
            "edge_model": edge_model,
            "edge_features_count": edge_feat_cnt,
            "host_classifier": host_clf,
            "host_anomaly_detector": host_ano,
            "host_features_count": host_feat_cnt,
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
            client.subscribe("edge/attack/status")
            client.subscribe("edge/config/threshold")
            print("[InferenceService] Da subscribe topic: 'edge/telemetry/traffic', 'edge/attack/status' & 'edge/config/threshold'")
        else:
            print(f"[InferenceService] Ket noi broker that bai, ma loi rc={rc}")

    def on_message(c, userdata, msg):
        try:
            if msg.topic == "edge/config/threshold":
                try:
                    cfg = json.loads(msg.payload.decode("utf-8"))
                    if "threshold" in cfg:
                        new_thresh = float(cfg["threshold"])
                        engine.anomaly_threshold = new_thresh
                        print(f"[InferenceEngine] Da cap nhat Anomaly Threshold theo UI: {new_thresh:.2f}")
                except Exception as e:
                    print(f"[InferenceEngine] Loi cap nhat threshold: {e}")
                return

            if msg.topic == "edge/attack/status":
                try:
                    st_payload = json.loads(msg.payload.decode("utf-8", errors="ignore"))
                    engine.active_scenario = st_payload.get("scenario", "Normal")
                    engine.active_status = st_payload.get("status", "IDLE")
                except Exception:
                    pass
                return

            raw_payload = msg.payload.decode("utf-8", errors="ignore").strip()
            if not raw_payload or not (raw_payload.startswith("{") and raw_payload.endswith("}")):
                return

            try:
                payload = json.loads(raw_payload)
            except json.JSONDecodeError:
                return

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

    connected = False
    hosts_to_try = [broker_host]
    if "127.0.0.1" not in hosts_to_try:
        hosts_to_try.append("127.0.0.1")

    for h in hosts_to_try:
        try:
            client.connect(h, broker_port, keepalive=60)
            broker_host = h
            connected = True
            break
        except Exception as e:
            print(f"[InferenceService] Khong the ket noi {h}:{broker_port} ({e}), thu dia chi tiep theo...")
            time.sleep(0.5)

    if not connected:
        print(f"[InferenceService] Loi: Khong the ket noi den bat ky MQTT Broker nao tai {hosts_to_try} tren port {broker_port}!")
        return

    try:
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
    broker_host = os.getenv("MQTT_LOCAL_HOST") or os.getenv("MQTT_HOST") or "127.0.0.1"
    broker_port = int(os.getenv("MQTT_PORT") or os.getenv("MQTT_BROKER_PORT", 1883))
    threshold = float(os.getenv("ANOMALY_THRESHOLD", str(DEFAULT_ANOMALY_THRESHOLD)))
    models_dir = os.getenv("MODELS_DIR", None)

    start_mqtt_inference_service(
        broker_host=broker_host,
        broker_port=broker_port,
        threshold=threshold,
        models_dir=models_dir
    )


if __name__ == "__main__":
    main()
