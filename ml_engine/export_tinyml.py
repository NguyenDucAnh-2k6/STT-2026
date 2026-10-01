#!/usr/bin/env python3
"""
TinyML & TFLite C Header Exporter Helper Module
===============================================
Chỉ dẫn module:
- Cung cấp hàm tiện ích export_saved_models_to_tinyml():
  1. Hỗ trợ mô hình Decision Tree (chuyển đổi sang C if/else header).
  2. Hỗ trợ mô hình Deep Learning (DNN & Autoencoder chuyển đổi sang TensorFlow Lite .tflite và C byte array).
- Tự động đồng bộ file tinyml_model.h sang thư mục firmware/esp32_probe/ để nạp trực tiếp lên ESP32.
"""

import os
import sys
from typing import Optional
import joblib

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml_engine.config.schema import FEATURE_NAMES, LABEL_NAMES
from ml_engine.exporter.tinyml_exporter import export_decision_tree_to_header
from ml_engine.exporter.tflite_exporter import export_tinyml_suite


def export_saved_models_to_tinyml(
    models_dir: Optional[str] = None,
    esp_dir: Optional[str] = None
) -> bool:
    """
    Xuất mô hình đã lưu (.joblib) ra C Header và TFLite cho ESP-32.
    """
    root_dir = ROOT_DIR
    if models_dir is None:
        models_dir = os.path.join(root_dir, "ml_engine", "models")
    if esp_dir is None:
        esp_dir = os.path.join(root_dir, "firmware", "esp32_probe")

    clf_path = os.path.join(models_dir, "attack_classifier.joblib")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    prep_path = os.path.join(models_dir, "preprocessor.joblib")

    if not os.path.exists(clf_path):
        print(f"[ExportTinyML] [Lỗi] Không tìm thấy classifier tại: {clf_path}")
        print("  -> Vui lòng chạy huấn luyện trước: python ml_engine/train.py")
        return False

    classifier = joblib.load(clf_path)
    anomaly_model = joblib.load(iso_path) if os.path.exists(iso_path) else None
    preprocessor = joblib.load(prep_path) if os.path.exists(prep_path) else None

    # Kiểm tra loại mô hình
    estimator = getattr(classifier, "underlying_estimator", classifier)
    estimator = getattr(estimator, "model", estimator)

    # 1. Nếu là Decision Tree thuần
    if hasattr(estimator, "tree_"):
        out_path = os.path.join(models_dir, "tinyml_model.h")
        esp_path = os.path.join(esp_dir, "tinyml_model.h")
        export_decision_tree_to_header(estimator, out_path, FEATURE_NAMES, LABEL_NAMES)
        print(f"[ExportTinyML] Đã xuất Decision Tree C Header tại: {out_path}")
        if os.path.exists(esp_dir):
            export_decision_tree_to_header(estimator, esp_path, FEATURE_NAMES, LABEL_NAMES)
            print(f"[ExportTinyML] Đã đồng bộ sang firmware ESP32: {esp_path}")
        return True

    # 2. Nếu là mô hình Deep Learning (DNN / Autoencoder / TFLite)
    print(f"[ExportTinyML] Xuất giải pháp TinyML Deep Learning (TFLite) cho ESP-32...")
    export_tinyml_suite(
        anomaly_model=anomaly_model,
        classifier_model=classifier,
        preprocessor=preprocessor,
        output_dir=models_dir,
        esp_firmware_dir=esp_dir,
        label_names=LABEL_NAMES
    )
    return True


if __name__ == "__main__":
    print("[NOTE] Entrypoint CLI chính thức cho huấn luyện & xuất TinyML là: python ml_engine/train.py")
    export_saved_models_to_tinyml()
