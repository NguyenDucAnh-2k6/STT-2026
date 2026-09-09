#!/usr/bin/env python3
"""
TinyML C Header Exporter CLI
=============================
Chỉ dẫn module:
- Script này xuất mô hình phân loại (Decision Tree) đã huấn luyện ra mã nguồn C Header
  cho firmware vi điều khiển ESP32 / ESP32-S3.
- Cú pháp sử dụng:
    python ml_engine/export_tinyml.py
    python ml_engine/export_tinyml.py --model ml_engine/models/attack_classifier.joblib
"""

import os
import sys
import argparse

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path khi gọi trực tiếp
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import joblib

from ml_engine.config.schema import FEATURE_NAMES, LABEL_NAMES
from ml_engine.exporter.tinyml_exporter import export_decision_tree_to_header


def main():
    parser = argparse.ArgumentParser(description="Export Trained Decision Tree to C Header for ESP32 TinyML")
    parser.add_argument(
        "--model",
        default="ml_engine/models/attack_classifier.joblib",
        help="Duong dan den file model classifier (.joblib)"
    )
    parser.add_argument(
        "--out",
        default="ml_engine/models/tinyml_model.h",
        help="Duong dan file .h xuat ra"
    )
    parser.add_argument(
        "--esp-out",
        default="firmware/esp32_probe/tinyml_model.h",
        help="Duong dan copy sang thu muc firmware ESP32 (neu co)"
    )
    args = parser.parse_args()

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(root_dir, args.model) if not os.path.isabs(args.model) else args.model
    out_path = os.path.join(root_dir, args.out) if not os.path.isabs(args.out) else args.out
    esp_path = os.path.join(root_dir, args.esp_out) if not os.path.isabs(args.esp_out) else args.esp_out

    if not os.path.exists(model_path):
        print(f"[ExportTinyML] [Loi] Khong tim thay model tai: {model_path}")
        print("  -> Vui long chay: python ml_engine/train.py truoc.")
        sys.exit(1)

    classifier = joblib.load(model_path)
    
    # Kiểm tra xem mô hình có phải dạng cây quyết định hay không
    estimator = getattr(classifier, "underlying_estimator", classifier)
    estimator = getattr(estimator, "model", estimator)
    if not hasattr(estimator, "tree_"):
        print(f"[ExportTinyML] [Canh bao] Model hien tai ({type(estimator).__name__}) khong phai Decision Tree.")
        print("  -> Chi mo hinh 'decision_tree' moi ho tro bien dich truc tiep thanh if/else C Header.")
        print("  -> De huan luyen Decision Tree: python ml_engine/train.py --classifier decision_tree")
        sys.exit(0)

    export_decision_tree_to_header(estimator, out_path, FEATURE_NAMES, LABEL_NAMES)
    print(f"[ExportTinyML] Da sinh thanh cong C Header tai: {out_path}")

    if os.path.exists(os.path.dirname(esp_path)):
        export_decision_tree_to_header(estimator, esp_path, FEATURE_NAMES, LABEL_NAMES)
        print(f"[ExportTinyML] Da dong bo C Header sang firmware ESP32: {esp_path}")


if __name__ == "__main__":
    main()
