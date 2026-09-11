#!/usr/bin/env python3
"""
TinyML C Header Exporter Helper Module
======================================
Chỉ dẫn module:
- Module này cung cấp hàm tiện ích export_saved_classifier_to_tinyml()
  để chuyển đổi mô hình Decision Tree đã huấn luyện (.joblib) thành mã nguồn C Header
  cho firmware vi điều khiển ESP32 / ESP32-S3.
- ENTRYPOINT DÒNG LỆNH (CLI) DUY NHẤT cho huấn luyện và xuất TinyML là:
      python ml_engine/train.py
      python ml_engine/train.py --export-tinyml-only
"""

import os
import sys
from typing import Optional
import joblib

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml_engine.config.schema import FEATURE_NAMES, LABEL_NAMES
from ml_engine.exporter.tinyml_exporter import export_decision_tree_to_header


def export_saved_classifier_to_tinyml(
    model_path: Optional[str] = None,
    out_path: Optional[str] = None,
    esp_path: Optional[str] = None
) -> bool:
    """
    Xuất mô hình Decision Tree đã lưu (.joblib) ra C Header cho ESP32.
    """
    root_dir = ROOT_DIR
    if model_path is None:
        model_path = os.path.join(root_dir, "ml_engine", "models", "attack_classifier.joblib")
    if out_path is None:
        out_path = os.path.join(root_dir, "ml_engine", "models", "tinyml_model.h")
    if esp_path is None:
        esp_path = os.path.join(root_dir, "firmware", "esp32_probe", "tinyml_model.h")

    if not os.path.exists(model_path):
        print(f"[ExportTinyML] [Lỗi] Không tìm thấy model tại: {model_path}")
        print("  -> Vui lòng chạy huấn luyện trước: python ml_engine/train.py")
        return False

    classifier = joblib.load(model_path)

    # Kiểm tra xem mô hình có phải dạng cây quyết định hay không
    estimator = getattr(classifier, "underlying_estimator", classifier)
    estimator = getattr(estimator, "model", estimator)
    if not hasattr(estimator, "tree_"):
        print(f"[ExportTinyML] [Cảnh báo] Model hiện tại ({type(estimator).__name__}) không phải Decision Tree.")
        print("  -> Chỉ mô hình 'decision_tree' mới hỗ trợ biên dịch trực tiếp thành if/else C Header.")
        print("  -> Để huấn luyện Decision Tree: python ml_engine/train.py --classifier decision_tree")
        return False

    export_decision_tree_to_header(estimator, out_path, FEATURE_NAMES, LABEL_NAMES)
    print(f"[ExportTinyML] Đã sinh thành công C Header tại: {out_path}")

    if os.path.exists(os.path.dirname(esp_path)):
        export_decision_tree_to_header(estimator, esp_path, FEATURE_NAMES, LABEL_NAMES)
        print(f"[ExportTinyML] Đã đồng bộ C Header sang firmware ESP32: {esp_path}")
    return True


if __name__ == "__main__":
    print("[NOTE] Entrypoint CLI chính thức cho huấn luyện & xuất TinyML là: python ml_engine/train.py")
    export_saved_classifier_to_tinyml()

