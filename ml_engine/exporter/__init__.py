"""
TinyML & TFLite Exporter Package
================================
Chỉ dẫn module:
- Cung cấp công cụ chuyển đổi mô hình Decision Tree và Deep Learning (TFLite)
  sang mã C thuần túy (.h header) và FlatBuffers (.tflite) để nhúng trực tiếp
  vào firmware ESP32 / ARM Cortex-M / Edge IoT Gateways.
"""

from .tinyml_exporter import export_decision_tree_to_header, tree_to_c_code
from .tflite_exporter import (
    convert_keras_to_tflite,
    create_keras_autoencoder,
    create_keras_classifier,
    export_tinyml_suite
)

__all__ = [
    "export_decision_tree_to_header",
    "tree_to_c_code",
    "convert_keras_to_tflite",
    "create_keras_autoencoder",
    "create_keras_classifier",
    "export_tinyml_suite"
]
