"""
TinyML Exporter Package
=======================
Chỉ dẫn module:
- Cung cấp công cụ chuyển đổi mô hình Decision Tree sang mã C thuần túy (.h header)
  để nhúng trực tiếp vào firmware ESP32 / ARM Cortex-M / Edge IoT Gateways.
"""

from .tinyml_exporter import export_decision_tree_to_header, tree_to_c_code

__all__ = [
    "export_decision_tree_to_header",
    "tree_to_c_code"
]
