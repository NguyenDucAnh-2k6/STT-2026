"""
Preprocessing and Feature Engineering Package
==============================================
Chỉ dẫn module:
- Cung cấp công cụ sinh tập dữ liệu mạng mô phỏng (Dataset Generator).
- Cung cấp bộ chuẩn hóa và trích xuất vector đặc trưng từ gói telemetry (Feature Preprocessor).
"""

from .dataset_generator import (
    generate_synthetic_dataset,
    save_synthetic_dataset
)
from .feature_preprocessor import (
    TrafficFeaturePreprocessor
)

__all__ = [
    "generate_synthetic_dataset",
    "save_synthetic_dataset",
    "TrafficFeaturePreprocessor"
]
