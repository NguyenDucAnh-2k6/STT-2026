"""
Machine Learning Algorithms Package
===================================
Chỉ dẫn module:
- Cung cấp kiến trúc module hóa cho các mô hình học máy:
  1. Classifiers (Phân loại dạng tấn công):
     - Decision Tree (Hỗ trợ xuất TinyML C code)
     - Random Forest
     - Extra Trees
     - Gradient Boosting / HistGradientBoosting
     - Multi-Layer Perceptron (MLP / Neural Network)
     - Logistic Regression
  2. Anomaly Detectors (Nhận diện bất thường không giám sát / novelty):
     - Isolation Forest
     - One-Class SVM
     - Elliptic Envelope (Robust Covariance)
     - Local Outlier Factor (Novelty Detection)
- Factory Functions:
  - `get_classifier(name, **kwargs)`
  - `get_anomaly_detector(name, **kwargs)`
"""

from .base import BaseAnomalyDetector, BaseAttackClassifier
from .classifiers import (
    SUPPORTED_CLASSIFIERS,
    get_classifier,
    list_supported_classifiers
)
from .anomaly_detectors import (
    SUPPORTED_ANOMALY_DETECTORS,
    get_anomaly_detector,
    list_supported_anomaly_detectors
)

__all__ = [
    "BaseAnomalyDetector",
    "BaseAttackClassifier",
    "SUPPORTED_CLASSIFIERS",
    "SUPPORTED_ANOMALY_DETECTORS",
    "get_classifier",
    "get_anomaly_detector",
    "list_supported_classifiers",
    "list_supported_anomaly_detectors"
]
