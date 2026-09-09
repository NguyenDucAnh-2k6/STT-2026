"""
Base Machine Learning Interfaces
=================================
Chỉ dẫn module:
- Định nghĩa abstract base class / interface cho các thuật toán phân loại và phát hiện bất thường.
- Đảm bảo tất cả các mô hình mở rộng trong tương lai đều tuân thủ hợp đồng giao diện:
  + Classifier: fit(X, y), predict(X), predict_proba(X)
  + AnomalyDetector: fit(X), score_samples(X), predict(X)
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional
import numpy as np


class BaseAttackClassifier(ABC):
    """Giao diện chuẩn cho tất cả các mô hình phân loại tấn công mạng."""

    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray) -> "BaseAttackClassifier":
        """Huấn luyện mô hình phân loại đa lớp."""
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán nhãn lớp (0: Normal, 1: SYN_Flood, ...)."""
        pass

    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán phân phối xác suất trên các lớp."""
        pass

    @property
    @abstractmethod
    def can_export_tinyml(self) -> bool:
        """Cho biết mô hình có thể xuất trực tiếp sang C code cho ESP32 hay không."""
        pass


class BaseAnomalyDetector(ABC):
    """Giao diện chuẩn cho các mô hình phát hiện lưu lượng mạng bất thường."""

    @abstractmethod
    def fit(self, X_normal: np.ndarray) -> "BaseAnomalyDetector":
        """Học phân phối bình thường từ tập lưu lượng chuẩn (Normal)."""
        pass

    @abstractmethod
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Tính điểm số bất thường thô (thường điểm càng âm thì càng bất thường)."""
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán nhị phân (1: Inlier/Bình thường, -1: Outlier/Bất thường)."""
        pass
