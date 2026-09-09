"""
Network Traffic Feature Preprocessor
====================================
Chỉ dẫn module:
- Module này quản lý toàn bộ quy trình tiền xử lý đặc trưng lưu lượng mạng:
  1. Trích xuất an toàn vector đặc trưng (Feature Vector) từ gói tin Telemetry dạng JSON/dict.
  2. Chuẩn hóa đặc trưng (StandardScaler) cho các mô hình nhạy cảm với khoảng giá trị (Isolation Forest, SVM, MLP).
  3. Quản lý việc lưu trữ (save) và nạp (load) scaler weights bằng Joblib.
- Đảm bảo độ trễ trích xuất siêu thấp (< 0.1ms) để đáp ứng thời gian thực cho thiết bị biên.
"""

import os
from typing import Dict, Any, Tuple, Optional, Union
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

from ..config.schema import FEATURE_NAMES, TelemetryPayload


class TrafficFeaturePreprocessor:
    """
    Bộ tiền xử lý và chuẩn hóa đặc trưng lưu lượng mạng.
    """

    def __init__(self, scaler: Optional[StandardScaler] = None):
        self.scaler: StandardScaler = scaler if scaler is not None else StandardScaler()
        self.is_fitted: bool = hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None

    def extract_features(self, telemetry: Union[Dict[str, Any], TelemetryPayload]) -> np.ndarray:
        """
        Trích xuất vector 8 chiều từ dictionary telemetry.
        Tự động gán giá trị mặc định 0.0 an toàn nếu thiếu trường thông tin.

        Parameters:
        -----------
        telemetry : dict
            Dữ liệu gói tin telemetry từ ESP32 probe hoặc Simulator.

        Returns:
        --------
        np.ndarray:
            Ma trận hình dạng (1, 8) với kiểu float32.
        """
        vector = [
            float(telemetry.get(feat, 0.0)) for feat in FEATURE_NAMES
        ]
        return np.array([vector], dtype=np.float32)

    def fit(self, X: np.ndarray) -> "TrafficFeaturePreprocessor":
        """
        Học các thông số trung bình (mean) và phương sai (variance) từ tập huấn luyện.
        """
        self.scaler.fit(X)
        self.is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Chuẩn hóa ma trận đặc trưng theo phân phối z-score: (x - u) / s.
        """
        if not self.is_fitted:
            raise RuntimeError("[FeaturePreprocessor] Scaler chua duoc fit! Vui long fit() truoc.")
        return self.scaler.transform(X)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """
        Vừa học vừa chuẩn hóa tập dữ liệu đầu vào.
        """
        transformed = self.scaler.fit_transform(X)
        self.is_fitted = True
        return transformed

    def save(self, file_path: str) -> str:
        """
        Lưu scaler xuống đĩa bằng Joblib.
        """
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        joblib.dump(self.scaler, file_path)
        return os.path.abspath(file_path)

    @classmethod
    def load(cls, file_path: str) -> "TrafficFeaturePreprocessor":
        """
        Tải scaler đã lưu từ đĩa.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[FeaturePreprocessor] Khong tim thay file scaler tai: {file_path}")
        scaler = joblib.load(file_path)
        instance = cls(scaler=scaler)
        instance.is_fitted = True
        return instance
