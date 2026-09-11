"""
Network Traffic Feature Preprocessor
====================================
Chỉ dẫn module:
- Module này quản lý toàn bộ quy trình tiền xử lý đặc trưng lưu lượng mạng:
  1. Trích xuất an toàn vector đặc trưng (Feature Vector) từ gói tin Telemetry dạng JSON/dict.
  2. Chuẩn hóa đặc trưng (StandardScaler) cho các mô hình nhạy cảm với khoảng giá trị.
  3. Quản lý việc lưu trữ (save) và nạp (load) scaler/preprocessor weights bằng Joblib.
- Tự động tương thích với bộ đặc trưng đầy đủ 61 chiều (Edge-IIoTset) và bộ thu gọn 8 chiều.
"""

import os
from typing import Dict, Any, Tuple, Optional, Union, List
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

from ..config.schema import (
    FEATURE_NAMES,
    EDGE_IIOTSET_FEATURES,
    SLIDING_WINDOW_FEATURES,
    TelemetryPayload
)
from .edge_iiotset_preprocessor import EdgeTrafficPreprocessor


class TrafficFeaturePreprocessor:
    """
    Bộ tiền xử lý và chuẩn hóa đặc trưng lưu lượng mạng tương thích ngược và tiến.
    """

    def __init__(
        self,
        scaler: Optional[StandardScaler] = None,
        feature_names: Optional[List[str]] = None,
        edge_preprocessor: Optional[EdgeTrafficPreprocessor] = None
    ):
        self.feature_names: List[str] = feature_names if feature_names is not None else list(FEATURE_NAMES)
        self.edge_preprocessor: EdgeTrafficPreprocessor = (
            edge_preprocessor if edge_preprocessor is not None
            else EdgeTrafficPreprocessor(feature_names=self.feature_names, scaler=scaler)
        )
        self.scaler: StandardScaler = self.edge_preprocessor.scaler
        self.is_fitted: bool = self.edge_preprocessor.is_fitted

    def extract_features(self, telemetry: Union[Dict[str, Any], TelemetryPayload]) -> np.ndarray:
        """
        Trích xuất vector đặc trưng từ dictionary telemetry.
        Tự động gán giá trị mặc định 0.0 an toàn nếu thiếu trường thông tin.
        """
        if self.edge_preprocessor is not None and self.edge_preprocessor.is_fitted:
            return self.edge_preprocessor.extract_features(telemetry)
        
        # Fallback vector nếu chưa fit edge_preprocessor
        vector = [
            float(telemetry.get(feat, 0.0)) for feat in self.feature_names
        ]
        return np.array([vector], dtype=np.float32)

    def fit(self, X: Union[np.ndarray, pd.DataFrame], y: Optional[Any] = None) -> "TrafficFeaturePreprocessor":
        """Học các thông số chuẩn hóa từ tập huấn luyện."""
        if isinstance(X, pd.DataFrame):
            self.edge_preprocessor.fit(X, y)
            self.scaler = self.edge_preprocessor.scaler
            self.is_fitted = self.edge_preprocessor.is_fitted
        else:
            self.scaler.fit(X)
            self.is_fitted = True
            self.edge_preprocessor.scaler = self.scaler
            self.edge_preprocessor.is_fitted = True
        return self

    def transform(self, X: Union[np.ndarray, pd.DataFrame]) -> np.ndarray:
        """Chuẩn hóa ma trận đặc trưng theo phân phối z-score."""
        if not self.is_fitted:
            raise RuntimeError("[FeaturePreprocessor] Scaler chua duoc fit! Vui long fit() truoc.")
        if isinstance(X, pd.DataFrame):
            return self.edge_preprocessor.transform(X)
        return self.scaler.transform(X)

    def fit_transform(self, X: Union[np.ndarray, pd.DataFrame], y: Optional[Any] = None) -> np.ndarray:
        """Vừa học vừa chuẩn hóa tập dữ liệu đầu vào."""
        if isinstance(X, pd.DataFrame):
            X_t, _ = self.edge_preprocessor.fit_transform(X, y)
            self.scaler = self.edge_preprocessor.scaler
            self.is_fitted = True
            return X_t
        transformed = self.scaler.fit_transform(X)
        self.is_fitted = True
        self.edge_preprocessor.scaler = self.scaler
        self.edge_preprocessor.is_fitted = True
        return transformed

    def save(self, file_path: str) -> str:
        """Lưu scaler và preprocessor xuống đĩa bằng Joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        return self.edge_preprocessor.save(file_path)

    @classmethod
    def load(cls, file_path: str) -> "TrafficFeaturePreprocessor":
        """Tải scaler và preprocessor đã lưu từ đĩa."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[FeaturePreprocessor] Khong tim thay file scaler tai: {file_path}")
        edge_prep = EdgeTrafficPreprocessor.load(file_path)
        instance = cls(edge_preprocessor=edge_prep, scaler=edge_prep.scaler, feature_names=edge_prep.feature_names)
        instance.is_fitted = edge_prep.is_fitted
        return instance
