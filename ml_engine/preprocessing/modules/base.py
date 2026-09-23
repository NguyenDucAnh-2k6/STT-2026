"""
Base Sub-Preprocessor Interface
================================
Định nghĩa giao diện chuẩn (Base Interface) cho từng module con tiền xử lý đặc trưng mạng.
Mỗi module quản lý độc lập một nhóm đặc trưng theo tầng giao thức hoặc miền logic.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd


class BaseSubPreprocessor(ABC):
    """Lớp cơ sở trừu tượng cho các module con tiền xử lý đặc trưng mạng."""

    def __init__(self, feature_names: List[str], cat_cols: Optional[List[str]] = None):
        self.feature_names: List[str] = list(feature_names)
        self.cat_cols: List[str] = list(cat_cols) if cat_cols else []
        self.learned_baselines_: Dict[str, float] = {}
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame) -> "BaseSubPreprocessor":
        """
        Học phân phối thống kê thực nghiệm (Empirical Distribution) từ dữ liệu thực tế:
        - Giá trị median cho đặc trưng liên tục (tránh ảnh hưởng bởi ngoại lai cực đoan).
        - Giá trị mode cho đặc trưng phân loại / cờ giao thức.
        """
        for feat in self.feature_names:
            if feat in df.columns:
                series = df[feat]
                if feat in self.cat_cols or series.dtype == "object":
                    mode_val = series.mode()
                    val = mode_val.iloc[0] if not mode_val.empty else 0.0
                    try:
                        self.learned_baselines_[feat] = float(val)
                    except (ValueError, TypeError):
                        self.learned_baselines_[feat] = 0.0
                else:
                    num_series = pd.to_numeric(series, errors="coerce")
                    med = num_series.median()
                    self.learned_baselines_[feat] = float(med) if pd.notnull(med) else 0.0
            else:
                self.learned_baselines_[feat] = 0.0

        self._fit_internal(df)
        self.is_fitted = True
        return self

    def _fit_internal(self, df: pd.DataFrame):
        """Hook mở rộng cho các bước fit chuyên biệt trong từng module con."""
        pass

    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Làm sạch và mã hóa các cột đặc trưng thuộc phạm vi quản lý của module."""
        pass

    @abstractmethod
    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        """
        Trích xuất các trường đặc trưng từ telemetry thời gian thực.
        Tuyệt đối không dùng số cứng (hardcoded magic numbers).
        Nếu telemetry không có trường này, sử dụng giá trị baseline thực nghiệm đã học từ fit().
        """
        pass
