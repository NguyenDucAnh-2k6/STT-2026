"""
UDP Transport Sub-Preprocessor
==============================
Quản lý các đặc trưng của giao thức UDP:
- udp.port: Cổng dịch vụ UDP thực tế
- udp.stream: Định danh luồng gói tin UDP
- udp.time_delta: Khoảng thời gian giữa 2 gói tin liên tiếp trong luồng
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
from .base import BaseSubPreprocessor, numeric_series

UDP_FEATURES: List[str] = [
    "udp.port",
    "udp.stream",
    "udp.time_delta"
]


class UDPTransportPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng tầng UDP dựa trên lưu lượng thực tế."""

    def __init__(self):
        super().__init__(feature_names=UDP_FEATURES)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                out[col] = numeric_series(df[col]).fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Keep measured canonical values; never fabricate packet fields from windows."""
        return {feat: telemetry[feat] for feat in self.feature_names if feat in telemetry}
