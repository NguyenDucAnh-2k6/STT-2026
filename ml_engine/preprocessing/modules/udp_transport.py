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
from .base import BaseSubPreprocessor

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
                out[col] = pd.to_numeric(df[col], errors="coerce").fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        res = {}
        for feat in self.feature_names:
            if feat in telemetry:
                try:
                    res[feat] = float(telemetry[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)
            else:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        proto = str(telemetry.get("protocol", "")).upper()
        udp_r = float(telemetry.get("udp_ratio", 0.0))

        if udp_r > 0.4 or "UDP" in proto:
            # Port đích thực tế của UDP
            dst_p = float(telemetry.get("dst_port", 0.0))
            if dst_p > 0:
                res["udp.port"] = dst_p

            # Tốc độ hoặc time delta thực tế
            pkt_rate = float(telemetry.get("packet_rate", 0.0))
            if pkt_rate > 0:
                res["udp.stream"] = pkt_rate
                res["udp.time_delta"] = 1.0 / pkt_rate

        return res
