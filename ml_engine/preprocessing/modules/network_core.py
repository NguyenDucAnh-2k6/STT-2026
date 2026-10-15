"""
Network Core Sub-Preprocessor (ARP & ICMP)
===========================================
Quản lý các đặc trưng thuộc tầng liên kết dữ liệu và điều khiển mạng:
- ARP: arp.opcode, arp.hw.size
- ICMP: icmp.checksum, icmp.seq_le, icmp.transmit_timestamp, icmp.unused
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
from .base import BaseSubPreprocessor, numeric_series

NETWORK_CORE_FEATURES: List[str] = [
    "arp.opcode",
    "arp.hw.size",
    "icmp.checksum",
    "icmp.seq_le",
    "icmp.transmit_timestamp",
    "icmp.unused"
]


class NetworkCorePreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng ARP và ICMP dựa trên dữ liệu thực tế."""

    def __init__(self):
        super().__init__(feature_names=NETWORK_CORE_FEATURES, cat_cols=["arp.opcode"])

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
