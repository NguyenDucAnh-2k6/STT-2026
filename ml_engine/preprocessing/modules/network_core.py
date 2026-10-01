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
from .base import BaseSubPreprocessor

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

        # Trích xuất đo đạc lưu lượng thực tế nếu có
        proto = str(telemetry.get("protocol", "")).upper()
        icmp_r = float(telemetry.get("icmp_ratio", 0.0))
        pkt_rate = float(telemetry.get("packet_rate", 0.0))

        if icmp_r > 0.0 or "ICMP" in proto:
            if "icmp.checksum" not in telemetry:
                res["icmp.checksum"] = float(telemetry.get("checksum", 1.0))
            if "icmp.seq_le" not in telemetry and pkt_rate > 0:
                res["icmp.seq_le"] = float(pkt_rate)

        return res
