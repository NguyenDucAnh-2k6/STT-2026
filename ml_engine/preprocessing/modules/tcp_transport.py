"""
TCP Transport Sub-Preprocessor
==============================
Quản lý 15 đặc trưng của giao thức TCP:
- Ports: tcp.srcport, tcp.dstport
- Sequence & Ack: tcp.seq, tcp.ack, tcp.ack_raw
- Connection State & Flags: tcp.flags, tcp.flags.ack, tcp.connection.syn, tcp.connection.synack,
                            tcp.connection.fin, tcp.connection.rst
- Payload & Checksum: tcp.len, tcp.payload, tcp.options, tcp.checksum
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
from sklearn.preprocessing import OrdinalEncoder
from .base import BaseSubPreprocessor

TCP_FEATURES: List[str] = [
    "tcp.ack",
    "tcp.ack_raw",
    "tcp.checksum",
    "tcp.connection.fin",
    "tcp.connection.rst",
    "tcp.connection.syn",
    "tcp.connection.synack",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.options",
    "tcp.payload",
    "tcp.seq",
    "tcp.srcport"
]

TCP_CAT_COLS: List[str] = [
    "tcp.flags",
    "tcp.options",
    "tcp.payload"
]


class TCPTransportPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng tầng TCP dựa trên số liệu thực tế từ gói tin mạng."""

    def __init__(self):
        super().__init__(feature_names=TCP_FEATURES, cat_cols=TCP_CAT_COLS)
        self.encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        self._cat_maps: Dict[str, Dict[str, float]] = {}

    def _fit_internal(self, df: pd.DataFrame):
        valid_cats = [c for c in self.cat_cols if c in df.columns]
        if valid_cats:
            str_df = df[valid_cats].fillna("0.0").astype(str)
            self.encoder.fit(str_df)
            for idx, col in enumerate(valid_cats):
                cats = self.encoder.categories_[idx]
                self._cat_maps[col] = {str(c): float(i) for i, c in enumerate(cats)}

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                if col in self.cat_cols and col in self._cat_maps:
                    mapping = self._cat_maps[col]
                    out[col] = df[col].astype(str).map(lambda v: mapping.get(v, -1.0)).astype(np.float32)
                else:
                    s = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
                    out[col] = s.fillna(self.learned_baselines_.get(col, 0.0)).clip(lower=-1e9, upper=1e9)
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        res = {}
        # 1. Trích xuất các trường có sẵn trong telemetry
        for feat in self.feature_names:
            if feat in telemetry:
                try:
                    res[feat] = float(telemetry[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)
            else:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        # 2. Ánh xạ trực tiếp từ các trường đo đạc mạng thực tế của Probe
        proto = str(telemetry.get("protocol", "TCP")).upper()
        if "TCP" in proto or float(telemetry.get("syn_ratio", 0.0)) > 0 or float(telemetry.get("ack_ratio", 0.0)) > 0:
            # Ports thực tế từ gói tin
            if "src_port" in telemetry and telemetry["src_port"]:
                res["tcp.srcport"] = float(telemetry["src_port"])
            if "dst_port" in telemetry and telemetry["dst_port"]:
                res["tcp.dstport"] = float(telemetry["dst_port"])

            # Kích thước gói tin thực tế
            pkt_len = float(telemetry.get("packet_length", telemetry.get("avg_packet_size", 0.0)))
            if pkt_len > 0:
                res["tcp.len"] = pkt_len

            # Cờ TCP thực tế đo từ Sniffer
            syn_r = float(telemetry.get("syn_ratio", 0.0))
            ack_r = float(telemetry.get("ack_ratio", 0.0))

            if syn_r > 0.5:
                res["tcp.connection.syn"] = 1.0
                res["tcp.flags"] = 2.0  # SYN bit (0x02)
            elif ack_r > 0.5:
                res["tcp.flags.ack"] = 1.0
                res["tcp.flags"] = 16.0  # ACK bit (0x10)

        return res
