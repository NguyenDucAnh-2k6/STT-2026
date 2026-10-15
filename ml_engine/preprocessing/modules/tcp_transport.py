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
from .base import BaseSubPreprocessor, numeric_series, normalize_categorical_value

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

TCP_CAT_COLS: List[str] = ["tcp.options", "tcp.payload"]


class TCPTransportPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng tầng TCP dựa trên số liệu thực tế từ gói tin mạng."""

    def __init__(self):
        super().__init__(feature_names=TCP_FEATURES, cat_cols=TCP_CAT_COLS)
        self._cat_maps: Dict[str, Dict[str, float]] = {}

    def _fit_internal(self, df: pd.DataFrame) -> None:
        self._cat_maps = {}
        for col in self.cat_cols:
            if col in df:
                categories = sorted(set(df[col].map(normalize_categorical_value)) - {"0"})
                self._cat_maps[col] = {value: float(i) for i, value in enumerate(["0"] + categories)}

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                mapping = getattr(self, "_cat_maps", {}).get(col)
                if mapping is not None:
                    out[col] = df[col].map(lambda value: mapping.get(normalize_categorical_value(value), 0.0))
                    continue
                s = numeric_series(df[col])
                out[col] = s.fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Keep measured canonical values; never fabricate packet fields from windows."""
        return {feat: telemetry[feat] for feat in self.feature_names if feat in telemetry}
