"""Schema checks shared by benchmark loading and field-data eligibility."""
from typing import Dict

import pandas as pd

from ..config.schema import EDGE_IIOTSET_FEATURES
from .modules.base import numeric_series
from .modules.http_application import HTTP_CAT_COLS
from .modules.iot_protocols import IOT_CAT_COLS
from .modules.tcp_transport import TCP_CAT_COLS

CATEGORICAL_FEATURES = set(HTTP_CAT_COLS + IOT_CAT_COLS + TCP_CAT_COLS)


def invalid_feature_counts(frame: pd.DataFrame) -> Dict[str, int]:
    """Count malformed numeric measurements without exposing packet contents."""
    invalid: Dict[str, int] = {}
    for feature in EDGE_IIOTSET_FEATURES:
        if feature not in frame or feature in CATEGORICAL_FEATURES:
            continue
        raw = frame[feature]
        parsed = numeric_series(raw)
        mask = raw.notna() & parsed.isna()
        if feature in ("tcp.srcport", "tcp.dstport", "udp.port", "http.tls_port"):
            mask |= parsed.notna() & (~parsed.between(0, 65535) | parsed.mod(1).ne(0))
        if mask.any():
            invalid[feature] = int(mask.sum())
    return invalid


def invalid_record_mask(frame: pd.DataFrame) -> pd.Series:
    """Vectorized row eligibility for malformed numeric fields."""
    mask = pd.Series(False, index=frame.index)
    for feature in invalid_feature_counts(frame):
        parsed = numeric_series(frame[feature])
        mask |= frame[feature].notna() & parsed.isna()
        if feature in ("tcp.srcport", "tcp.dstport", "udp.port", "http.tls_port"):
            mask |= parsed.notna() & (~parsed.between(0, 65535) | parsed.mod(1).ne(0))
    return mask
