"""
HTTP Application Sub-Preprocessor
=================================
Quản lý 9 đặc trưng của giao thức ứng dụng HTTP:
- http.request.method: Phương thức (GET, POST, OPTIONS, TRACE...)
- http.content_length: Kích thước nội dung truyền tải
- http.request.uri.query, http.request.full_uri: Đường dẫn tài nguyên
- http.referer: Nguồn chuyển tiếp
- http.request.version, http.response, http.tls_port, http.file_data
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
from .base import BaseSubPreprocessor, normalize_categorical_value

HTTP_FEATURES: List[str] = [
    "http.file_data",
    "http.content_length",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version",
    "http.response",
    "http.tls_port"
]

HTTP_CAT_COLS: List[str] = [
    "http.file_data",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version"
]


class HTTPApplicationPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng tầng ứng dụng HTTP."""

    def __init__(self):
        super().__init__(feature_names=HTTP_FEATURES, cat_cols=HTTP_CAT_COLS)
        self._cat_maps: Dict[str, Dict[str, float]] = {}

    def _fit_internal(self, df: pd.DataFrame):
        valid_cats = [c for c in self.cat_cols if c in df.columns]
        for col in valid_cats:
            norm_series = df[col].map(normalize_categorical_value)
            unique_cats = sorted(norm_series.unique())
            if "0" not in unique_cats:
                unique_cats.insert(0, "0")
            else:
                unique_cats.remove("0")
                unique_cats.insert(0, "0")
            self._cat_maps[col] = {cat: float(idx) for idx, cat in enumerate(unique_cats)}

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                if col in self.cat_cols and col in self._cat_maps:
                    mapping = self._cat_maps[col]
                    default_idx = mapping.get("0", 0.0)
                    out[col] = df[col].map(lambda v: mapping.get(normalize_categorical_value(v), default_idx)).astype(np.float32)
                else:
                    out[col] = pd.to_numeric(df[col], errors="coerce").fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        res = {}
        for feat in self.feature_names:
            if feat in telemetry:
                val = telemetry[feat]
                if feat in self.cat_cols and feat in self._cat_maps:
                    mapping = self._cat_maps[feat]
                    default_idx = mapping.get("0", 0.0)
                    res[feat] = mapping.get(normalize_categorical_value(val), default_idx)
                else:
                    try:
                        res[feat] = float(val)
                    except (ValueError, TypeError):
                        res[feat] = self.learned_baselines_.get(feat, 0.0)
            else:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        # Trích xuất đo đạc HTTP thực tế nếu có
        if "http.content_length" not in telemetry:
            byte_rate = float(telemetry.get("byte_rate", 0.0))
            if byte_rate > 0 and (telemetry.get("dst_port") in (80, 8080, 443) or telemetry.get("src_port") in (80, 8080, 443)):
                res["http.content_length"] = byte_rate

        # Mã hóa phương thức HTTP nếu có trong telemetry (ví dụ: 'GET', 'POST')
        if "http_method" in telemetry or "method" in telemetry:
            m = str(telemetry.get("http_method", telemetry.get("method", ""))).upper()
            if m and "http.request.method" in self._cat_maps:
                mapping = self._cat_maps["http.request.method"]
                res["http.request.method"] = mapping.get(normalize_categorical_value(m), mapping.get("0", 0.0))

        return res
