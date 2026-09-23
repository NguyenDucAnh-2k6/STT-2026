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
from sklearn.preprocessing import OrdinalEncoder
from .base import BaseSubPreprocessor

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
                    res[feat] = self._cat_maps[feat].get(str(val), -1.0)
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
                res["http.request.method"] = self._cat_maps["http.request.method"].get(m, -1.0)

        return res
