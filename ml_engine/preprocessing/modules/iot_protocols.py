"""
IoT & Industrial Protocols Sub-Preprocessor
==========================================
Quản lý các đặc trưng của giao thức IoT và hệ thống điều khiển công nghiệp:
- DNS (7 đặc trưng): dns.qry.name, dns.qry.name.len, dns.qry.qu, dns.qry.type,
                      dns.retransmission, dns.retransmit_request, dns.retransmit_request_in
- MQTT (13 đặc trưng): mqtt.conack.flags, mqtt.conflag.cleansess, mqtt.conflags, mqtt.hdrflags,
                       mqtt.len, mqtt.msg_decoded_as, mqtt.msg, mqtt.msgtype, mqtt.proto_len,
                       mqtt.protoname, mqtt.topic, mqtt.topic_len, mqtt.ver
- Modbus TCP (3 đặc trưng): mbtcp.len, mbtcp.trans_id, mbtcp.unit_id
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
from .base import BaseSubPreprocessor, normalize_categorical_value

IOT_FEATURES: List[str] = [
    "dns.qry.name",
    "dns.qry.name.len",
    "dns.qry.qu",
    "dns.qry.type",
    "dns.retransmission",
    "dns.retransmit_request",
    "dns.retransmit_request_in",
    "mqtt.conack.flags",
    "mqtt.conflag.cleansess",
    "mqtt.conflags",
    "mqtt.hdrflags",
    "mqtt.len",
    "mqtt.msg_decoded_as",
    "mqtt.msg",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.protoname",
    "mqtt.topic",
    "mqtt.topic_len",
    "mqtt.ver",
    "mbtcp.len",
    "mbtcp.trans_id",
    "mbtcp.unit_id"
]

IOT_CAT_COLS: List[str] = [
    "dns.qry.name",
    "mqtt.msg",
    "mqtt.protoname",
    "mqtt.topic"
]


class IoTProtocolsPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng DNS, MQTT và Modbus TCP cho hệ thống IoT biên."""

    def __init__(self):
        super().__init__(feature_names=IOT_FEATURES, cat_cols=IOT_CAT_COLS)
        self._cat_maps: Dict[str, Dict[str, float]] = {}

    def _fit_internal(self, df: pd.DataFrame):
        valid_cats = [c for c in self.cat_cols if c in df.columns]
        for col in valid_cats:
            norm_series = df[col].map(normalize_categorical_value)
            unique_cats = sorted(norm_series.unique())
            # Luôn đảm bảo category '0' (mặc định/không xuất hiện) có index 0
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

        # Trích xuất đo đạc DNS thực tế nếu có
        if "dns_query" in telemetry:
            q_name = str(telemetry["dns_query"])
            res["dns.qry.name.len"] = float(len(q_name))
            if "dns.qry.name" in self._cat_maps:
                mapping = self._cat_maps["dns.qry.name"]
                res["dns.qry.name"] = mapping.get(normalize_categorical_value(q_name), mapping.get("0", 0.0))

        # Trích xuất đo đạc MQTT thực tế nếu có
        if "mqtt_topic" in telemetry:
            t_name = str(telemetry["mqtt_topic"])
            res["mqtt.topic_len"] = float(len(t_name))
            if "mqtt.topic" in self._cat_maps:
                res["mqtt.topic"] = self._cat_maps["mqtt.topic"].get(t_name, -1.0)

        return res
