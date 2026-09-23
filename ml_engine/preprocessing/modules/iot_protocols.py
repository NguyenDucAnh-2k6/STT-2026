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
from sklearn.preprocessing import OrdinalEncoder
from .base import BaseSubPreprocessor

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
    "mqtt.conack.flags",
    "mqtt.msg",
    "mqtt.protoname",
    "mqtt.topic"
]


class IoTProtocolsPreprocessor(BaseSubPreprocessor):
    """Tiền xử lý các đặc trưng DNS, MQTT và Modbus TCP cho hệ thống IoT biên."""

    def __init__(self):
        super().__init__(feature_names=IOT_FEATURES, cat_cols=IOT_CAT_COLS)
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

        # Trích xuất đo đạc DNS thực tế nếu có
        if "dns_query" in telemetry:
            q_name = str(telemetry["dns_query"])
            res["dns.qry.name.len"] = float(len(q_name))
            if "dns.qry.name" in self._cat_maps:
                res["dns.qry.name"] = self._cat_maps["dns.qry.name"].get(q_name, -1.0)

        # Trích xuất đo đạc MQTT thực tế nếu có
        if "mqtt_topic" in telemetry:
            t_name = str(telemetry["mqtt_topic"])
            res["mqtt.topic_len"] = float(len(t_name))
            if "mqtt.topic" in self._cat_maps:
                res["mqtt.topic"] = self._cat_maps["mqtt.topic"].get(t_name, -1.0)

        return res
