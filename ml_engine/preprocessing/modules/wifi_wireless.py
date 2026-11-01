"""
IEEE 802.11 Wireless & Radio Dynamics Sub-Preprocessor
======================================================
Quản lý các đặc trưng không dây tầng liên kết dữ liệu (Layer 2) và lớp vô tuyến (Radio):
- Hoàn toàn hoạt động trên khung tin 802.11 không cần giải mã WPA2/WPA3.
- Quản lý 14 đặc trưng canonical của chuẩn AWID3 (AWID3_WIFI_FEATURES):
  Frame length, Frequency, RSSI, Frame Control flags (Type, Subtype, DS, Retry, Protected),
  Duration và Sequence Number.
- Mở rộng bổ sung các chỉ số động lực học cửa sổ trượt (Rolling Radio Dynamics):
  Tốc độ gói Deauth, Disassociation, tỷ lệ khung Management/Data, tỷ lệ khung được mã hóa,
  và hiệu số Sequence Number (bắt spoofing).

Tài liệu tham khảo:
- Chatzoglou et al., "AWID3: A modern Wi-Fi intrusion detection dataset", 2021.
- Kolias et al., "DDoS in the IoT: The 802.11 Attack Landscape", IEEE.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from .base import BaseSubPreprocessor, numeric_series
from ...config.edge_profiles import AWID3_WIFI_FEATURES

# 14 đặc trưng cơ sở 802.11 chuẩn AWID3
WIFI_CORE_FEATURES: List[str] = list(AWID3_WIFI_FEATURES)

# Các đặc trưng động lực học không dây mở rộng theo cửa sổ thời gian
WIFI_WINDOW_EXTENDED_FEATURES: List[str] = [
    "deauth_rate",
    "disassoc_rate",
    "mgmt_to_data_ratio",
    "protected_ratio",
    "delta_seq_mean",
    "unique_macs"
]

ALL_WIFI_FEATURES: List[str] = WIFI_CORE_FEATURES + WIFI_WINDOW_EXTENDED_FEATURES


def parse_80211_frame_header(payload: bytes, rssi: int = -50, channel: int = 1) -> Optional[Dict[str, float]]:
    """
    Trích xuất trực tiếp 14 đặc trưng AWID3 từ mảng byte khung tin 802.11 thô.
    Đồng bộ tuyệt đối với hàm C extractWirelessFeatures() trên ESP32!
    """
    if len(payload) < 24:
        return None

    fc = payload[0] | (payload[1] << 8)
    fc_type = (fc >> 2) & 0x03
    fc_subtype = (fc >> 4) & 0x0F
    fc_ts = (fc_type << 4) | fc_subtype
    fc_ds = ((fc >> 8) & 1) << 1 | ((fc >> 9) & 1)
    fc_frag = (fc >> 10) & 1
    fc_retry = (fc >> 11) & 1
    fc_pwrmgt = (fc >> 12) & 1
    fc_moredata = (fc >> 13) & 1
    fc_protected = (fc >> 14) & 1

    freq = 2484.0 if channel == 14 else (2407.0 + channel * 5.0)
    duration = float(payload[2] | (payload[3] << 8))
    seq = float(((payload[22] | (payload[23] << 8)) >> 4) & 0x0FFF)

    return {
        "frame.len": float(len(payload)),
        "radiotap.channel.freq": freq,
        "radiotap.dbm_antsignal": float(rssi),
        "wlan.fc.type": float(fc_type),
        "wlan.fc.subtype": float(fc_subtype),
        "wlan.fc.type_subtype": float(fc_ts),
        "wlan.fc.ds": float(fc_ds),
        "wlan.fc.frag": float(fc_frag),
        "wlan.fc.retry": float(fc_retry),
        "wlan.fc.pwrmgt": float(fc_pwrmgt),
        "wlan.fc.moredata": float(fc_moredata),
        "wlan.fc.protected": float(fc_protected),
        "wlan.duration": duration,
        "wlan.seq": seq
    }


class WifiWirelessPreprocessor(BaseSubPreprocessor):
    """
    Tiền xử lý đặc trưng mạng không dây 802.11 Wi-Fi & Radio Dynamics.
    """

    def __init__(self, include_extended: bool = False):
        feature_list = ALL_WIFI_FEATURES if include_extended else WIFI_CORE_FEATURES
        super().__init__(feature_names=feature_list, cat_cols=[])
        self.include_extended = include_extended

    def _fit_internal(self, df: pd.DataFrame) -> None:
        pass

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                s = numeric_series(df[col])
                out[col] = s.fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        """
        Trích xuất từ Telemetry:
        - Lấy từ edge_raw_features hoặc telemetry cấp cao nếu có.
        - Hoặc trích xuất tức thì từ byte hex của radio frame ('frame_hex').
        """
        res: Dict[str, float] = {}
        # Kiểm tra edge_raw_features lồng nhau
        nested_raw = telemetry.get("edge_raw_features", {})

        for feat in self.feature_names:
            if feat in telemetry:
                try:
                    res[feat] = float(telemetry[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)
            elif feat in nested_raw:
                try:
                    res[feat] = float(nested_raw[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)

        if len(res) == len(self.feature_names):
            return res

        # Thử phân tích cú pháp từ chuỗi hex nếu có
        raw_hex = telemetry.get("frame_hex") or telemetry.get("payload_hex")
        if raw_hex:
            from .payload_entropy import parse_hex_to_bytes
            raw_b = parse_hex_to_bytes(raw_hex)
            rssi = int(telemetry.get("rssi", -50))
            channel = int(telemetry.get("channel", 1))
            parsed = parse_80211_frame_header(raw_b, rssi, channel)
            if parsed:
                for feat in self.feature_names:
                    if feat in parsed:
                        res[feat] = parsed[feat]

        for feat in self.feature_names:
            if feat not in res:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        return res
