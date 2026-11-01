"""
Payload Shannon Entropy & Byte Distribution Sub-Preprocessor
=============================================================
Khai thác tính chất ngẫu nhiên (randomness) và phân bố byte của gói tin:
- Khi DPI bị vô hiệu hóa bởi mã hóa (TLS, SSH, WPA2), nội dung payload
  trở thành dòng byte giả ngẫu nhiên (pseudo-random bytes).
- Shannon Entropy của dòng byte mã hóa xấp xỉ ~7.8 - 8.0 bit/byte.
- Payload bản rõ (HTTP, DNS, Modbus) có entropy thấp hơn (~3.0 - 5.5).
- Tấn công flood với payload rỗng hoặc lặp lại (SYN flood, Ping flood) có entropy ~0.

Tài liệu tham khảo:
- Yu Liu, "A Survey of Machine Learning-Based Packet Classification", UBC.
- Elmaghraby et al., "Encrypted network traffic classification...", Ain Shams Eng. J., 2024.
"""

import math
from typing import Dict, Any, List, Optional, Union
import numpy as np
import pandas as pd
from .base import BaseSubPreprocessor, numeric_series

PAYLOAD_ENTROPY_FEATURES: List[str] = [
    "payload_len",
    "payload_entropy",
    "payload_byte_mean",
    "payload_byte_std",
    "payload_zero_ratio",
    "payload_printable_ratio"
]


def calculate_byte_entropy(data: Union[bytes, bytearray, List[int], np.ndarray]) -> float:
    """
    Tính Shannon Entropy của chuỗi byte (bit/byte).
    Trả về giá trị từ 0.0 (hoàn toàn đơn điệu) đến 8.0 (ngẫu nhiên hoàn hảo / mã hóa AES).
    """
    if data is None or len(data) == 0:
        return 0.0
    
    length = len(data)
    counts = np.bincount(data if isinstance(data, (np.ndarray, list)) else list(data), minlength=256)
    
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return float(entropy)


def parse_hex_to_bytes(hex_val: Any) -> bytes:
    """Chuyển đổi chuỗi Hex (từ Wireshark / TShark / PCAP) sang bytes."""
    if hex_val is None or pd.isna(hex_val):
        return b""
    s = str(hex_val).strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    # Loại bỏ các ký tự phân cách (dấu hai chấm, khoảng trắng)
    s = s.replace(":", "").replace(" ", "").replace("\n", "")
    if len(s) % 2 != 0:
        s = s[:-1]
    if not s or s == "0":
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def extract_payload_statistics(raw_bytes: bytes) -> Dict[str, float]:
    """Trích xuất 6 đặc trưng phân bố và entropy từ mảng byte thô của payload."""
    n = len(raw_bytes)
    if n == 0:
        return {
            "payload_len": 0.0,
            "payload_entropy": 0.0,
            "payload_byte_mean": 0.0,
            "payload_byte_std": 0.0,
            "payload_zero_ratio": 0.0,
            "payload_printable_ratio": 0.0,
        }

    arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    entropy = calculate_byte_entropy(arr)
    byte_mean = float(np.mean(arr))
    byte_std = float(np.std(arr))
    zero_count = int(np.count_nonzero(arr == 0))
    printable_count = int(np.count_nonzero((arr >= 32) & (arr <= 126)))

    return {
        "payload_len": float(n),
        "payload_entropy": round(entropy, 4),
        "payload_byte_mean": round(byte_mean, 2),
        "payload_byte_std": round(byte_std, 2),
        "payload_zero_ratio": round(zero_count / n, 4),
        "payload_printable_ratio": round(printable_count / n, 4),
    }


class PayloadEntropyPreprocessor(BaseSubPreprocessor):
    """
    Tiền xử lý và trích xuất đặc trưng entropy và phân bố byte từ payload gói tin.
    Có thể xử lý cả chuỗi Hex trong DataFrame hoặc byte thô thời gian thực từ Telemetry.
    """

    def __init__(self, raw_payload_col: str = "tcp.payload"):
        super().__init__(feature_names=PAYLOAD_ENTROPY_FEATURES, cat_cols=[])
        self.raw_payload_col = raw_payload_col

    def _fit_internal(self, df: pd.DataFrame) -> None:
        """Học các giá trị phân phối baseline thực nghiệm khi payload bị rỗng/thiếu."""
        # Baseline đã được BaseSubPreprocessor khởi tạo bằng median từ df nếu các cột đã có sẵn
        pass

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Nếu DataFrame đã có sẵn các cột payload_*, làm sạch và điền baseline.
        Nếu có cột raw_payload_col (chứa hex), tự động tính toán các đặc trưng entropy.
        """
        out = pd.DataFrame(index=df.index)

        # Kiểm tra xem DataFrame đã có sẵn các cột đặc trưng entropy chưa
        has_precomputed = any(col in df.columns for col in self.feature_names)

        if not has_precomputed and self.raw_payload_col in df.columns:
            # Tính toán trực tiếp từ cột hex payload
            computed_records = []
            for hex_val in df[self.raw_payload_col]:
                b = parse_hex_to_bytes(hex_val)
                computed_records.append(extract_payload_statistics(b))
            computed_df = pd.DataFrame(computed_records, index=df.index)
            for feat in self.feature_names:
                out[feat] = computed_df[feat]
            return out

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
        - Nếu có sẵn các trường payload_entropy, payload_len,... -> lấy trực tiếp.
        - Nếu có trường "frame_hex" hoặc "tcp.payload" -> phân tích động ngay lập tức.
        """
        res: Dict[str, float] = {}
        for feat in self.feature_names:
            if feat in telemetry:
                try:
                    res[feat] = float(telemetry[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)

        if len(res) == len(self.feature_names):
            return res

        # Fallback: Trích xuất trực tiếp từ chuỗi hex nếu có
        raw_hex = telemetry.get("frame_hex") or telemetry.get("tcp.payload") or telemetry.get("payload_hex")
        if raw_hex:
            raw_b = parse_hex_to_bytes(raw_hex)
            return extract_payload_statistics(raw_b)

        # Trả về baseline nếu không có dữ liệu
        for feat in self.feature_names:
            if feat not in res:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        return res
