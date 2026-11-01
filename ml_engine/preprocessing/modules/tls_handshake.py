"""
TLS Handshake & JA3 Fingerprinting Sub-Preprocessor
===================================================
Trích xuất đặc trưng nhận dạng phiên mã hóa từ các gói tin bắt tay (TLS Handshake):
- Dù nội dung ứng dụng sau đó bị mã hóa hoàn toàn, gói tin TLS Client Hello ban đầu
  luôn để lộ: Phiên bản TLS, danh sách các bộ mã hóa (Cipher Suites), danh sách Extensions,
  các đường cong Elliptic Curves hỗ trợ và Server Name Indication (SNI).
- Sinh dấu vân tay JA3 (JA3 Fingerprint) - chuẩn nhận diện mã độc và botnet quốc tế:
  JA3 = MD5(SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats)
- Hỗ trợ phân tích trực tiếp từ chuỗi Hex gói tin hoặc dữ liệu cột trích xuất từ TShark/PCAP.

Tài liệu tham khảo:
- OFDPI: "An OpenFlow-based Deep Packet Inspection Framework", SDN.pdf.
- John Althouse et al., "JA3 - A method for profiling SSL/TLS Clients", Salesforce.
"""

import hashlib
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
import numpy as np
import pandas as pd
from .base import BaseSubPreprocessor, numeric_series, normalize_categorical_value

TLS_HANDSHAKE_FEATURES: List[str] = [
    "tls_version",
    "tls_ciphersuite_count",
    "tls_extension_count",
    "tls_supported_groups_count",
    "tls_sni_present",
    "tls_sni_length",
    "tls_is_client_hello"
]

TLS_CAT_COLS: List[str] = ["tls_ja3_hash"]

# Bộ giá trị GREASE (RFC 8701) cần lọc bỏ khi tính JA3
GREASE_VALUES: Set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBAAB, 0xCAAC, 0xDAAD, 0xEAAE, 0xFAAF
}


def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Phân tích cú pháp nhị phân của gói tin TLS Record Layer để trích xuất Client Hello.
    Hoàn toàn thuần Python, không phụ thuộc vào thư viện ngoài.
    """
    if len(payload) < 9:
        return None

    # TLS Record Layer:
    # Byte 0: Content Type (22 = Handshake)
    # Byte 1-2: Record Version (ví dụ 0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    # Byte 3-4: Length
    content_type = payload[0]
    if content_type != 22:
        return None

    record_version = struct.unpack("!H", payload[1:3])[0]
    record_len = struct.unpack("!H", payload[3:5])[0]

    if len(payload) < 5 + min(record_len, 4):
        return None

    # Handshake Header:
    # Byte 5: Handshake Type (1 = Client Hello)
    # Byte 6-8: Handshake Length (3 bytes uint24)
    hs_type = payload[5]
    if hs_type != 1:
        return None

    hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
    offset = 9

    if len(payload) < offset + 34:
        return None

    # Client Version (2 bytes) & Random (32 bytes)
    client_version = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2 + 32

    # Session ID
    if offset >= len(payload):
        return None
    session_id_len = payload[offset]
    offset += 1 + session_id_len

    # Cipher Suites
    if offset + 2 > len(payload):
        return None
    cipher_len = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2

    ciphers: List[int] = []
    end_cipher = offset + cipher_len
    while offset + 2 <= min(end_cipher, len(payload)):
        c = struct.unpack("!H", payload[offset:offset + 2])[0]
        if c not in GREASE_VALUES:
            ciphers.append(c)
        offset += 2
    offset = end_cipher

    # Compression Methods
    if offset >= len(payload):
        return None
    comp_len = payload[offset]
    offset += 1 + comp_len

    # Extensions
    extensions: List[int] = []
    supported_groups: List[int] = []
    point_formats: List[int] = []
    sni_hostname = ""

    if offset + 2 <= len(payload):
        ext_total_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total_len

        while offset + 4 <= min(ext_end, len(payload)):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type not in GREASE_VALUES:
                extensions.append(ext_type)

            ext_data = payload[offset:offset + ext_len]
            # Extension 0: Server Name Indication (SNI)
            if ext_type == 0 and len(ext_data) >= 5:
                sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
                if ext_data[2] == 0:  # HostName type
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        sni_hostname = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")

            # Extension 10: Supported Groups (Elliptic Curves)
            elif ext_type == 10 and len(ext_data) >= 2:
                groups_len = struct.unpack("!H", ext_data[0:2])[0]
                g_off = 2
                while g_off + 2 <= min(2 + groups_len, len(ext_data)):
                    g = struct.unpack("!H", ext_data[g_off:g_off + 2])[0]
                    if g not in GREASE_VALUES:
                        supported_groups.append(g)
                    g_off += 2

            # Extension 11: EC Point Formats
            elif ext_type == 11 and len(ext_data) >= 1:
                formats_len = ext_data[0]
                point_formats = list(ext_data[1:1 + formats_len])

            offset += ext_len

    # Tạo JA3 Fingerprint String: Version,Ciphers,Extensions,Curves,Formats
    ciphers_str = "-".join(str(c) for c in ciphers)
    extensions_str = "-".join(str(e) for e in extensions)
    groups_str = "-".join(str(g) for g in supported_groups)
    formats_str = "-".join(str(f) for f in point_formats)

    ja3_string = f"{client_version},{ciphers_str},{extensions_str},{groups_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()

    return {
        "tls_version": float(client_version),
        "tls_ciphersuite_count": float(len(ciphers)),
        "tls_extension_count": float(len(extensions)),
        "tls_supported_groups_count": float(len(supported_groups)),
        "tls_sni_present": 1.0 if len(sni_hostname) > 0 else 0.0,
        "tls_sni_length": float(len(sni_hostname)),
        "tls_is_client_hello": 1.0,
        "tls_ja3_string": ja3_string,
        "tls_ja3_hash": ja3_hash,
        "tls_sni": sni_hostname
    }


class TLSHandshakePreprocessor(BaseSubPreprocessor):
    """
    Tiền xử lý và trích xuất đặc trưng TLS Handshake và JA3 Fingerprint.
    """

    def __init__(self):
        super().__init__(feature_names=TLS_HANDSHAKE_FEATURES, cat_cols=TLS_CAT_COLS)
        self._ja3_map: Dict[str, float] = {}

    def _fit_internal(self, df: pd.DataFrame) -> None:
        self._ja3_map = {}
        if "tls_ja3_hash" in df.columns:
            hashes = sorted(set(df["tls_ja3_hash"].map(normalize_categorical_value)) - {"0"})
            self._ja3_map = {h: float(i + 1) for i, h in enumerate(hashes)}

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
        - Lấy trực tiếp nếu các trường tls_* đã có.
        - Hoặc nếu telemetry có chuỗi hex gói tin ('frame_hex' hoặc 'tcp.payload'),
          phân tích động gói tin TLS Client Hello ngay lập tức.
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

        # Thử phân tích cú pháp từ chuỗi hex nếu có
        raw_hex = telemetry.get("frame_hex") or telemetry.get("tcp.payload") or telemetry.get("payload_hex")
        if raw_hex:
            from .payload_entropy import parse_hex_to_bytes
            raw_b = parse_hex_to_bytes(raw_hex)
            tls_info = parse_tls_client_hello(raw_b)
            if tls_info:
                return {feat: tls_info.get(feat, self.learned_baselines_.get(feat, 0.0)) for feat in self.feature_names}

        # Baseline mặc định
        for feat in self.feature_names:
            if feat not in res:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        return res
