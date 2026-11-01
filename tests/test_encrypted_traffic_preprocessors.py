"""
Unit Tests for Encrypted Traffic Preprocessing Modules
=====================================================
Kiểm thử toàn diện 4 module tiền xử lý dữ liệu lưu lượng mã hóa:
1. PayloadEntropyPreprocessor (Shannon Entropy & Byte distribution)
2. FlowDynamicsPreprocessor (Biflow 2 chiều & Sub-flow windowing)
3. TLSHandshakePreprocessor (TLS Client Hello parsing & JA3 fingerprinting)
4. WifiWirelessPreprocessor (802.11 Layer 2 Frame Control & Radio Dynamics)
"""

import unittest
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd

from ml_engine.preprocessing.modules import (
    PayloadEntropyPreprocessor,
    calculate_byte_entropy,
    extract_payload_statistics,
    parse_hex_to_bytes,
    FlowDynamicsPreprocessor,
    compute_biflow_features_from_packets,
    partition_into_subflows,
    TLSHandshakePreprocessor,
    parse_tls_client_hello,
    WifiWirelessPreprocessor,
    parse_80211_frame_header
)


class TestPayloadEntropyPreprocessor(unittest.TestCase):
    def test_zero_entropy_for_repeated_bytes(self):
        repeated = bytes([0x41] * 200)  # 'A' * 200
        entropy = calculate_byte_entropy(repeated)
        self.assertAlmostEqual(entropy, 0.0, places=4)

    def test_high_entropy_for_uniform_random_bytes(self):
        # 256 byte khác nhau hoàn toàn: mỗi byte xuất hiện đúng 1 lần -> p = 1/256 -> H = log2(256) = 8.0
        uniform = bytes(range(256))
        entropy = calculate_byte_entropy(uniform)
        self.assertAlmostEqual(entropy, 8.0, places=4)

    def test_empty_payload(self):
        stats = extract_payload_statistics(b"")
        self.assertEqual(stats["payload_len"], 0.0)
        self.assertEqual(stats["payload_entropy"], 0.0)

    def test_ascii_printable_and_zero_ratio(self):
        # 10 byte zero, 90 byte printable ASCII ('a')
        data = bytes([0] * 10 + [ord('a')] * 90)
        stats = extract_payload_statistics(data)
        self.assertEqual(stats["payload_len"], 100.0)
        self.assertAlmostEqual(stats["payload_zero_ratio"], 0.10, places=2)
        self.assertAlmostEqual(stats["payload_printable_ratio"], 0.90, places=2)

    def test_fit_and_transform_dataframe(self):
        df = pd.DataFrame({
            "tcp.payload": [
                "000000000000",
                "474554202f20485454502f312e310d0a",  # GET / HTTP/1.1\r\n
                None
            ]
        })
        prep = PayloadEntropyPreprocessor(raw_payload_col="tcp.payload")
        prep.fit(df)
        transformed = prep.transform(df)
        self.assertEqual(len(transformed), 3)
        self.assertIn("payload_entropy", transformed.columns)
        self.assertIn("payload_len", transformed.columns)
        self.assertEqual(transformed["payload_entropy"].iloc[0], 0.0)
        self.assertGreater(transformed["payload_entropy"].iloc[1], 0.0)

    def test_extract_from_telemetry(self):
        prep = PayloadEntropyPreprocessor()
        prep.fit(pd.DataFrame(columns=prep.feature_names))
        telemetry = {"frame_hex": "0102030405060708"}
        features = prep.extract_from_telemetry(telemetry)
        self.assertEqual(features["payload_len"], 8.0)
        self.assertGreater(features["payload_entropy"], 0.0)


class TestFlowDynamicsPreprocessor(unittest.TestCase):
    def test_biflow_computation(self):
        packets = [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "len": 100, "timestamp": 1.0},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "len": 200, "timestamp": 1.1},
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "len": 50,  "timestamp": 1.15},
            {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "len": 50,  "timestamp": 1.25},
        ]
        biflow = compute_biflow_features_from_packets(packets)
        self.assertEqual(biflow["fwd_pkt_count"], 2.0)
        self.assertEqual(biflow["bwd_pkt_count"], 2.0)
        self.assertEqual(biflow["pkt_asymmetry_ratio"], 0.5)
        self.assertEqual(biflow["fwd_byte_count"], 300.0)
        self.assertEqual(biflow["bwd_byte_count"], 100.0)
        self.assertEqual(biflow["byte_asymmetry_ratio"], 0.75)  # 300 / 400
        self.assertAlmostEqual(biflow["fwd_iat_mean"], 0.1, places=3)
        self.assertAlmostEqual(biflow["bwd_iat_mean"], 0.1, places=3)
        self.assertAlmostEqual(biflow["flow_duration_sec"], 0.25, places=3)

    def test_partition_into_subflows(self):
        packets = [{"id": i} for i in range(65)]
        subflows = partition_into_subflows(packets, subflow_size=25)
        self.assertEqual(len(subflows), 3)
        self.assertEqual(len(subflows[0]), 25)
        self.assertEqual(len(subflows[1]), 25)
        self.assertEqual(len(subflows[2]), 15)

    def test_fit_and_transform_dataframe(self):
        prep = FlowDynamicsPreprocessor()
        df = pd.DataFrame({
            "fwd_pkt_count": [10.0, 20.0],
            "bwd_pkt_count": [5.0, 15.0],
            "pkt_asymmetry_ratio": [0.66, 0.57]
        })
        prep.fit(df)
        transformed = prep.transform(df)
        self.assertEqual(len(transformed), 2)
        self.assertIn("byte_asymmetry_ratio", transformed.columns)


class TestTLSHandshakePreprocessor(unittest.TestCase):
    def test_parse_tls_client_hello(self):
        # Tạo gói tin nhị phân TLS Client Hello hợp lệ
        # TLS Record Header: Type 22 (Handshake), Version 0x0303 (TLS 1.2)
        # Handshake Header: Type 1 (Client Hello), Length
        # Client Version 0x0303, Random 32 bytes, SessionID len 0
        # Ciphers len 4: [0xc02f, 0xc030], Comp len 1: [0x00]
        # Extensions len 12: Ext 0 (SNI)
        random_bytes = b"\x01" * 32
        ciphers = b"\xc0\x2f\xc0\x30"
        sni_hostname = b"example.com"
        sni_ext_data = (
            b"\x00\x0e" +          # Server name list length (14)
            b"\x00" +              # Hostname type 0
            b"\x00\x0b" +          # Length of hostname (11)
            sni_hostname
        )
        ext_sni = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
        extensions = ext_sni
        ext_block = len(extensions).to_bytes(2, "big") + extensions

        hs_body = (
            b"\x03\x03" +          # Client version 0x0303
            random_bytes +         # Random
            b"\x00" +              # Session ID length = 0
            len(ciphers).to_bytes(2, "big") + ciphers +
            b"\x01\x00" +          # Compression methods (1 method: 0 = None)
            ext_block
        )

        hs_header = b"\x01" + len(hs_body).to_bytes(3, "big")
        record_body = hs_header + hs_body
        record_header = b"\x16\x03\x03" + len(record_body).to_bytes(2, "big")
        tls_packet = record_header + record_body

        res = parse_tls_client_hello(tls_packet)
        self.assertIsNotNone(res)
        self.assertEqual(res["tls_is_client_hello"], 1.0)
        self.assertEqual(res["tls_version"], 0x0303)
        self.assertEqual(res["tls_ciphersuite_count"], 2.0)
        self.assertEqual(res["tls_extension_count"], 1.0)
        self.assertEqual(res["tls_sni_present"], 1.0)
        self.assertEqual(res["tls_sni"], "example.com")
        self.assertIn("tls_ja3_hash", res)
        self.assertEqual(len(res["tls_ja3_hash"]), 32)

    def test_non_tls_packet_returns_none(self):
        dummy = b"\x45\x00\x00\x3c\x12\x34\x00\x00\x40\x06"
        res = parse_tls_client_hello(dummy)
        self.assertIsNone(res)


class TestWifiWirelessPreprocessor(unittest.TestCase):
    def test_parse_80211_data_frame(self):
        # 24-byte Data Frame:
        # Byte 0: 0x08 (Type 2 = Data, Subtype 0)
        # Byte 1: 0x40 (Protected Frame bit 14 set = WPA2)
        # Byte 2-3: Duration
        # Addr1 (6 bytes), Addr2 (6 bytes), Addr3 (6 bytes)
        # Byte 22-23: Seq 0x0120 -> seq = 0x012 = 18
        payload = bytearray(24)
        payload[0] = 0x08  # Type 2 (Data), Subtype 0
        payload[1] = 0x40  # Protected Frame
        payload[2] = 0x30
        payload[3] = 0x00  # Duration = 48
        payload[22] = 0x20
        payload[23] = 0x01  # Seq 0x0120 >> 4 = 18

        res = parse_80211_frame_header(bytes(payload), rssi=-65, channel=6)
        self.assertIsNotNone(res)
        self.assertEqual(res["wlan.fc.type"], 2.0)
        self.assertEqual(res["wlan.fc.subtype"], 0.0)
        self.assertEqual(res["wlan.fc.protected"], 1.0)
        self.assertEqual(res["radiotap.dbm_antsignal"], -65.0)
        self.assertEqual(res["radiotap.channel.freq"], 2437.0)  # 2407 + 6*5
        self.assertEqual(res["wlan.duration"], 48.0)
        self.assertEqual(res["wlan.seq"], 18.0)

    def test_parse_80211_deauth_frame(self):
        # Deauthentication: Type 0 (Management), Subtype 12 (0x0C)
        # Byte 0: (12 << 4) | (0 << 2) = 0xC0
        payload = bytearray(24)
        payload[0] = 0xC0
        payload[1] = 0x00

        res = parse_80211_frame_header(bytes(payload), rssi=-40, channel=1)
        self.assertIsNotNone(res)
        self.assertEqual(res["wlan.fc.type"], 0.0)
        self.assertEqual(res["wlan.fc.subtype"], 12.0)
        self.assertEqual(res["wlan.fc.protected"], 0.0)


if __name__ == "__main__":
    unittest.main()
