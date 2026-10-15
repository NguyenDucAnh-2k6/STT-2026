"""Content survives extraction/Parquet without altering canonical features."""
import csv
import io
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from data_lake.lakehouse import DataLakeManager
from firmware.host_probe.content import extract_raw_content
from firmware.host_probe.packet_capture import FIELDS, parse_packet
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES


class RawContentTests(unittest.TestCase):
    def test_content_roundtrip_preserves_zero_unicode_whitespace_and_query(self) -> None:
        raw = dict.fromkeys(FIELDS, "")
        text = "  hello\tViệt Nam\r\n0  "
        raw.update({"frame.number": "1", "frame.time_epoch": "1800000000.1",
            "frame.len": "100", "frame.cap_len": "100", "frame.protocols": "eth:ip:tcp:http",
            "tcp.payload": text.encode().hex(), "tcp.len": str(len(text.encode())),
            "http.file_data": " 0\r\n ", "http.request.uri.query": "q=%3Cscript%3E&literal=0",
            "http.request.method": "POST", "mqtt.msg": "0", "_ws.col.Info": "HTTP response"})
        stream = io.StringIO()
        csv.writer(stream, delimiter="\t").writerow([raw[name].replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t") for name in FIELDS])
        types = dict.fromkeys(EDGE_IIOTSET_FEATURES, "FT_UINT32")
        types.update({"http.file_data": "FT_STRING", "mqtt.msg": "FT_STRING"})
        packet = parse_packet(stream.getvalue(), types, "fixture", "test", offline=True)
        self.assertEqual(packet["raw_tcp_payload_text"], text)
        self.assertEqual(packet["raw_http_body"], " 0\r\n ")
        self.assertEqual(packet["raw_mqtt_message"], "0")
        self.assertEqual(packet["raw_packet_info"], "HTTP response")
        with tempfile.TemporaryDirectory() as directory:
            lake = DataLakeManager(directory)
            lake.record_telemetry(packet)
            lake.close_session()
            row = pd.read_parquet(next(Path(directory).glob("raw/**/*.parquet"))).iloc[0]
            for name in ("raw_tcp_payload_hex", "raw_tcp_payload_text", "raw_http_body", "raw_http_query", "raw_mqtt_message"):
                self.assertEqual(row[name], packet[name])
            self.assertEqual(row["http.file_data"], "0")  # Existing normalized model contract.
            self.assertFalse(set(EDGE_IIOTSET_FEATURES) & {key for key in packet if key.startswith("raw_")})

    def test_binary_encrypted_absent_and_truncated_are_explicit(self) -> None:
        row = extract_raw_content({"tcp.payload": "ff00", "frame.protocols": "ip:tcp"}, {}, True)
        self.assertEqual(row["raw_tcp_payload_hex"], "ff00")
        self.assertIsNone(row["raw_tcp_payload_text"])
        self.assertEqual(row["raw_tcp_payload_decode_status"], "non_utf8")
        self.assertTrue(row["content_capture_truncated"])
        row = extract_raw_content({"tcp.payload": "6162", "frame.protocols": "ip:tcp:tls"}, {}, False)
        self.assertIsNone(row["raw_tcp_payload_text"])
        self.assertEqual(row["raw_tcp_payload_decode_status"], "encrypted_transport")
        row = extract_raw_content({}, {}, False)
        self.assertIsNone(row["raw_http_body"])
        self.assertIsNone(row["raw_tcp_payload_hex"])
        self.assertEqual(row["raw_http_body_completeness"], "not_observed")
