"""Synthetic radio frames only; no physical capture or existing artifacts touched."""
import copy
import io
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pandas as pd
import numpy as np

from firmware.esp32_probe.radio_capture import (RadioPacketDecoder, parse_radio_sample,
    annotate_radio_packet, pcap_record)
from firmware.host_probe.packet_capture import field_registry
from firmware.host_probe.tshark_engine import find_tshark_path
from data_lake.collector import DataLakeCollector
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.inference_service import AnomalyInferenceEngine
from ml_engine.preprocessing import EdgeTrafficPreprocessor


def radio_payload(protected: bool = False) -> dict:
    header = bytes.fromhex("08400000" if protected else "08000000") + bytes.fromhex(
        "00112233445566778899aabb0011223344550000")
    http = b"GET /sample HTTP/1.1\r\nHost: example.test\r\n\r\n"
    tcp = struct.pack("!HHLLBBHHH", 40000, 80, 101, 1, 0x50, 0x18, 4096, 0, 0) + http
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
    frame = header + bytes.fromhex("aaaa030000000800") + ip + tcp
    return dict(schema_version=1, record_kind="radio_frame", device_id="test-esp32",
                boot_id=123, sequence=1, timestamp=2000, timestamp_kind="uptime_ms",
                linktype=105, fcs_included=False, original_length=len(frame), captured_length=len(frame),
                channel=6, rssi=-50, sample_interval_ms=500, frame_hex=frame.hex())


class ESP32RadioTests(unittest.TestCase):
    def test_bounded_validation_and_pcap(self) -> None:
        payload = radio_payload()
        sample = parse_radio_sample(payload, 1_800_000_000_000)
        self.assertEqual(sample.identity, ("test-esp32", 123, 1))
        self.assertEqual(struct.unpack("<IIII", pcap_record(sample)[:16]),
                         (1_800_000_000, 0, len(sample.payload), len(sample.payload)))
        for changes in ({"timestamp": True}, {"channel": 0}, {"fcs_included": True},
                        {"frame_hex": "00"}, {"captured_length": 2049}, {"rssi": float("nan")},
                        {"device_id": {}}, {"linktype": 1}, {"boot_id": -1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_radio_sample({**payload, **changes}, 1_800_000_000_000)

    def test_protected_and_fragmented_are_unmeasured(self) -> None:
        packet = {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "protocol_stack": "wlan:ip:tcp",
                  "missing_features": [], "absent_fields": []}
        protected = parse_radio_sample(radio_payload(True), 1_800_000_000_000)
        row = annotate_radio_packet(copy.deepcopy(packet), protected)
        self.assertEqual(row["missing_features"], EDGE_IIOTSET_FEATURES)
        self.assertTrue(all(row[name] is None for name in EDGE_IIOTSET_FEATURES))
        self.assertFalse(row["supervised_training_eligible"])
        self.assertEqual(row["packet_id"], "test-esp32:123:radio:1")
        payload = radio_payload()
        frame = bytearray.fromhex(payload["frame_hex"])
        frame[1] |= 4
        payload["frame_hex"] = frame.hex()
        row = annotate_radio_packet(copy.deepcopy(packet), parse_radio_sample(payload, 1_800_000_000_000))
        self.assertTrue(row["radio_fragmented"])
        self.assertFalse(row["protocol_features_available"])

    def test_uptime_wrap_and_late_transport_frame(self) -> None:
        decoder = RadioPacketDecoder.__new__(RadioPacketDecoder)
        decoder.error = None
        decoder.process = SimpleNamespace(poll=lambda: None, stdin=io.BytesIO())
        decoder.slots = threading.BoundedSemaphore(64)
        decoder.lock = threading.Lock()
        decoder.pending = {}
        decoder.number = 0
        decoder.last_uptime_ms = decoder.capture_epoch_ms = None
        first = radio_payload() | {"timestamp": 0xffffff00}
        second = radio_payload() | {"timestamp": 256, "sequence": 2}
        late = radio_payload() | {"timestamp": 100, "sequence": 3}
        self.assertTrue(decoder.feed(parse_radio_sample(first, 1_800_000_000_000)))
        self.assertTrue(decoder.feed(parse_radio_sample(second, 1_800_000_009_000)))
        self.assertEqual(decoder.capture_epoch_ms, 1_800_000_000_512)
        self.assertFalse(decoder.feed(parse_radio_sample(late, 1_800_000_010_000)))
        self.assertEqual(decoder.number, 2)

    def test_encrypted_inference_never_calls_models(self) -> None:
        engine = AnomalyInferenceEngine.__new__(AnomalyInferenceEngine)
        engine.metadata = {"preprocessing_version": 2}
        engine.classifier, engine.anomaly_detector = MagicMock(), MagicMock()
        sample = parse_radio_sample(radio_payload(True), 1_800_000_000_000)
        row = annotate_radio_packet({"record_kind": "packet", "missing_features": []}, sample)
        result = engine.predict(row)
        self.assertEqual(result["inference_status"], "unavailable")
        self.assertIsNone(result["is_anomaly"])
        self.assertEqual(result["class_probabilities"], {})
        engine.classifier.predict_proba.assert_not_called()

    def test_lake_identity_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lake = DataLakeManager(base_dir=directory)
            lake.start_session("esp32", "ap-locked")
            collector = DataLakeCollector(lake_manager=lake)
            sample = parse_radio_sample(radio_payload(True), 1_800_000_000_000)
            row = annotate_radio_packet({"timestamp": sample.received_at_ms, "schema_version": 2,
                "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1", "missing_features": [],
                "label_source": "unverified"}, sample)
            message = SimpleNamespace(topic="edge/telemetry/traffic", payload=json.dumps(row).encode())
            collector._on_message(None, None, message)
            collector._on_message(None, None, message)
            self.assertEqual(len(lake.buffer), 1)
            self.assertEqual(lake.buffer[0]["sniffer_mode"], "radio-sampled")
            self.assertEqual(lake.buffer[0]["source_timestamp"], 2000)
            lake.close_session()
            frame = pd.read_parquet(next(Path(directory).rglob("*.parquet")))
            self.assertEqual(frame.iloc[0].probe_type, "esp32")
            self.assertTrue(frame[EDGE_IIOTSET_FEATURES].isna().all().all())
            self.assertTrue(select_training_records(frame)[0].empty)

    @unittest.skipUnless(find_tshark_path(), "TShark unavailable")
    def test_native_stream_plaintext_and_encrypted(self) -> None:
        executable = find_tshark_path()
        types = field_registry(executable)
        rows = []
        received = threading.Event()
        def collect(row: dict) -> None:
            rows.append(row)
            if len(rows) >= 2:
                received.set()
        decoder = RadioPacketDecoder(executable, types, "test-native", collect)
        try:
            decoder.feed(parse_radio_sample(radio_payload(), 1_800_000_000_000))
            encrypted = radio_payload(True)
            encrypted["sequence"] = 2
            decoder.feed(parse_radio_sample(encrypted, 1_800_000_000_500))
            self.assertTrue(received.wait(8), decoder.error)
            self.assertIsNone(decoder.error)
        finally:
            decoder.close()
        self.assertEqual(rows[0]["tcp.srcport"], 40000)
        self.assertEqual(rows[0]["tcp.dstport"], 80)
        self.assertEqual(rows[0]["http.request.method"], "GET")
        self.assertEqual(rows[0]["missing_features"], [])
        self.assertEqual(rows[1]["missing_features"], EDGE_IIOTSET_FEATURES)
        self.assertEqual(rows[0]["capture_id"], rows[1]["capture_id"])
        self.assertEqual(decoder.pending, {})
        self.assertIsNotNone(decoder.process.poll())
        # Exercise the final inference contract with controlled estimator outputs,
        # not a claim about any deployed model's accuracy on radio traffic.
        engine = AnomalyInferenceEngine.__new__(AnomalyInferenceEngine)
        engine.metadata = {"preprocessing_version": 2, "labels": ["Normal", "DDoS_TCP"],
                           "isolation_score_min": -1, "isolation_score_max": 0}
        engine.preprocessor = EdgeTrafficPreprocessor().fit(
            pd.DataFrame([rows[0], rows[0]])[EDGE_IIOTSET_FEATURES], pd.Series(["Normal", "Normal"]))
        engine.classifier = SimpleNamespace(predict_proba=lambda x: np.array([[.8, .2]]))
        engine.anomaly_detector = SimpleNamespace(score_samples=lambda x: np.array([-.5]))
        engine.anomaly_threshold = .55
        result = engine.predict(rows[0])
        self.assertEqual(result["inference_status"], "ok")
        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["class_probabilities"], {"Normal": .8, "DDoS_TCP": .2})
        self.assertEqual(result["edge_inference_status"], "unavailable")
        self.assertEqual(result["edge_features_count"], 0)
        self.assertIsNone(result["edge_flag"])

    def test_usb_routes_radio_and_window_without_time_throttle(self) -> None:
        from launcher.workers import serial_telemetry_bridge_worker
        stop = threading.Event()
        radio = b"ESP32_RADIO:" + json.dumps(radio_payload()).encode() + b"\n"
        window = b'ESP32_TELEMETRY:{"device_id":"test-esp32","radio_capture_version":1}\n'
        lines = iter([radio, window])
        def read(*args, **kwargs) -> bytes:
            try:
                return next(lines)
            except StopIteration:
                stop.set()
                return b""
        port = MagicMock()
        port.__enter__.return_value.read_until.side_effect = read
        client = MagicMock()
        client.publish.return_value.rc = 0
        with patch("serial.Serial", return_value=port), patch("paho.mqtt.client.Client", return_value=client):
            serial_telemetry_bridge_worker("fixture", stop_event=stop)
        self.assertEqual([call.args[0] for call in client.publish.call_args_list],
                         ["edge/telemetry/radio", "edge/telemetry/traffic", "edge/telemetry/window"])
        client.disconnect.assert_called_once()
        client.loop_stop.assert_called_once()

    def test_esp32_dashboard_does_not_start_twin(self) -> None:
        from dashboard.backend import experiment_runtime
        with patch.dict("os.environ", {"AERO_PROBE_MODE": "esp32"}):
            experiment_runtime.start_runtime(MagicMock())
        self.assertIsNone(experiment_runtime.service)


if __name__ == "__main__":
    unittest.main()
