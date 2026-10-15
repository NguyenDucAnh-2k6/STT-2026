"""Offline native TShark/Mosquitto tests. No live capture or real traffic generation."""
import csv
import io
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import paho.mqtt.client as mqtt
from broker.manager import find_mosquitto_executable
from data_lake.collector import DataLakeCollector
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records
from firmware.host_probe.packet_capture import FIELDS, PacketTSharkEngine, parse_packet, field_registry
from firmware.host_probe.tshark_engine import find_tshark_path
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import CATEGORICAL_FEATURES, invalid_feature_counts
from ml_engine.preprocessing import EdgeTrafficPreprocessor


def write_fixture(path: Path) -> None:
    def ip_packet(proto: int, body: bytes) -> bytes:
        ethernet = bytes.fromhex("00112233445566778899aabb0800")
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0,
                         socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
        return ethernet + ip + body

    dns = struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0) + b"\x07example\x04test\x00\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    syn = struct.pack("!HHLLBBHHH", 40000, 80, 100, 0, 0x50, 2, 4096, 0, 0)
    http = b'GET /test?q=%22hello%22 HTTP/1.1\r\nHost: example.test\r\nReferer: http://example.test/a|b\r\n\r\n'
    tcp = struct.pack("!HHLLBBHHH", 40000, 80, 101, 1, 0x50, 0x18, 4096, 0, 0) + http
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate([ip_packet(17, udp), ip_packet(6, syn), ip_packet(6, tcp)]):
            handle.write(struct.pack("<IIII", 1_800_000_000, index * 100000, len(packet), len(packet)))
            handle.write(packet)


class HostPacketTests(unittest.TestCase):
    def test_twin_live_inference_filter_targets_service(self) -> None:
        interfaces = [{"index": "9", "device": "loopback", "name": "Loopback"}]
        with patch("firmware.host_probe.packet_capture.get_available_interfaces", return_value=interfaces), \
             patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "9", "HOST_TWIN_SERVICE_PORT": "8088"}):
            engine = PacketTSharkEngine(MagicMock(), MagicMock(), tshark_path="mock")
            command = engine.build_command()
            capture_filter = command[command.index("-f")+1]
            self.assertIn("tcp portrange 8088-8099", capture_filter)
            self.assertIn("udp port 8088", capture_filter)
            self.assertIn("not ((tcp port", capture_filter)
    def test_quoted_fields_and_malformed_input(self) -> None:
        raw = {name: "" for name in FIELDS}
        raw.update({"frame.number": "1", "frame.time_epoch": "1800000000.1",
                    "frame.len": "64", "frame.cap_len": "64", "tcp.flags": "0x0002",
                    "tcp.payload": "000123", "http.referer": 'quote"|tab\\ttext',
                    "tcp.connection.syn": "1", "mqtt.msg_decoded_as": "Text"})
        types = dict.fromkeys(EDGE_IIOTSET_FEATURES, "FT_UINT32")
        types["tcp.connection.syn"] = "FT_NONE"
        buffer = io.StringIO()
        csv.writer(buffer, delimiter="\t").writerow([raw[name] for name in FIELDS])
        row = parse_packet(buffer.getvalue(), types, "capture", "fixture")
        self.assertEqual(row["http.referer"], 'quote"|tab\ttext')
        self.assertEqual(row["tcp.payload"], "000123")
        self.assertEqual(row["tcp.flags"], 2)
        self.assertEqual(row["mqtt.msg_decoded_as"], "Text")
        self.assertEqual(row["mqtt.msgtype"], 0)
        self.assertEqual(row["missing_features"], [])
        self.assertFalse(row["label_verified"])
        with self.assertRaises(ValueError):
            parse_packet("too\tfew\n", types, "capture", "fixture")

    def test_live_filter_and_required_capture(self) -> None:
        engine = PacketTSharkEngine(MagicMock(), MagicMock(), broker_port=2883,
                                    tshark_path="mock-tshark")
        engine.pcap_path = None
        with patch("firmware.host_probe.packet_capture.get_available_interfaces", return_value=[]), \
             patch("firmware.host_probe.packet_capture.select_best_interfaces", return_value=["2"]):
            command = engine.build_command()
        capture_filter = command[command.index("-f") + 1]
        self.assertIn("tcp port 2883 and (host 127.0.0.1)", capture_filter)
        self.assertIn("tcp src port 8000", capture_filter)
        self.assertIn("tcp dst port 8000", capture_filter)
        self.assertNotIn("-2", command)
        self.assertEqual(command.count("-e"), len(FIELDS))
        engine.tshark_path = None
        with self.assertRaises(RuntimeError):
            engine.start()

    @unittest.skipUnless(find_tshark_path(), "native TShark unavailable")
    def test_native_pcap_features_mqtt_parquet(self) -> None:
        executable = find_mosquitto_executable()
        if not executable:
            self.skipTest("native Mosquitto unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root / "fixture.pcap")
            rows = []
            engine = PacketTSharkEngine(MagicMock(), rows.append, pcap_path=str(root / "fixture.pcap"))
            try:
                engine.start()
                self.assertTrue(engine.completed.wait(10))
                self.assertIsNone(engine.error)
            finally:
                engine.stop()
            self.assertEqual(len(rows), 3)
            self.assertEqual(len(set(row["packet_id"] for row in rows)), 3)
            self.assertEqual(rows[0]["dns.qry.name"], "example.test")
            self.assertEqual(rows[0]["udp.port"], 53000)
            self.assertEqual(rows[1]["tcp.connection.syn"], 1)
            self.assertEqual(rows[2]["http.request.method"], "GET")
            self.assertEqual(rows[2]["http.referer"], "http://example.test/a|b")
            self.assertTrue(rows[2]["raw_tcp_payload_text"].startswith("GET /test?q=%22hello%22 HTTP/1.1"))
            self.assertIn("%22hello%22", rows[2]["raw_http_query"])
            self.assertTrue(rows[2]["raw_packet_info"])
            self.assertFalse(invalid_feature_counts(pd.DataFrame(rows)))
            self.assertTrue(all(row["missing_features"] == [] for row in rows))
            frame = pd.DataFrame(rows)[EDGE_IIOTSET_FEATURES]
            processor = EdgeTrafficPreprocessor().fit(frame, pd.Series(["Normal"] * len(frame)))
            for index, row in enumerate(rows):
                self.assertEqual(processor.transform(processor.extract_features(row)).tolist(),
                                 processor.transform(frame.iloc[[index]]).tolist())
            # Cross-check every extracted field against native, quoted TShark output.
            command = engine.build_command()
            native = subprocess.check_output(command, text=True, encoding="utf-8")
            types = field_registry(engine.tshark_path)
            expected = [parse_packet(line, types, engine.capture_id, engine.version, True)
                        for line in native.splitlines()]
            for actual, reference in zip(rows, expected):
                self.assertEqual({name: actual[name] for name in EDGE_IIOTSET_FEATURES},
                                 {name: reference[name] for name in EDGE_IIOTSET_FEATURES})

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            (root / "mosquitto.conf").write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n", encoding="utf-8")
            broker = subprocess.Popen([executable, "-c", str(root / "mosquitto.conf")],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            lake = DataLakeManager(str(root / "lake"))
            collector = DataLakeCollector(broker_port=port, lake_manager=lake, buffer_size=100)
            publisher = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="offline-test-publisher")
            started = False
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail("isolated Mosquitto did not start")
                        time.sleep(.05)
                collector.start()
                started = True
                publisher.connect("127.0.0.1", port)
                publisher.loop_start()
                # Same millisecond is deliberately shared: dedup must use packet ID.
                rows[1]["timestamp"] = rows[0]["timestamp"]
                for row in [*rows, rows[0]]:
                    info = publisher.publish("edge/telemetry/traffic", json.dumps(row), qos=1)
                    info.wait_for_publish(timeout=3)
                    self.assertTrue(info.is_published())
                deadline = time.monotonic() + 5
                while len(lake.buffer) < 3 and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertEqual(len(lake.buffer), 3)
            finally:
                publisher.disconnect()
                publisher.loop_stop()
                if started:
                    collector.stop()
                broker.terminate()
                broker.wait(timeout=5)
            stored = lake.load_all_training_data()
            self.assertEqual(len(stored), 3)
            self.assertTrue(stored.ground_truth_scenario.eq("Unknown").all())
            self.assertEqual(lake.get_summary_stats()["unknown_records"], 3)
            self.assertEqual(lake.get_summary_stats()["recent_sessions"][0]["attack_scenario"], "Unknown")
            self.assertTrue(lake.load_labeled_dataset().empty)
            for original, saved in zip(rows, stored.to_dict("records")):
                for name in EDGE_IIOTSET_FEATURES:
                    self.assertEqual(original[name], saved[name])
                for name in ("raw_tcp_payload_hex", "raw_tcp_payload_text", "raw_http_query", "raw_http_body", "raw_mqtt_message", "raw_packet_info"):
                    if original[name] is None:
                        self.assertTrue(pd.isna(saved[name]))
                    else:
                        self.assertEqual(original[name], saved[name])
            stored["label_verified"] = True
            stored["label_source"] = "manual_review"
            stored["ground_truth_scenario"] = "Normal"
            eligible, _ = select_training_records(stored)
            self.assertEqual(len(eligible), 3)


if __name__ == "__main__":
    unittest.main()
