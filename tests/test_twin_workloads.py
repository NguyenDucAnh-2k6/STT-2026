"""Disposable local fixture tests; no real victim, host files or external targets."""
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from data_lake.lakehouse import DataLakeManager
from data_lake.quality import TRAINING_REQUIRED_COLUMNS
from digital_twin.lab.fixture_app import FixtureState, query_fixture
from digital_twin.lab.flows import FlowRecorder, packet_label
from digital_twin.lab.profile import capture_filter, scenario_metadata
from digital_twin.lab.raw_packets import syn_packet, checksum, require_raw_capability
from digital_twin.lab.services import LabServices
from digital_twin.lab.workloads import TwinWorkloads
from firmware.simulator.lab_config import allow_twin_loopback, validate_lab_target
from firmware.simulator.scenarios import require_twin_scenario
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES, LABEL_NAMES


class TwinWorkloadTests(unittest.TestCase):
    def test_loopback_allowlist_does_not_allow_external_addresses(self) -> None:
        with patch.dict(os.environ, {"LAB_ALLOWED_TARGETS": "192.0.2.10/32"}):
            value = allow_twin_loopback()
            self.assertEqual(value, "192.0.2.10/32,127.0.0.1/32")
            self.assertEqual(allow_twin_loopback(), value)
            self.assertEqual(validate_lab_target("127.0.0.1"), "127.0.0.1")
            with self.assertRaises(ValueError):
                validate_lab_target("198.51.100.1")

    def test_all_benchmark_modes_registered_and_surrogates_explicit(self) -> None:
        for name in LABEL_NAMES:
            self.assertEqual(require_twin_scenario(name), name)
        for name in ["MITM", "Backdoor", "Ransomware", "Fingerprinting"]:
            self.assertFalse(scenario_metadata(name)["supervised_training_eligible"])
        self.assertTrue(scenario_metadata("Port_Scanning")["supervised_training_eligible"])

    def test_sqlite_injection_changes_only_disposable_read_query(self) -> None:
        self.assertEqual(query_fixture("missing")["result_count"], 0)
        self.assertEqual(query_fixture("missing' OR 1=1 -- ")["result_count"], 3)
        self.assertTrue(query_fixture("'; DROP TABLE items; --")["database_error"])
        self.assertEqual(query_fixture("alpha")["result_count"], 1)

    def test_fixture_actions_never_execute_shell_or_touch_user_files(self) -> None:
        fixture = FixtureState()
        self.assertFalse(fixture.action("/lab/channel", {"action": "exec"}, b"")["accepted"])
        self.assertFalse(fixture.action("/lab/channel", {"action": "status"}, b"")["shell_execution"])
        encrypted = fixture.action("/lab/encrypt-fixture", {}, b"")
        self.assertTrue(encrypted["roundtrip_ok"])
        self.assertFalse(encrypted["host_files_touched"])
        self.assertTrue(fixture.action("/lab/login", {"username": "lab-user", "password": "lab-password"}, b"")["authenticated"])

    def test_syn_packet_is_real_syn_checksum_and_windows_not_fake_connect(self) -> None:
        packet = syn_packet(35000, 8088, 100)
        self.assertEqual(len(packet), 40)
        self.assertEqual(checksum(packet[:20]), 0)
        self.assertEqual(packet[33], 2)
        pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, 20)
        self.assertEqual(checksum(pseudo+packet[20:]), 0)
        with patch("digital_twin.lab.raw_packets.sys.platform", "win32"):
            with self.assertRaisesRegex(ValueError, "Linux"):
                require_raw_capability("DDoS_TCP")

    def test_icmp_label_requires_echo_id_type_and_time(self) -> None:
        flow = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 12,
                "dst_port": 12, "transport": "icmp", "started_ms": 1000, "ended_ms": 2000}
        packet = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "timestamp": 1500,
                  "protocol_stack": "null:ip:icmp", "icmp_identifier": 12, "icmp_type": 8}
        self.assertEqual(packet_label(packet, [flow], "DDoS_ICMP")["ground_truth_scenario"], "DDoS_ICMP")
        for change in [{"icmp_identifier": 13}, {"icmp_type": 3}, {"timestamp": 3000}]:
            self.assertEqual(packet_label(packet | change, [flow], "DDoS_ICMP")["ground_truth_scenario"], "Unknown")

    def test_surrogate_gate_cannot_be_bypassed_by_projected_read(self) -> None:
        row = {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1", "schema_version": 2,
               "device_id": "test", "packet_id": "1", "timestamp": 1800000000000, "capture_backend": "pcap", "label_source": "controlled_flow",
               "ground_truth_scenario": "MITM", "missing_features": [], "supervised_training_eligible": False}
        with tempfile.TemporaryDirectory() as directory:
            lake = DataLakeManager(directory)
            pd.DataFrame([row]).to_parquet(Path(lake.raw_dir)/"fixture.parquet")
            self.assertTrue(lake.load_labeled_dataset(columns=TRAINING_REQUIRED_COLUMNS).empty)
            self.assertEqual(lake.last_training_report["reasons"]["scenario_not_training_eligible"], 1)
            row.update(supervised_training_eligible=True, data_provenance="twin-controlled-lab", experiment_manifest_version=2)
            pd.DataFrame([row]).to_parquet(Path(lake.raw_dir)/"fixture.parquet")
            self.assertTrue(lake.load_labeled_dataset(columns=TRAINING_REQUIRED_COLUMNS).empty)
            self.assertEqual(lake.last_training_report["reasons"]["legacy_twin_attack_requires_recollection"], 1)
            row.update(label_source="manual_review", data_provenance=None, ground_truth_scenario="SQL_injection")
            field = pd.DataFrame([row])
            field["data_provenance"] = field["data_provenance"].astype("string")
            field.to_parquet(Path(lake.raw_dir)/"fixture.parquet")
            self.assertEqual(len(lake.load_labeled_dataset(columns=TRAINING_REQUIRED_COLUMNS)), 1)

    def test_owned_ports_scan_open_closed_and_http_modes_complete(self) -> None:
        server = None
        with patch.dict(os.environ, {"TWIN_SCAN_PORT_COUNT": "3"}):
            for port in range(22088, 22288, 3):
                candidate = LabServices(port, set(), dns_proxy=True)
                try:
                    candidate.start()
                    server = candidate
                    break
                except RuntimeError:
                    continue
            self.assertIsNotNone(server)
            recorder = FlowRecorder()
            runner = TwinWorkloads(server.port, recorder, threading.Event(), 42)
            try:
                runner.burst("Port_Scanning")
                self.assertEqual({f["dst_port"] for f in recorder.snapshot()}, set(range(server.port, server.port+3)))
                for name in ["SQL_injection", "XSS", "DDoS_HTTP", "Vulnerability_scanner", "Uploading", "Password"]:
                    self.assertGreater(runner.burst(name), 0, name)
                runner.burst("DDoS_UDP")
                self.assertTrue(any(f["transport"] == "udp" for f in recorder.snapshot()))
                self.assertIn("tcp portrange", capture_filter(server.port, "Port_Scanning"))
            finally:
                server.close()
