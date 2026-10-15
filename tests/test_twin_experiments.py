"""Twin experiments: attribution and benign local Normal integration only."""
import asyncio
import json
import os
import subprocess
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from digital_twin.experiment_service import TwinExperimentService
from digital_twin.lab.flows import FlowRecorder, packet_label, lab_socket
from digital_twin.lab.http_target import LabRequestHandler
from dashboard.backend.models import ExperimentStartRequest
from dashboard.backend.routers.api import start_experiment
from data_lake.quality import select_training_records
from digital_twin.lab.capture_config import loopback_interface
from firmware.host_probe.tshark_engine import get_available_interfaces


class TwinExperimentTests(unittest.TestCase):
    def test_api_accepts_every_twin_label_not_only_legacy_modes(self) -> None:
        from ml_engine.config.schema import LABEL_NAMES
        service = MagicMock()
        service.start.return_value = {"status": "accepted", "command_id": "test"}
        with patch("dashboard.backend.experiment_runtime.service", service):
            for scenario in LABEL_NAMES:
                result = asyncio.run(start_experiment(ExperimentStartRequest(scenario=scenario, duration_sec=1)))
                self.assertEqual(result["status"], "accepted", scenario)
                service.start.assert_called_with(scenario, 1)

    def test_refused_tcp_lab_connection_keeps_explicit_source(self) -> None:
        recorder = FlowRecorder()
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.bind(("127.0.0.1", 0))  # Bound, deliberately not listening.
        sender = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
        sender.settimeout(1)
        try:
            self.assertNotEqual(sender.connect_ex(target.getsockname()), 0)
            flows = recorder.snapshot()
            self.assertTrue(flows)
            self.assertTrue(all(flow["src_ip"] == "127.0.0.1" and flow["src_port"] > 0 for flow in flows))
        finally:
            sender.close()
            target.close()

    def test_udp_lab_records_actual_loopback_source(self) -> None:
        recorder = FlowRecorder()
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(1)
        sender = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, recorder)
        try:
            sender.sendto(b"N", receiver.getsockname())
            payload, measured_source = receiver.recvfrom(16)
            self.assertEqual(payload, b"N")
            flow = recorder.snapshot()[0]
            self.assertEqual((flow["src_ip"], flow["src_port"]), measured_source)
            packet = {"src_ip": measured_source[0], "src_port": measured_source[1],
                "dst_ip": "127.0.0.1", "dst_port": receiver.getsockname()[1],
                "protocol_stack": "null:ip:udp", "timestamp": flow["started_ms"]}
            self.assertEqual(packet_label(packet, recorder.snapshot(), "DDoS_UDP")["ground_truth_scenario"], "DDoS_UDP")
            self.assertNotIn("label_verified", packet_label(packet, recorder.snapshot(), "DDoS_UDP"))
            self.assertEqual(packet_label({**packet, "protocol_stack": "null:ip:icmp:ip:udp"}, recorder.snapshot(), "DDoS_UDP")["ground_truth_scenario"], "Unknown")
        finally:
            sender.close()
            receiver.close()

    def test_lab_interface_config_does_not_depend_on_twin_override(self) -> None:
        interfaces = [{"index": "8", "device": "physical", "name": "Ethernet"},
                      {"index": "9", "device": "loopback-device", "name": "Loopback"}]
        with patch("digital_twin.lab.capture_config.get_available_interfaces", return_value=interfaces), \
             patch.dict(os.environ, {"TWIN_CAPTURE_INTERFACE": "8"}):
            self.assertEqual(loopback_interface("mock", "auto-loopback"), "loopback-device")
            with self.assertRaises(ValueError):
                loopback_interface("mock", "8")

    def test_interface_discovery_preserves_failure_details(self) -> None:
        failure = subprocess.CalledProcessError(13, ["tshark", "-D"], stderr="dumpcap DLL initialization failed")
        with patch("firmware.host_probe.tshark_engine.subprocess.check_output", side_effect=failure):
            with self.assertRaisesRegex(ValueError, "dumpcap DLL initialization failed"):
                loopback_interface("tshark")
            self.assertEqual(get_available_interfaces("tshark"), [])
        with patch("firmware.host_probe.tshark_engine.subprocess.check_output", side_effect=subprocess.TimeoutExpired("tshark", 15)):
            with self.assertRaisesRegex(ValueError, "timed out after 15"):
                loopback_interface("tshark")

    def test_empty_interface_setting_uses_auto_loopback(self) -> None:
        interfaces = [{"index": "9", "device": "\\Device\\NPF_Loopback", "name": "Loopback"}]
        with patch("digital_twin.lab.capture_config.get_available_interfaces", return_value=interfaces), \
             patch.dict(os.environ, {"TWIN_CAPTURE_INTERFACE": ""}):
            self.assertEqual(loopback_interface("mock"), "\\Device\\NPF_Loopback")

    def test_loopback_selection_is_stable_after_nic_indices_change(self) -> None:
        interfaces = [{"index": "8", "device": "physical", "name": "Ethernet"},
                      {"index": "9", "device": "loopback-device", "name": "Loopback"}]
        with patch("digital_twin.lab.capture_config.get_available_interfaces", return_value=interfaces), \
             patch.dict(os.environ, {"TWIN_CAPTURE_INTERFACE": "auto-loopback"}):
            self.assertEqual(loopback_interface("mock"), "loopback-device")
        with patch("digital_twin.lab.capture_config.get_available_interfaces", return_value=interfaces), \
             patch.dict(os.environ, {"TWIN_CAPTURE_INTERFACE": "8"}):
            with self.assertRaises(ValueError):
                loopback_interface("mock")
    def test_flow_attribution_bidirectional_and_time_bounded(self) -> None:
        flows = [{"src_ip": "127.0.0.1", "src_port": 12345, "dst_ip": "127.0.0.1",
                  "dst_port": 8088, "transport": "tcp", "started_ms": 1000, "ended_ms": 2000, "verified": True}]
        packet = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 8088,
                  "dst_port": 12345, "timestamp": 1500, "protocol_stack": "eth:ip:tcp:http"}
        self.assertEqual(packet_label(packet, flows, "Normal")["label_method"], "automatic_flow")
        self.assertEqual(packet_label(packet, flows, "SQL_injection")["ground_truth_scenario"], "SQL_injection")
        self.assertNotIn("label_verified", packet_label(packet, flows, "SQL_injection"))
        self.assertEqual(packet_label({**packet, "dst_port": 12346}, flows, "Normal")["ground_truth_scenario"], "Unknown")
        self.assertEqual(packet_label({**packet, "timestamp": 2500}, flows, "Normal")["ground_truth_scenario"], "Unknown")
        self.assertEqual(packet_label({**packet, "protocol_stack": "ip:udp"}, flows, "Normal")["ground_truth_scenario"], "Unknown")

    def test_normal_workload_records_response_health_and_real_sockets(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
        worker.start()
        recorder = FlowRecorder()
        service = TwinExperimentService(lambda _: None)
        try:
            service._normal(recorder, 1, server.server_port)
            flows = recorder.snapshot()
            self.assertGreaterEqual(len(flows), 2)
            self.assertTrue(all(flow["response_ok"] for flow in flows))
            self.assertTrue(all(flow["src_port"] > 0 for flow in flows))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_concurrent_experiment_rejected_and_stop_cooperative(self) -> None:
        service = TwinExperimentService(lambda _: None)
        service.worker = MagicMock()
        service.worker.is_alive.return_value = True
        with self.assertRaises(RuntimeError):
            service.start("Normal")
        service.stop()
        self.assertTrue(service.cancel.is_set())

    def test_unsupported_scenario_fails_before_start(self) -> None:
        service = TwinExperimentService(lambda _: None)
        with self.assertRaises(ValueError):
            service.start("not-a-scenario")
        with self.assertRaises(ValueError):
            service.start("Normal", 61)
        self.assertIsNone(service.worker)

    def test_api_start_calls_owned_service_and_reports_busy(self) -> None:
        service = MagicMock()
        service.start.return_value = {"status": "accepted", "command_id": "test"}
        with patch("dashboard.backend.experiment_runtime.service", service):
            result = asyncio.run(start_experiment(ExperimentStartRequest(scenario="Normal", duration_sec=1)))
            self.assertEqual(result["status"], "accepted")
            service.start.assert_called_once_with("Normal", 1)
            service.start.side_effect = RuntimeError("busy")
            self.assertEqual(asyncio.run(start_experiment(ExperimentStartRequest(scenario="Normal"))).status_code, 409)

    def test_native_normal_capture_and_import_opt_in(self) -> None:
        if os.getenv("AERO_TEST_TWIN_CAPTURE") != "1":
            self.skipTest("Set AERO_TEST_TWIN_CAPTURE=1 for bounded native loopback capture")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "TWIN_LAB_BACKEND": "native", "TWIN_CAPTURE_INTERFACE": "auto-loopback", "LAB_HTTP_PORT": "18088"}):
            statuses = []
            service = TwinExperimentService(statuses.append, Path(directory))
            service.start("Normal", 1)
            service.worker.join(45)
            service.close()
            self.assertFalse(service.worker.is_alive())
            self.assertEqual(service.status["phase"], "COMPLETED", service.status)
            self.assertGreater(service.status["labeled_rows"], 0)
            manifest = json.loads(next((Path(directory) / "experiments").glob("*/manifest.json")).read_text())
            self.assertTrue(manifest["capture_sha256"])
            self.assertEqual(manifest["pcap_packets"], manifest["parsed_packets"] + manifest["rejected_packets"])
            from data_lake.lakehouse import DataLakeManager
            frame = DataLakeManager(directory).load_all_training_data()
            accepted, _ = select_training_records(frame)
            self.assertGreater(len(accepted), 0)
            self.assertTrue(accepted.ground_truth_scenario.eq("Normal").all())
            self.assertEqual(len(accepted), service.status["labeled_rows"])
            self.assertNotIn("label_verified", frame)
            from digital_twin.lab.profile import capture_filter
            self.assertEqual(manifest["capture_filter"], capture_filter(18088, "Normal"))
            print("Native Normal capture/import:", {key: service.status[key] for key in (
                "saved_rows", "labeled_rows", "unknown_rows", "parsed_packets", "rejected_packets")})
