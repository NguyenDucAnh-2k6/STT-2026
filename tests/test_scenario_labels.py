"""Offline experiment labels and isolated Parquet tests; never generate attacks."""
import asyncio
import json
import os
import http.client
import threading
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pandas as pd
from data_lake.collector import DataLakeCollector
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records
from data_lake.scenario_context import ScenarioContext
from firmware.simulator.scenarios import require_implemented
from firmware.simulator.lab_config import configured_target, validate_lab_target
from firmware.simulator.attack_traffic_generator import AttackTrafficController, burst_http_load
from firmware.simulator.lab_http_service import LabRequestHandler
from http.server import ThreadingHTTPServer
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES

NOW = 1_800_000_000_000


def status(scenario: str = "SQL_injection", timestamp: int = NOW) -> dict:
    return {"status": "ATTACKING", "scenario": scenario, "timestamp": timestamp,
            "expires_at_ms": timestamp + 60_000, "experiment_id": "experiment-test",
            "target_ip": "127.0.0.1", "implementation_status": "traffic_pattern_unverified"}


def packet(timestamp: int = NOW + 1000) -> dict:
    return {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "device_id": "probe-test",
            "timestamp": timestamp, "timestamp_kind": "epoch_ms", "packet_id": f"test:{timestamp}",
            "schema_version": 2, "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1",
            "missing_features": [], "capture_backend": "tshark", "dst_ip": "127.0.0.1",
            "label_verified": False, "label_source": "unverified", "ground_truth_scenario": "Unknown"}


class ScenarioLabelTests(unittest.TestCase):
    def test_both_subscriptions_acknowledged(self) -> None:
        collector = DataLakeCollector(lake_manager=MagicMock())
        client = MagicMock()
        client.subscribe.side_effect = [(0, 1), (0, 2)]
        collector._on_connect(client, None, None, 0)
        collector._on_subscribe(client, None, 1, [])
        self.assertFalse(collector._subscribed.is_set())
        collector._on_subscribe(client, None, 2, [])
        self.assertTrue(collector._subscribed.is_set())
        client.subscribe.side_effect = [(0, 3), (4, 4)]
        collector._on_connect(client, None, None, 0)
        collector._on_subscribe(client, None, 3, [])
        self.assertFalse(collector._subscribed.is_set())

    def test_local_http_endpoint_with_benign_requests(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        worker.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertFalse(body["executes_injected_content"])
            connection.request("POST", "/upload", body=b"benign test bytes")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["path"], "/upload")
        finally:
            connection.close()
            server.shutdown()
            worker.join(timeout=2)
            server.server_close()
        self.assertFalse(worker.is_alive())

    def test_context_does_not_become_training_truth(self) -> None:
        context = ScenarioContext()
        context.update(status())
        row = packet() | context.annotate(packet())
        self.assertEqual(row["requested_attack_label"], "SQL_injection")
        self.assertTrue(row["scenario_target_match"])
        self.assertFalse(row["scenario_label_verified"])
        self.assertEqual(len(select_training_records(pd.DataFrame([row]))[0]), 0)

    def test_stop_expiry_and_capture_timestamp(self) -> None:
        context = ScenarioContext()
        context.update(status())
        self.assertEqual(context.annotate(packet(NOW - 1))["requested_attack_label"], "Unknown")
        self.assertEqual(context.annotate(packet(NOW + 60_001))["requested_attack_label"], "Unknown")
        context.update(status(timestamp=NOW + 2000) | {"status": "IDLE"})
        self.assertEqual(context.annotate(packet(NOW + 3000))["requested_attack_label"], "Unknown")
        self.assertEqual(context.annotate(packet(NOW + 1500))["requested_attack_label"], "SQL_injection")
        self.assertEqual(context.annotate(packet() | {"timestamp_kind": "uptime_ms"})["requested_attack_label"], "Unknown")

    def test_ordering_and_bounded_history(self) -> None:
        context = ScenarioContext()
        context.update(status("DDoS_UDP", NOW + 1000))
        context.update(status("Port_Scanning", NOW))
        self.assertEqual(context.annotate(packet())["requested_attack_label"], "DDoS_UDP")
        for index in range(200):
            context.update(status(timestamp=NOW + index))
        self.assertEqual(len(context.events), 128)

    def test_aliases_and_unsupported_never_activate(self) -> None:
        self.assertEqual(require_implemented("SQL_Injection"), "SQL_injection")
        self.assertEqual(require_implemented("XSS_Attack"), "XSS")
        with patch.dict(os.environ, {"LAB_ALLOWED_TARGETS": "127.0.0.1/32"}):
            controller = AttackTrafficController("127.0.0.1")
        controller.mqtt_client = MagicMock()
        controller.set_scenario("MITM")
        self.assertFalse(controller.is_attacking)
        event = json.loads(controller.mqtt_client.publish.call_args.args[1])
        self.assertEqual(event["status"], "UNSUPPORTED")
        self.assertFalse(event["label_verified"])
        controller.set_scenario("SQL_Injection")
        self.assertEqual(controller.current_scenario, "SQL_injection")
        self.assertIsNotNone(controller.experiment_id)

    def test_explicit_targets_only(self) -> None:
        with patch.dict(os.environ, {"LAB_TARGET_IP": "127.0.0.1", "LAB_ALLOWED_TARGETS": "127.0.0.1/32"}, clear=True):
            self.assertEqual(configured_target(), "127.0.0.1")
            with self.assertRaises(ValueError):
                validate_lab_target("192.0.2.1")
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            configured_target()

    def test_http_workload_mocked(self) -> None:
        with patch.dict(os.environ, {"LAB_ALLOWED_TARGETS": "127.0.0.1/32"}), \
                patch("firmware.simulator.attack_traffic_generator.http.client.HTTPConnection") as constructor:
            self.assertEqual(burst_http_load("127.0.0.1", 8088, count=2), 2)
            self.assertEqual(constructor.return_value.close.call_count, 2)

    def test_context_persisted_in_real_parquet(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            lake = DataLakeManager(folder)
            collector = DataLakeCollector(lake_manager=lake)
            collector._on_message(None, None, SimpleNamespace(topic="edge/attack/status", payload=json.dumps(status()).encode()))
            collector._on_message(None, None, SimpleNamespace(topic="edge/telemetry/traffic", payload=json.dumps(packet()).encode()))
            lake.close_session()
            frame = pd.read_parquet(next(Path(folder).glob("raw/**/*.parquet")))
            self.assertEqual(frame.iloc[0].requested_attack_label, "SQL_injection")
            self.assertEqual(frame.iloc[0].experiment_id, "experiment-test")
            self.assertEqual(frame.iloc[0].ground_truth_scenario, "Unknown")
            self.assertEqual(len(select_training_records(frame)[0]), 0)

    def test_late_status_refreshes_buffer_without_changing_truth(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            lake = DataLakeManager(folder)
            collector = DataLakeCollector(lake_manager=lake)
            collector._on_message(None, None, SimpleNamespace(topic="edge/telemetry/traffic", payload=json.dumps(packet()).encode()))
            self.assertEqual(lake.buffer[0]["requested_attack_label"], "Unknown")
            collector._on_message(None, None, SimpleNamespace(topic="edge/attack/status", payload=json.dumps(status()).encode()))
            self.assertEqual(lake.buffer[0]["requested_attack_label"], "SQL_injection")
            self.assertEqual(lake.buffer[0]["ground_truth_scenario"], "Unknown")
            self.assertFalse(lake.buffer[0]["label_verified"])
            lake.close_session()

    def test_api_unsupported_and_publish_failure(self) -> None:
        from dashboard.backend.routers.api import trigger_attack
        from dashboard.backend.models import AttackTriggerRequest
        with patch("dashboard.backend.routers.api.mqtt_client") as client:
            response = asyncio.run(trigger_attack(AttackTriggerRequest(attack_type="MITM")))
            self.assertEqual(response.status_code, 422)
            client.publish.assert_not_called()
            client.publish.return_value.rc = 4
            response = asyncio.run(trigger_attack(AttackTriggerRequest(attack_type="DDoS_HTTP")))
            self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
