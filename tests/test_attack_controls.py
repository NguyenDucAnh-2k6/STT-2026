"""Control regressions with mocked sockets/MQTT; never send attack traffic."""
import asyncio
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from data_lake.lakehouse import DataLakeManager
from firmware.simulator.attack_traffic_generator import AttackTrafficController, burst_uploading, burst_sql_injection

class AttackControlTests(unittest.TestCase):
    def controller(self) -> AttackTrafficController:
        with patch.dict("os.environ", {"LAB_ALLOWED_TARGETS": "127.0.0.1/32"}):
            controller = AttackTrafficController("127.0.0.1")
        controller.mqtt_client = MagicMock()
        return controller

    def command(self, controller: AttackTrafficController, command: str, **fields) -> None:
        controller.on_mqtt_message(None, None, SimpleNamespace(
            topic="edge/attack/control", retain=False,
            payload=json.dumps({"command": command, **fields}).encode()))

    def test_deleted_raw_and_partial_batches_do_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lake = DataLakeManager(directory)
            lake.record_telemetry({"timestamp": 1}, "Normal")
            lake.flush()
            lake.record_telemetry({"timestamp": 2})
            self.assertEqual(lake.get_summary_stats()["buffered_records"], 1)
            lake.flush()
            files = sorted(Path(lake.raw_dir).rglob("*.parquet"))
            self.assertEqual(lake.get_summary_stats()["total_records"], 2)
            files[0].unlink()
            stats = lake.get_summary_stats()
            self.assertEqual(stats["total_records"], 1)
            self.assertEqual(stats["normal_records"], 0)
            shutil.rmtree(lake.raw_dir)
            self.assertEqual(lake.get_summary_stats()["total_records"], 0)
            lake.record_telemetry({"timestamp": 3})
            lake.flush()
            self.assertEqual(lake.get_summary_stats()["total_records"], 1)

    def test_manual_command_cancels_old_burst_and_auto_cycle(self) -> None:
        controller = self.controller()
        controller.set_scenario("Uploading")
        old = controller.cancel_event
        controller.auto_cycle = True
        self.command(controller, "TRIGGER", mode="SQL_Injection", command_id="manual")
        self.assertTrue(old.is_set())
        self.assertFalse(controller.auto_cycle)
        self.assertTrue(controller.cycle_wakeup.is_set())
        self.assertEqual(controller.current_scenario, "SQL_injection")
        experiment = controller.experiment_id
        self.command(controller, "TRIGGER", mode="SQL_Injection", command_id="manual")
        self.assertEqual(controller.experiment_id, experiment)
        event = json.loads(controller.mqtt_client.publish.call_args.args[1])
        self.assertEqual(event["command_id"], "manual")
        active = controller.cancel_event
        self.command(controller, "STOP", command_id="stop")
        self.assertTrue(active.is_set())
        self.assertFalse(controller.is_attacking)

    def test_auto_cycle_does_not_override_manual_choice_after_wakeup(self) -> None:
        controller = self.controller()
        controller.auto_cycle = True
        started = threading.Event()
        real_set = controller.set_scenario
        def observed_set(scenario: str) -> None:
            real_set(scenario)
            started.set()
        controller.set_scenario = observed_set
        worker = threading.Thread(target=controller.auto_cycle_worker)
        worker.start()
        try:
            self.assertTrue(started.wait(2))
            self.command(controller, "TRIGGER", mode="XSS", command_id="xss")
            self.assertEqual(controller.current_scenario, "XSS")
            self.assertFalse(controller.auto_cycle)
        finally:
            controller.running = False
            controller.cycle_wakeup.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(controller.current_scenario, "XSS")

    def test_every_scenario_dispatches_only_its_own_function(self) -> None:
        scenarios = {"Uploading": "burst_uploading", "SQL_injection": "burst_sql_injection",
            "XSS": "burst_xss_attack", "DDoS_HTTP": "burst_http_load", "DDoS_UDP": "burst_udp_flood",
            "DDoS_TCP": "burst_tcp_syn_flood", "Port_Scanning": "burst_port_scan",
            "Vulnerability_scanner": "burst_vulnerability_scan", "Adversarial": "burst_adversarial_evasion"}
        for scenario, expected in scenarios.items():
            with self.subTest(scenario=scenario):
                controller = self.controller()
                controller.set_scenario(scenario)
                mocks = {name: MagicMock(return_value=1) for name in scenarios.values()}
                def finish(*args, **kwargs):
                    controller.running = False
                    kwargs["cancel_event"].set()
                    return 1
                mocks[expected].side_effect = finish
                with patch.multiple("firmware.simulator.attack_traffic_generator", **mocks):
                    controller.attack_worker_loop()
                mocks[expected].assert_called_once()
                for name, mock in mocks.items():
                    if name != expected:
                        mock.assert_not_called()

    def test_cancelled_bursts_do_not_send_or_connect(self) -> None:
        event = threading.Event()
        event.set()
        with patch("firmware.simulator.attack_traffic_generator.socket.socket") as socket:
            self.assertEqual(burst_uploading("127.0.0.1", cancel_event=event), 0)
            self.assertEqual(burst_sql_injection("127.0.0.1", cancel_event=event), 0)
            socket.return_value.sendto.assert_not_called()
            socket.return_value.connect.assert_not_called()

    def test_stop_and_cycle_publish_failure_is_reported(self) -> None:
        from dashboard.backend.routers.api import stop_attack, toggle_auto_cycle
        from dashboard.backend.models import AutoCycleRequest
        with patch("dashboard.backend.routers.api.mqtt_client") as client:
            client.publish.return_value.rc = 4
            self.assertEqual(asyncio.run(stop_attack()).status_code, 503)
            self.assertEqual(asyncio.run(toggle_auto_cycle(AutoCycleRequest(enabled=False))).status_code, 503)
            self.assertEqual(client.publish.call_args.kwargs, {"qos": 1, "retain": False})

    def test_retained_commands_are_ignored(self) -> None:
        controller = self.controller()
        controller.on_mqtt_message(None, None, SimpleNamespace(topic="edge/attack/control", retain=True,
            payload=b'{"command":"TRIGGER","mode":"Uploading"}'))
        self.assertFalse(controller.is_attacking)
