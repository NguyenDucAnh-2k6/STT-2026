"""Throughput belongs to windows, independent of unavailable packet inference."""
import asyncio
import json
import unittest
import queue
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dashboard.backend import mqtt_bridge as bridge
from dashboard.backend.state import SystemState
from firmware.host_probe.tshark_engine import select_best_interfaces
from firmware.host_probe.host_sniffer import WindowStats
from firmware.host_probe.packet_runtime import publish_packet_queue


class DashboardWindowTests(unittest.IsolatedAsyncioTestCase):
    async def test_window_survives_packet_prediction_and_duplicate_counts(self) -> None:
        state = SystemState()
        broadcast = AsyncMock()
        loop = asyncio.get_running_loop()
        window = {"device_id": "fixture", "capture_id": "capture", "captured_packets": 1000,
                  "record_kind": "window", "packet_rate": 200.0, "byte_rate": 102400.0}
        packet = {"device_id": "fixture", "inference_status": "unavailable", "anomaly_score": None,
                  "raw_telemetry": {"record_kind": "packet", "frame_length": 128,
                                    "timestamp": 1800000000000, "tcp.srcport": 1234, "tcp.dstport": 443}}
        with patch.object(bridge, "state", state), patch.object(bridge.manager, "broadcast", broadcast), \
             patch.dict(bridge.loop_holder, {"loop": loop}, clear=True):
            message = SimpleNamespace(topic="edge/telemetry/window", payload=json.dumps(window).encode())
            bridge.on_mqtt_message(None, None, message)
            self.assertIsNone(state.latest_traffic_window)  # Owning event loop applies it later.
            await asyncio.sleep(0.02)
            bridge.process_mqtt_payload("edge/telemetry/prediction", packet)
            bridge.process_mqtt_payload("edge/telemetry/prediction", packet)
            bridge.process_mqtt_payload("edge/telemetry/window", window)
            await asyncio.sleep(0.02)
            self.assertEqual(state.total_packets_inspected, 1000)
            self.assertEqual(state.latest_traffic_window["packet_rate"], 200)
            self.assertEqual(len(state.telemetry_history), 1)
            self.assertNotIn("packet_rate", state.telemetry_history[0])
            self.assertNotIn("byte_rate", state.telemetry_history[0])
            self.assertIsNone(state.current_anomaly_score)
            events = [call.args[0] for call in broadcast.await_args_list]
            self.assertTrue(any(event["type"] == "TRAFFIC_WINDOW_UPDATE" for event in events))

    async def test_invalid_window_does_not_become_zero(self) -> None:
        state = SystemState()
        with patch.object(bridge, "state", state), patch.dict(bridge.loop_holder, {"loop": asyncio.get_running_loop()}, clear=True):
            bridge.process_mqtt_payload("edge/telemetry/window", {"packet_rate": float("nan"), "byte_rate": 3})
            self.assertIsNone(state.latest_traffic_window)

    def test_auto_interface_selection_never_adds_loopback(self) -> None:
        interfaces = [{"index": "1", "device": "loopback", "name": "Loopback"},
                      {"index": "2", "device": "fixture", "name": "Wi-Fi"}]
        with patch.dict("os.environ", {"HOST_CAPTURE_INTERFACES": ""}), \
             patch("firmware.host_probe.tshark_engine.active_adapter_ids", return_value={"wi-fi"}):
            self.assertEqual(select_best_interfaces(interfaces), ["fixture"])
        with patch.dict("os.environ", {"HOST_CAPTURE_INTERFACES": "1"}):
            self.assertEqual(select_best_interfaces(interfaces), ["loopback"])

    def test_window_counts_use_actual_duration_and_reset(self) -> None:
        stats = WindowStats()
        for _ in range(4):
            stats.add_packet(proto=6, size=128)
        first = stats.snapshot_and_reset(2.0)
        self.assertEqual(first["packet_rate"], 2)
        self.assertEqual(first["byte_rate"], 256)
        self.assertEqual(stats.snapshot_and_reset(1.0)["packet_rate"], 0)

    def test_packet_publisher_pipelines_acknowledgments(self) -> None:
        sent = []
        client = SimpleNamespace(publish=lambda *args, **kwargs: (
            sent.append(args) or SimpleNamespace(rc=0, is_published=lambda: len(sent) >= 3)))
        packets = queue.Queue()
        for index in range(3):
            packets.put({"packet_id": str(index)})
        stop = threading.Event()
        stop.set()
        counters = {"published": 0, "failed": 0, "dropped": 0}
        publish_packet_queue(client, packets, stop, counters)
        self.assertEqual(counters, {"published": 3, "failed": 0, "dropped": 0})
