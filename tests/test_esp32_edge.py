"""Native C++ parity, protocol bounds and device-decision routing; no hardware/network."""
import json
import asyncio
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import AsyncMock
from types import SimpleNamespace

import numpy as np
from firmware.esp32_probe.radio_capture import parse_radio_sample
from firmware.host_probe.packet_capture import PacketTSharkEngine
from firmware.host_probe.tshark_engine import find_tshark_path
from ml_engine.edge.prediction import edge_prediction, radio_prediction_input
from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, ESP32_PACKET_PROFILE
from ml_engine.config.schema import LABEL_NAMES
from test_esp32_radio import radio_payload

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / ".esp32_validation_env/native/esp32_packet_parity.exe"


def edge_payload() -> dict:
    return radio_payload() | {"edge_input_profile": ESP32_PACKET_PROFILE, "edge_model_version": "a" * 32,
        "edge_inference_status": "ok", "edge_features_count": len(ESP32_PACKET_FEATURES),
        "edge_anomaly_score": .2, "edge_threshold": .8, "edge_confidence": .7,
        "edge_prediction": "Normal", "edge_flag": False, "edge_latency_ms": .5,
        "edge_class_probabilities": {name: .7 if name == "Normal" else .3 if name == "DDoS_TCP" else 0 for name in LABEL_NAMES},
        "edge_raw_features": {name: 0 for name in ESP32_PACKET_FEATURES}}


class ESP32EdgeTests(unittest.TestCase):
    def test_native_edge_result_preserved(self) -> None:
        sample = parse_radio_sample(edge_payload(), 1_800_000_000_000)
        packet = radio_prediction_input(sample)
        result = edge_prediction(packet)
        self.assertEqual(result["inference_status"], "ok")
        self.assertEqual(result["inference_source"], "esp32")
        self.assertEqual(result["host_classifier"], "not_used")
        self.assertEqual(result["latency_ms"], .5)
        self.assertEqual(result["class_probabilities"]["Normal"], .7)
        self.assertEqual(packet["capture_backend"], "esp32_native")
        self.assertEqual(len(packet["missing_features"]), 46)
        self.assertEqual(result["edge_threshold"], .8)
        self.assertFalse(packet["supervised_training_eligible"])

    def test_invalid_probabilities_and_decisions_are_unknown(self) -> None:
        packet = radio_prediction_input(parse_radio_sample(edge_payload(), 1_800_000_000_000))
        for changes in [{"edge_confidence": float("nan")}, {"edge_flag": True},
            {"edge_prediction": "DDoS_TCP"}, {"edge_model_version": ""}, {"radio_protected": True},
            {"edge_class_probabilities": {"Normal": 1}}, {"tcp.flags": None}]:
            result = edge_prediction(packet | changes)
            self.assertEqual(result["inference_status"], "unavailable")
            self.assertIsNone(result["is_anomaly"])

    def test_classifier_normal_with_high_anomaly_is_zero_day(self) -> None:
        payload = edge_payload() | {"edge_anomaly_score": .9, "edge_flag": True, "edge_prediction": "ZeroDay_Anomaly"}
        result = edge_prediction(radio_prediction_input(parse_radio_sample(payload, 1_800_000_000_000)))
        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["threat_type"], "ZeroDay_Anomaly")

    def test_mqtt_edge_mode_never_loads_host_models_and_deduplicates(self) -> None:
        from ml_engine.inference_service import start_mqtt_inference_service
        client = MagicMock()
        client.publish.return_value.rc = 0
        message = SimpleNamespace(topic="edge/telemetry/radio", retain=False, payload=json.dumps(edge_payload()).encode())
        def run() -> None:
            client.on_message(client, None, message)
            client.on_message(client, None, message)
        client.loop_forever.side_effect = run
        with patch.dict("os.environ", {"AERO_PROBE_MODE": "esp32"}), \
             patch("ml_engine.inference_service.AnomalyInferenceEngine") as host_engine, \
             patch("ml_engine.inference_service.mqtt.Client", return_value=client):
            start_mqtt_inference_service(models_dir="nonexistent")
        host_engine.assert_not_called()
        predictions = [json.loads(call.args[1]) for call in client.publish.call_args_list if call.args[0] == "edge/telemetry/prediction"]
        self.assertEqual(len(predictions), 1)
        self.assertEqual(predictions[0]["inference_source"], "esp32")
        self.assertEqual(predictions[0]["class_probabilities"]["Normal"], .7)

    @unittest.skipUnless(NATIVE.is_file() and find_tshark_path(), "Compile native parity tool and install TShark first")
    def test_native_parser_matches_tshark(self) -> None:
        tcp = bytes.fromhex(radio_payload()["frame_hex"])
        header, llc = tcp[:24], bytes.fromhex("aaaa03000000")
        arp = header + llc + bytes.fromhex("0806") + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes(20)
        icmp_body = struct.pack("!BBHHH", 8, 0, 0x1234, 1, 2)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 1, 0,
                         socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
        icmp = header + llc + bytes.fromhex("0800") + ip + icmp_body
        large_ack = bytearray(tcp)
        large_ack[60:64] = bytes.fromhex("ffffffff")
        fixtures = [tcp, arp, icmp, bytes(large_ack)]
        lines = [f"F {len(frame)} {frame.hex()}" for frame in fixtures]
        native = subprocess.run([str(NATIVE)], input="\n".join(lines) + "\n", text=True, capture_output=True, check=True).stdout.splitlines()
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "radio.pcap"
            with capture.open("wb") as handle:
                handle.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 2048, 105))
                for index, frame in enumerate(fixtures):
                    handle.write(struct.pack("<IIII", 1_800_000_000, index * 100000, len(frame), len(frame)))
                    handle.write(frame)
            rows = []
            engine = PacketTSharkEngine(MagicMock(), rows.append, pcap_path=str(capture))
            try:
                engine.start()
                self.assertTrue(engine.completed.wait(10), engine.error)
            finally:
                engine.stop()
        self.assertEqual(len(rows), len(fixtures))
        for actual, expected in zip(native, rows):
            self.assertEqual(actual.split()[1], "ok")
            np.testing.assert_array_equal(np.array(actual.split()[2:], dtype=np.uint32),
                                          np.array([expected[name] for name in ESP32_PACKET_FEATURES], dtype=np.uint32))

    @unittest.skipUnless(NATIVE.is_file(), "Compile native parity tool first")
    def test_native_parser_rejects_unsafe_frames(self) -> None:
        valid = bytes.fromhex(radio_payload()["frame_hex"])
        protected = bytes.fromhex(radio_payload(True)["frame_hex"])
        fragment = bytearray(valid)
        fragment[1] |= 4
        bad_ip = bytearray(valid)
        bad_ip[32] = 0x41
        udp = bytearray(valid)
        udp[41] = 17
        fixtures = [(protected, len(protected), "encrypted_payload"), (valid[:40], len(valid), "truncated_frame"),
                    (bytes(fragment), len(valid), "fragmented_frame"), (bytes(bad_ip), len(valid), "malformed_frame"),
                    (bytes(udp), len(valid), "unsupported_protocol")]
        lines = [f"F {size} {frame.hex()}" for frame, size, _ in fixtures]
        result = subprocess.run([str(NATIVE)], input="\n".join(lines) + "\n", text=True, capture_output=True, check=True)
        self.assertEqual([line.split()[1] for line in result.stdout.splitlines()], [status for _, _, status in fixtures])


class EdgeAlertTests(unittest.IsolatedAsyncioTestCase):
    async def test_device_and_usb_alert_copies_are_deduplicated(self) -> None:
        from dashboard.backend import mqtt_bridge as bridge
        from dashboard.backend.state import SystemState
        state = SystemState()
        broadcast = AsyncMock()
        alert = {"device_id": "test-esp32", "packet_id": "test-esp32:123:native:1", "threat_type": "DDoS_TCP"}
        with patch.object(bridge, "state", state), patch.object(bridge.manager, "broadcast", broadcast), \
             patch.dict(bridge.loop_holder, {"loop": asyncio.get_running_loop()}, clear=True):
            bridge.process_mqtt_payload("edge/alerts/high_priority", alert)
            bridge.process_mqtt_payload("edge/alerts/high_priority", alert)
            await asyncio.sleep(.02)
        self.assertEqual(len(state.alerts_history), 1)
        self.assertEqual(broadcast.await_count, 1)


if __name__ == "__main__":
    unittest.main()
