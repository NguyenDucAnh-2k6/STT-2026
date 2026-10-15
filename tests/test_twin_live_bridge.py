import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from digital_twin.lab.live_bridge import LiveBridge


class TwinLiveBridgeTests(unittest.TestCase):
    def make_bridge(self) -> LiveBridge:
        bridge = LiveBridge(Path("unused"), "experiment", lambda **values: None)
        bridge.client = MagicMock()
        bridge.client.publish.return_value.rc = 0
        return bridge

    def test_prediction_backpressure_bounds_model_backlog(self) -> None:
        bridge = self.make_bridge()
        for index in range(10):
            bridge.consume({"record_kind": "packet", "sequence": index})
        self.assertEqual(bridge.health()["live_published"], 4)
        self.assertEqual(bridge.health()["live_preview_dropped"], 6)
        bridge._prediction(None, None, SimpleNamespace(payload=json.dumps({"capture_id": "experiment", "packet_id": "experiment:live:0", "inference_status": "ok"})))
        bridge.consume({"record_kind": "packet", "sequence": 10})
        self.assertEqual(bridge.health()["live_predictions"], 1)
        self.assertEqual(bridge.health()["live_inference_pending"], 4)

    def test_error_acknowledgment_is_not_successful_inference(self) -> None:
        bridge = self.make_bridge()
        bridge.consume({"record_kind": "packet", "sequence": 1})
        bridge._prediction(None, None, SimpleNamespace(payload=json.dumps({"capture_id": "different", "packet_id": "experiment:live:1", "inference_status": "ok"})))
        self.assertEqual(bridge.health()["live_inference_pending"], 1)
        bridge._prediction(None, None, SimpleNamespace(payload=json.dumps({"capture_id": "experiment", "packet_id": "experiment:live:1", "inference_status": "error"})))
        self.assertEqual(bridge.health()["live_predictions"], 0)
        self.assertEqual(bridge.health()["live_inference_failed"], 1)

    def test_idle_has_zero_rates_but_preserves_capture_total(self) -> None:
        bridge = self.make_bridge()
        bridge.window = {"captured_packets": 100, "packet_rate": 30, "byte_rate": 10000, "tcp_count": 30}
        bridge.publish_idle()
        saved = json.loads(bridge.client.publish.call_args.args[1])
        self.assertEqual(saved["packet_rate"], 0)
        self.assertEqual(saved["byte_rate"], 0)
        self.assertEqual(saved["tcp_count"], 0)
        self.assertEqual(saved["captured_packets"], 100)

    def test_partial_utf8_record_is_completed_before_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"experiments"/"child"
            path.mkdir(parents=True)
            message = json.dumps({"record_kind": "window", "packet_rate": 1, "byte_rate": 2, "info": "dữ liệu"}, ensure_ascii=False).encode()
            split = message.index("ữ".encode()) + 1
            preview = path/"live.ndjson"
            preview.write_bytes(message[:split])
            bridge = self.make_bridge()
            bridge.directory = Path(directory)
            import threading
            import time
            worker = threading.Thread(target=bridge._tail)
            worker.start()
            time.sleep(.05)
            with preview.open("ab") as output:
                output.write(message[split:] + b'\n{"record_kind":"live_end"}\n')
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertIsNone(bridge.error)


if __name__ == "__main__":
    unittest.main()
