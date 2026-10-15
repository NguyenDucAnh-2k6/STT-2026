"""Stream container previews through host MQTT with inference acknowledgments."""
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

import paho.mqtt.client as mqtt

LOG = logging.getLogger(__name__)
TOPIC = "edge/telemetry/twin_live"


class LiveBridge:
    def __init__(self, directory: Path, experiment_id: str, notify: Callable[..., None]) -> None:
        self.directory, self.experiment_id, self.notify = directory, experiment_id, notify
        self.stop_event = threading.Event()
        self.connected = threading.Event()
        self.subscribed = threading.Event()
        self.lock = threading.Lock()
        self.pending: dict[str, float] = {}
        self.counters = {"live_received": 0, "live_published": 0, "live_predictions": 0,
                         "live_inference_failed": 0, "live_preview_dropped": 0}
        self.error: str | None = None
        self.window: dict[str, Any] = {}
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"twin-live-{experiment_id[:12]}")
        self.client.max_queued_messages_set(16)
        self.client.on_connect = self._connect
        self.client.on_subscribe = self._subscribe
        self.client.on_message = self._prediction
        self.worker = threading.Thread(target=self._tail, name="twin-live-bridge")

    def _connect(self, client: Any, userdata: Any, flags: Any, reason: Any, properties: Any) -> None:
        if reason == 0:
            self.connected.set()
            client.subscribe("edge/telemetry/prediction", qos=1)

    def _subscribe(self, client: Any, userdata: Any, mid: int, reasons: Any, properties: Any) -> None:
        if not any(getattr(reason, "is_failure", False) for reason in reasons):
            self.subscribed.set()

    def _prediction(self, client: Any, userdata: Any, message: Any) -> None:
        try:
            result = json.loads(message.payload)
            with self.lock:
                if result.get("capture_id") != self.experiment_id or result.get("packet_id") not in self.pending:
                    return
                del self.pending[result["packet_id"]]
                if result.get("inference_status") == "ok":
                    self.counters["live_predictions"] += 1
                else:
                    self.counters["live_inference_failed"] += 1
        except (ValueError, TypeError, AttributeError):
            LOG.warning("Rejected invalid inference acknowledgment")

    def start(self) -> None:
        host = os.getenv("MQTT_HOST") or os.getenv("MQTT_BROKER_HOST", "127.0.0.1")
        port = int(os.getenv("MQTT_PORT") or os.getenv("MQTT_BROKER_PORT", "1883"))
        self.client.connect(host, port, keepalive=30)
        self.client.loop_start()
        if not self.subscribed.wait(5):
            raise RuntimeError("Twin live MQTT prediction subscription not ready")
        self.worker.start()

    def health(self) -> dict[str, Any]:
        with self.lock:
            return {**self.counters, "live_inference_pending": len(self.pending), "live_bridge_error": self.error}

    def consume(self, record: dict[str, Any]) -> None:
        if record.get("record_kind") == "window":
            self.window = record
            self.publish_window(record)
            return
        if record.get("record_kind") != "packet":
            return
        with self.lock:
            self.counters["live_received"] += 1
            if len(self.pending) >= 4:
                self.counters["live_preview_dropped"] += 1
                return  # Preview backpressure never discards the saved PCAP.
            packet_id = f"{self.experiment_id}:live:{record['sequence']}"
            self.pending[packet_id] = time.monotonic()
            record.update(packet_id=packet_id, capture_id=self.experiment_id,
                          device_id="Twin-Lab", experiment_id=self.experiment_id,
                          capture_environment="docker-twin", data_provenance="twin-live-preview")
            # Live preview has no final labels/effect metadata; PCAP import labels later.
            result = self.client.publish(TOPIC, json.dumps(record, ensure_ascii=False, allow_nan=False), qos=1, retain=False)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                del self.pending[packet_id]
                self.counters["live_inference_failed"] += 1
            else:
                self.counters["live_published"] += 1

    def publish_window(self, window: dict[str, Any]) -> None:
        payload = {**window, **self.health(), "device_id": "Twin-Lab", "capture_id": self.experiment_id,
                   "schema_version": 2, "probe_type": "host", "record_kind": "window",
                   "feature_semantics": "window-v1", "capture_backend": "tshark",
                   "capture_environment": "docker-twin", "timestamp_kind": "epoch_ms"}
        result = self.client.publish("edge/telemetry/window", json.dumps(payload, allow_nan=False), qos=0, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            self.error = "MQTT window publish unavailable"

    def publish_idle(self) -> None:
        self.publish_window({**self.window, "packet_rate": 0, "byte_rate": 0,
                             "tcp_count": 0, "udp_count": 0, "icmp_count": 0,
                             "tcp_ratio": 0, "udp_ratio": 0, "icmp_ratio": 0,
                             "timestamp": int(time.time() * 1000)})

    def _tail(self) -> None:
        stream = None
        ended = False
        partial = b""
        last_report = time.monotonic()
        try:
            while not self.stop_event.is_set():
                paths = list((self.directory / "experiments").glob("*/live.ndjson"))
                if stream is None and len(paths) == 1:
                    stream = paths[0].open("rb")
                if stream:
                    for _ in range(256):
                        line = stream.readline(1_000_001)
                        if not line:
                            break
                        partial += line
                        if len(partial) > 1_000_000:
                            raise ValueError("Oversized live preview record")
                        if not partial.endswith(b"\n"):
                            break
                        record = json.loads(partial)
                        partial = b""
                        if record.get("record_kind") == "live_end":
                            ended = True
                            self.publish_idle()
                        else:
                            self.consume(record)
                with self.lock:
                    for packet_id, started in list(self.pending.items()):
                        if time.monotonic() - started >= 3:
                            del self.pending[packet_id]
                            self.counters["live_inference_failed"] += 1
                if time.monotonic() - last_report >= .5:
                    self.notify(**self.health(), live_inference_status="RUNNING" if not ended else "DRAINING")
                    last_report = time.monotonic()
                if ended and not self.health()["live_inference_pending"]:
                    break
                self.stop_event.wait(.02)
        except Exception as error:
            self.error = type(error).__name__
            LOG.exception("Twin live bridge failed")
        finally:
            if stream:
                stream.close()

    def close(self) -> None:
        if self.worker.is_alive():
            self.worker.join(timeout=4)
        self.stop_event.set()
        if self.worker.is_alive():
            self.worker.join(timeout=2)
        if self.connected.is_set():
            self.publish_idle()
        self.client.disconnect()
        self.client.loop_stop()
