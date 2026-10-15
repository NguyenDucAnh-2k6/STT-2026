"""MQTT ingestion with packet identity deduplication and verified labels only."""
import json
import logging
import math
import threading
from collections import OrderedDict
from typing import Any, Optional

import paho.mqtt.client as mqtt
from .lakehouse import DataLakeManager, get_lakehouse_manager
from .scenario_context import ScenarioContext

LOG = logging.getLogger(__name__)


class DataLakeCollector:
    def __init__(self, broker_host: str = "127.0.0.1", broker_port: int = 1883,
                 probe_type: str = "host", sniffer_mode: str = "host-interface",
                 lake_manager: Optional[DataLakeManager] = None, buffer_size: int = 500,
                 flush_interval: float = 5.0) -> None:
        self.broker_host, self.broker_port = broker_host, broker_port
        self.probe_type, self.sniffer_mode = probe_type, sniffer_mode
        self.lake = lake_manager or get_lakehouse_manager()
        self.lake.flush_threshold = buffer_size
        self.flush_interval = flush_interval
        self.running = False
        self._stop = threading.Event()
        self._connected = threading.Event()
        self._subscribed = threading.Event()
        self._seen = OrderedDict()
        self._flush_thread = None
        self.latest_prediction = None
        self.scenario_context = ScenarioContext()
        self._subscription_mids: set[int] = set()
        self._subscription_failed = False
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="EdgeAI-DataLake-Collector")

    @property
    def session_id(self) -> Optional[str]:
        return self.lake.current_session_id

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None) -> None:
        if rc == 0:
            self._connected.set()
            self._subscribed.clear()
            self._subscription_mids.clear()
            self._subscription_failed = False
            for topic in ("edge/telemetry/traffic", "edge/attack/status"):
                result, mid = client.subscribe(topic, qos=1)
                if result != mqtt.MQTT_ERR_SUCCESS:
                    self._subscription_failed = True
                    LOG.error("Data lake subscription request failed: %s", topic)
                    return
                self._subscription_mids.add(mid)

    def _on_subscribe(self, client: Any, userdata: Any, mid: int, reasons: Any, properties: Any = None) -> None:
        if any(getattr(reason, "is_failure", False) for reason in reasons):
            self._subscription_failed = True
            LOG.error("Data lake topic subscription denied")
            return
        self._subscription_mids.discard(mid)
        if not self._subscription_mids and not self._subscription_failed:
            self._subscribed.set()

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        if msg.topic not in ("edge/telemetry/traffic", "edge/attack/status"):
            return
        try:
            if len(msg.payload) > 1_000_000:
                raise ValueError("Payload too large")
            payload = json.loads(msg.payload.decode("utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            if msg.topic == "edge/attack/status":
                if not isinstance(payload, dict):
                    raise ValueError("Invalid scenario payload")
                self.scenario_context.update(payload)
                self.lake.annotate_pending_scenarios(self.scenario_context.annotate)
                return
            if not isinstance(payload, dict) or not payload.get("device_id"):
                raise ValueError("Missing device identity")
            if not isinstance(payload.get("timestamp"), (int, float)) or not math.isfinite(payload["timestamp"]):
                raise ValueError("Invalid timestamp")
            identity = (payload["device_id"], payload.get("boot_id"),
                        payload.get("packet_id", payload.get("sequence", payload["timestamp"])))
            if identity in self._seen:
                return
            payload.update(self.scenario_context.annotate(payload))
            ground_truth = "Unknown"
            if payload.get("label_source") in ("manual_review", "controlled_flow"):
                from ml_engine.config.schema import LABEL_NAMES
                if payload.get("ground_truth_scenario") in LABEL_NAMES:
                    ground_truth = payload["ground_truth_scenario"]
            self.lake.record_telemetry(telemetry=payload, ground_truth=ground_truth)
            self._seen[identity] = None
            if len(self._seen) > 8192:
                self._seen.popitem(last=False)
        except Exception:
            LOG.exception("Telemetry ingestion failed; persistence buffer retained")

    def _periodic_flush_loop(self) -> None:
        while not self._stop.wait(self.flush_interval):
            try:
                self.lake.flush()
            except Exception:
                LOG.exception("Data lake flush failed; buffered rows retained")

    def start(self) -> None:
        self.lake.start_session(self.probe_type, self.sniffer_mode)
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message
        self.mqtt_client.on_subscribe = self._on_subscribe
        try:
            self.mqtt_client.connect(self.broker_host, self.broker_port, keepalive=60)
            self.mqtt_client.loop_start()
            if not self._subscribed.wait(5):
                raise RuntimeError("Data lake MQTT subscription was not acknowledged")
            self.running = True
            self._flush_thread = threading.Thread(target=self._periodic_flush_loop, name="lake-flush")
            self._flush_thread.start()
        except Exception:
            self.mqtt_client.disconnect()
            self.mqtt_client.loop_stop()
            self.lake.close_session()
            raise

    def stop(self) -> dict[str, Any]:
        self.running = False
        self.mqtt_client.disconnect()
        self.mqtt_client.loop_stop()
        self._stop.set()
        if self._flush_thread:
            self._flush_thread.join(timeout=10)
        return self.lake.close_session()


def start_lake_collector(**kwargs: Any) -> DataLakeCollector:
    collector = DataLakeCollector(**kwargs)
    collector.start()
    return collector
