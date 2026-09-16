#!/usr/bin/env python3
"""
Data Lake Ingestion Collector Daemon
====================================
Tiến trình nền lắng nghe luồng telemetry từ MQTT và ghi nhận vào kho Data Lakehouse:
- Lắng nghe 'edge/telemetry/traffic': Lưu trữ đặc trưng mạng thời gian thực.
- Lắng nghe 'edge/attack/status': Đồng bộ chính xác Ground-Truth (Normal vs Loại tấn công đang diễn ra).
- Lắng nghe 'edge/telemetry/prediction': Lưu trữ phán quyết của ML model để đánh giá chất lượng mô hình sau này.
"""

import json
import time
import threading
from typing import Optional, Dict, Any
import paho.mqtt.client as mqtt

from .lakehouse import DataLakeManager, get_lakehouse_manager


class DataLakeCollector:
    """
    Tiến trình Daemon thu nhận luồng dữ liệu mạng thời gian thực từ MQTT.
    """

    def __init__(
        self,
        broker_host: str = "127.0.0.1",
        broker_port: int = 1883,
        probe_type: str = "esp32",
        sniffer_mode: str = "all-networks",
        lake_manager: Optional[DataLakeManager] = None,
        buffer_size: int = 50,
        flush_interval: float = 5.0
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.probe_type = probe_type
        self.sniffer_mode = sniffer_mode
        self.lake = lake_manager or get_lakehouse_manager()
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval

        if hasattr(self.lake, "flush_threshold"):
            self.lake.flush_threshold = buffer_size

        self.current_scenario: str = "Normal"
        self.is_attack_active: bool = False
        self.latest_prediction: Optional[Dict[str, Any]] = None

        self.running = False
        self.mqtt_client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="EdgeAI-DataLake-Collector"
        )
        self._flush_thread: Optional[threading.Thread] = None

    @property
    def session_id(self) -> Optional[str]:
        """Tra ve session ID hien tai cua Data Lakehouse."""
        return self.lake.current_session_id if self.lake else None

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[DataLakeCollector] Da ket noi MQTT Broker tai {self.broker_host}:{self.broker_port}")
            client.subscribe("edge/telemetry/traffic")
            client.subscribe("edge/attack/status")
            client.subscribe("edge/telemetry/prediction")
            print("[DataLakeCollector] Da subscribe cac topic telemetry de luu kho.")
        else:
            print(f"[DataLakeCollector] Ket noi MQTT that bai (rc={rc})")

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        if topic == "edge/attack/status":
            scenario = payload.get("scenario", "Normal")
            status = payload.get("status", "IDLE")
            self.current_scenario = scenario if status in ["ACTIVE", "RUNNING"] else "Normal"
            self.is_attack_active = bool(status in ["ACTIVE", "RUNNING"] and scenario != "Normal")

        elif topic == "edge/telemetry/prediction":
            self.latest_prediction = payload

        elif topic == "edge/telemetry/traffic":
            ground_truth = self.current_scenario
            self.lake.record_telemetry(
                telemetry=payload,
                ground_truth=ground_truth,
                prediction=self.latest_prediction
            )

    def _periodic_flush_loop(self):
        while self.running:
            time.sleep(self.flush_interval)
            try:
                with self.lake._lock:
                    if len(self.lake.buffer) > 0:
                        self.lake._flush_locked()
            except Exception:
                pass

    def start(self):
        """Khởi động collector và bắt đầu phiên ghi mới."""
        self.running = True
        self.lake.start_session(
            probe_type=self.probe_type,
            sniffer_mode=self.sniffer_mode
        )

        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message

        # Kết nối MQTT với cơ chế retry
        connected = False
        for _ in range(5):
            try:
                self.mqtt_client.connect(self.broker_host, self.broker_port, keepalive=60)
                connected = True
                break
            except Exception:
                time.sleep(1.0)

        if not connected:
            print(f"  [Canh bao DataLake] Khong the ket noi broker {self.broker_host}:{self.broker_port}")

        self.mqtt_client.loop_start()

        self._flush_thread = threading.Thread(target=self._periodic_flush_loop, daemon=True)
        self._flush_thread.start()

    def stop(self) -> Dict[str, Any]:
        """Dừng collector và đóng phiên an toàn."""
        self.running = False
        try:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        except Exception:
            pass

        return self.lake.close_session()


_collector_instance: Optional[DataLakeCollector] = None


def start_lake_collector(
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    probe_type: str = "esp32",
    sniffer_mode: str = "all-networks",
    buffer_size: int = 50,
    flush_interval: float = 5.0,
    lake_manager: Optional[DataLakeManager] = None
) -> DataLakeCollector:
    global _collector_instance
    if _collector_instance is None or not _collector_instance.running:
        _collector_instance = DataLakeCollector(
            broker_host=broker_host,
            broker_port=broker_port,
            probe_type=probe_type,
            sniffer_mode=sniffer_mode,
            lake_manager=lake_manager,
            buffer_size=buffer_size,
            flush_interval=flush_interval
        )
        _collector_instance.start()
    return _collector_instance
