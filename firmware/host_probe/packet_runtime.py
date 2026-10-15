"""Bounded host packet publishing and independent dashboard windows."""
import json
import logging
import os
import queue
import threading
import time
from collections import deque
from typing import Any, Optional

import paho.mqtt.client as mqtt
from .packet_capture import PacketTSharkEngine

LOG = logging.getLogger(__name__)


def publish_packet_queue(client: Any, packets: queue.Queue, stop: threading.Event,
                         counters: dict[str, int]) -> None:
    """Pipeline up to 16 QoS messages instead of serially waiting for every ACK."""
    pending = deque()
    stop_deadline = None
    while not stop.is_set() or not packets.empty() or pending:
        now = time.monotonic()
        if stop.is_set() and stop_deadline is None:
            stop_deadline = now + 5
        for _ in range(len(pending)):
            info, sent_at = pending.popleft()
            try:
                if info.is_published():
                    counters["published"] += 1
                elif now - sent_at >= 2:
                    counters["failed"] += 1
                else:
                    pending.append((info, sent_at))
            except (ValueError, RuntimeError):
                counters["failed"] += 1
        if stop_deadline is not None and now >= stop_deadline:
            counters["failed"] += len(pending)
            while not packets.empty():
                try:
                    packets.get_nowait()
                    packets.task_done()
                    counters["dropped"] += 1
                except queue.Empty:
                    break
            return
        if len(pending) >= 16:
            stop.wait(0.005) if not stop.is_set() else time.sleep(0.005)
            continue
        try:
            packet = packets.get(timeout=0.01)
        except queue.Empty:
            continue
        try:
            encoded = json.dumps(packet, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > 1_000_000:
                counters["dropped"] += 1
                continue
            info = client.publish("edge/telemetry/traffic", encoded, qos=1, retain=False)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("Broker did not accept publish")
            pending.append((info, time.monotonic()))
        except Exception:
            counters["failed"] += 1
            LOG.error("Packet publish failed; total=%d", counters["failed"])
        finally:
            packets.task_done()


def run_packet_host(stats: Any, broker_host: str, broker_port: int,
                    window_sec: float, test_windows: Optional[int], stop_event: Any = None,
                    dashboard_port: Optional[int] = None) -> None:
    if window_sec <= 0:
        raise ValueError("window_sec must be positive")
    if os.getenv("HOST_TWIN_SERVICE_PORT") and test_windows is None:
        print("[Host] Twin IDLE: các nút UI dùng capture trong Docker; chờ thí nghiệm. Không bắn packet nền.")
        while stop_event is None or not stop_event.wait(.2):
            if stop_event is None:
                time.sleep(.2)
        print("[Host] Twin standby đã dừng.")
        return
    packets: queue.Queue = queue.Queue(maxsize=128)
    stop = threading.Event()
    connected = threading.Event()
    counters = {"published": 0, "dropped": 0, "failed": 0}
    client = None

    def enqueue(packet: dict[str, Any]) -> None:
        if test_windows is not None:
            return  # Capture-only diagnostic mode: no transport or persistence.
        try:
            packets.put_nowait(packet)
        except queue.Full:
            counters["dropped"] += 1

    engine = PacketTSharkEngine(stats, enqueue, broker_port, broker_host=broker_host,
                              dashboard_port=dashboard_port)
    worker = None
    try:
        if test_windows is None:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                 client_id=f"host-packets-{engine.capture_id[:12]}")
            client.max_queued_messages_set(32)
            client.max_inflight_messages_set(16)

            def on_connect(c: Any, u: Any, f: Any, reason: Any, p: Any) -> None:
                if reason == 0:
                    connected.set()

            client.on_connect = on_connect
            client.connect(broker_host, broker_port, keepalive=60)
            client.loop_start()
            if not connected.wait(timeout=5):
                raise RuntimeError("MQTT connection was not accepted")
            worker = threading.Thread(target=publish_packet_queue,
                                      args=(client, packets, stop, counters), name="packet-publisher")
            worker.start()
        engine.start()
        print("[Host] Packet mode: 56 raw fields | MQTT QoS 1 | labels Unknown")
        print("[Host] Window statistics use edge/telemetry/window; telemetry broker endpoint excluded from live capture")
        twin_port = os.getenv("HOST_TWIN_SERVICE_PORT")
        if twin_port:
            print(f"[Host] TWIN LAB: loopback TCP/UDP port {twin_port}; run a UI experiment to generate lab traffic. Wi-Fi traffic is excluded.")
        print(f"[Host] Selected capture interfaces: {engine.selected_interfaces}")
        count = 0
        started = time.monotonic()
        capture_started = started
        zero_reported = False
        while True:
            engine.completed.wait(timeout=min(window_sec, 0.2))
            elapsed = time.monotonic() - started
            if stop_event is not None and stop_event.is_set():
                break
            if elapsed < window_sec and not engine.completed.is_set():
                continue
            started = time.monotonic()
            telemetry = stats.snapshot_and_reset(max(elapsed, 0.001))
            telemetry.update({"schema_version": 2, "probe_type": "host", "record_kind": "window",
                              "device_id": os.getenv("HOST_PROBE_ID", "Host-PC-Live-Probe"),
                              "feature_semantics": "window-v1", "capture_backend": "tshark",
                              "timestamp_kind": "epoch_ms", "label_verified": False,
                              "window_ms": round(elapsed * 1000), "capture_id": engine.capture_id,
                              "captured_packets": engine.captured_packets,
                              "capture_interfaces": list(engine.selected_interfaces),
                              "publish_queue_depth": packets.qsize(),
                              "publish_queue_capacity": packets.maxsize,
                              "rejected_packets": engine.rejected_packets, **counters})
            if client:
                client.publish("edge/telemetry/window", json.dumps(telemetry), qos=0)
            print(f"[Host] captured={engine.captured_packets} published={counters['published']} "
                  f"dropped={counters['dropped']} failed={counters['failed']}")
            if not engine.pcap_path and not zero_reported and engine.captured_packets == 0 and time.monotonic() - capture_started >= 10:
                zero_reported = True
                LOG.warning("No parsed packets after 10s (rejected=%d). %s", engine.rejected_packets,
                    "Twin only captures the lab service: start a UI experiment; check its status if already started."
                    if twin_port else "Check adapter link/Npcap permissions; restart run_system.py to rediscover adapters after moving networks. No traffic or filter scope can also explain zero.")
            count += 1
            if engine.error:
                raise RuntimeError(engine.error)
            if engine.completed.is_set():
                if not engine.pcap_path:
                    raise RuntimeError("Live capture ended unexpectedly")
                break
            if test_windows and count >= test_windows:
                break
    except KeyboardInterrupt:
        print("[Host] Stopping packet capture...")
    finally:
        engine.stop()
        stop.set()
        if worker:
            worker.join(timeout=6)
        if client:
            client.disconnect()
            client.loop_stop()
        print(f"[Host] Final capture/publish counters: {engine.captured_packets}, {counters}")
