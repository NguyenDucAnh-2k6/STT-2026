"""Bounded ESP32 radio -> persistent TShark dissection -> canonical MQTT packets.

No radio-to-window synthesis, Wi-Fi decryption, or model training occurs here.
PCAP bytes travel through a pipe; original frames are not written to disk.
"""
import csv
import json
import logging
import queue
import re
import struct
import subprocess
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable

from firmware.host_probe.packet_capture import FIELDS, field_registry, parse_packet
from firmware.host_probe.tshark_engine import find_tshark_path
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES

LOG = logging.getLogger(__name__)
MAX_FRAME_BYTES = 2048
RADIO_TOPIC = "edge/telemetry/radio"


@dataclass(frozen=True)
class RadioSample:
    device_id: str
    boot_id: int
    sequence: int
    uptime_ms: int
    original_length: int
    channel: int
    rssi: int
    sample_interval_ms: int
    payload: bytes
    received_at_ms: int
    edge_result: dict[str, Any] | None = None

    @property
    def identity(self) -> tuple[str, int, int]:
        return self.device_id, self.boot_id, self.sequence


def parse_radio_sample(payload: dict[str, Any], received_at_ms: int) -> RadioSample:
    """Validate the firmware wire contract before allocating dissection state."""
    if not isinstance(payload, dict) or payload.get("record_kind") != "radio_frame":
        raise ValueError("Expected radio_frame")
    if payload.get("schema_version") != 1 or payload.get("linktype") != 105 or payload.get("fcs_included") is not False:
        raise ValueError("Unsupported radio schema/linktype/FCS")
    device = payload.get("device_id")
    if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", device):
        raise ValueError("Invalid radio device identity")
    if payload.get("timestamp_kind") != "uptime_ms":
        raise ValueError("Radio timestamp must be uptime_ms")
    bounds = {"boot_id": (0, 2**32 - 1), "sequence": (0, 2**32 - 1),
              "timestamp": (0, 2**32 - 1), "original_length": (24, 65535),
              "captured_length": (24, MAX_FRAME_BYTES), "channel": (1, 14),
              "rssi": (-128, 0), "sample_interval_ms": (1, 60000)}
    for name, (low, high) in bounds.items():
        value = payload.get(name)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"Invalid radio {name}")
    text = payload.get("frame_hex")
    if not isinstance(text, str) or len(text) != payload["captured_length"] * 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise ValueError("Invalid radio frame hex/length")
    data = bytes.fromhex(text)
    if payload["original_length"] < len(data) or (data[0] & 0x0c) != 8:
        raise ValueError("Invalid radio data frame")
    edge = {name: value for name, value in payload.items() if name.startswith("edge_")}
    if len(json.dumps(edge, allow_nan=False)) > 2048:
        raise ValueError("Oversized edge result")
    return RadioSample(device, payload["boot_id"], payload["sequence"], payload["timestamp"],
                       payload["original_length"], payload["channel"], payload["rssi"],
                       payload["sample_interval_ms"], data, received_at_ms, edge or None)


def pcap_record(sample: RadioSample, capture_epoch_ms: int | None = None) -> bytes:
    seconds, millis = divmod(sample.received_at_ms if capture_epoch_ms is None else capture_epoch_ms, 1000)
    return struct.pack("<IIII", seconds, millis * 1000, len(sample.payload), sample.original_length) + sample.payload


def annotate_radio_packet(packet: dict[str, Any], sample: RadioSample) -> dict[str, Any]:
    """Keep packet identity and radio capture limitations separate from features."""
    protected = bool(sample.payload[1] & 0x40)
    fragmented = bool(sample.payload[1] & 0x04 or sample.payload[22] & 0x0f)
    packet["dissection_id"] = packet.get("capture_id")
    packet["dissection_mode"] = "radio-one-pass-sampled"
    packet.update(probe_type="esp32", device_id=sample.device_id, boot_id=sample.boot_id,
                  sequence=sample.sequence, capture_id=f"{sample.device_id}:{sample.boot_id}",
                  packet_id=f"{sample.device_id}:{sample.boot_id}:radio:{sample.sequence}",
                  capture_backend="esp32_tshark", timestamp_kind="estimated_capture_epoch_ms",
                  capture_clock="esp32_uptime_ms_host_anchored",
                  source_timestamp=sample.uptime_ms, received_at_ms=sample.received_at_ms,
                  channel=sample.channel, rssi=sample.rssi, sniffer_mode="radio-sampled",
                  extractor_version="esp32-tshark-v1", data_provenance="esp32-radio",
                  radio_protected=protected, radio_fragmented=fragmented,
                  radio_sample_interval_ms=sample.sample_interval_ms,
                  edge_inference_status="unavailable", edge_prediction="Unknown", edge_flag=None,
                  edge_model="unavailable", edge_features_count=0,
                  supervised_training_eligible=False)
    # Only complete plaintext IP/ARP dissection can use the packet model. Radio
    # null-data, encryption and fragments must never become an all-zero Normal.
    stack = packet.get("protocol_stack", "").split(":")
    if protected or fragmented or not any(name in stack for name in ("ip", "ipv6", "arp")):
        packet["missing_features"] = list(EDGE_IIOTSET_FEATURES)
        packet["absent_fields"] = []
        for name in EDGE_IIOTSET_FEATURES:
            packet[name] = None
    packet["protocol_features_available"] = not packet["missing_features"]
    if sample.edge_result:
        packet.update(sample.edge_result)
    return packet


class RadioPacketDecoder:
    """One persistent dissector per device boot, with bounded in-flight records."""
    def __init__(self, executable: str, types: dict[str, str], version: str,
                 on_packet: Callable[[dict[str, Any]], None], stop_event: Any = None) -> None:
        self.types, self.version, self.on_packet = types, version, on_packet
        self.capture_id = uuid.uuid4().hex
        self.pending: dict[int, RadioSample] = {}
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(64)
        self.number = 0
        self.error: str | None = None
        self.stopping = False
        self.stop_event = stop_event
        self.closed = threading.Event()
        self.last_progress = time.monotonic()
        self.last_uptime_ms: int | None = None
        self.capture_epoch_ms: int | None = None
        command = [executable, "-l", "-n", "-r", "-", "-o", "tcp.relative_sequence_numbers:TRUE",
                   "-o", "tcp.analyze_sequence_numbers:TRUE", "-T", "fields",
                   "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=f"]
        for name in FIELDS:
            command += ["-e", name]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            self.process.stdin.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, MAX_FRAME_BYTES, 105))
            self.process.stdin.flush()
            self.reader = threading.Thread(target=self._read, name="radio-tshark-output")
            self.diagnostics = threading.Thread(target=self._errors, name="radio-tshark-errors")
            self.reader.start()
            self.diagnostics.start()
            self.watchdog = threading.Thread(target=self._watch, name="radio-pipe-watchdog")
            self.watchdog.start()
        except Exception:
            self.process.kill()
            self.process.wait(timeout=3)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
            raise

    def feed(self, sample: RadioSample) -> bool:
        if self.error or self.process.poll() is not None:
            raise RuntimeError(self.error or "Radio TShark stopped")
        if not self.slots.acquire(timeout=0.1):
            return False
        if self.last_uptime_ms is None:
            self.capture_epoch_ms = sample.received_at_ms
        else:
            elapsed_ms = (sample.uptime_ms - self.last_uptime_ms) & 0xffffffff
            if elapsed_ms > 0x7fffffff:
                self.slots.release()
                return False  # Late transport copy; do not reverse dissector time.
            self.capture_epoch_ms += elapsed_ms
        self.last_uptime_ms = sample.uptime_ms
        with self.lock:
            if not self.pending:
                self.last_progress = time.monotonic()
            self.number += 1
            self.pending[self.number] = sample
        self.process.stdin.write(pcap_record(sample, self.capture_epoch_ms))
        self.process.stdin.flush()
        return True

    def _read(self) -> None:
        try:
            for line in self.process.stdout:
                # The command has no display filter: exactly one output per record.
                number = int(next(csv.reader([line.decode("utf-8")], delimiter="\t"))[0])
                with self.lock:
                    sample = self.pending.pop(number)
                    self.last_progress = time.monotonic()
                self.slots.release()
                packet = parse_packet(line.decode("utf-8"), self.types, self.capture_id, self.version)
                self.on_packet(annotate_radio_packet(packet, sample))
        except Exception as exc:
            self.error = f"Radio dissection failed: {type(exc).__name__}"
            LOG.exception("Radio packet processing stopped")
        finally:
            if not self.stopping and not self.error:
                self.error = "Radio TShark output ended"

    def _errors(self) -> None:
        # Drain stderr without leaking packet content or unbounded accumulation.
        for _ in self.process.stderr:
            LOG.debug("Radio TShark emitted a diagnostic")

    def _watch(self) -> None:
        while not self.closed.wait(0.2):
            with self.lock:
                stalled = bool(self.pending) and time.monotonic() - self.last_progress > 5
            cancelled = self.stop_event is not None and self.stop_event.is_set()
            if stalled or cancelled:
                if stalled:
                    self.error = "Radio TShark stalled for five seconds"
                if self.process.poll() is None:
                    self.process.terminate()  # Unblocks a stalled pipe writer.
                return

    def close(self) -> None:
        self.stopping = True
        self.closed.set()
        if self.process.poll() is None:
            try:
                self.process.stdin.close()  # EOF drains accepted frames.
            except OSError:
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        for thread in (self.reader, self.diagnostics, self.watchdog):
            thread.join(timeout=3)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


def run_radio_capture(broker_host: str, broker_port: int, stop_event: Any) -> None:
    """Own decoder processes, bounded MQTT intake, and transport deduplication."""
    import paho.mqtt.client as mqtt
    executable = find_tshark_path()
    if not executable:
        raise RuntimeError("ESP32 packet collection requires TShark; install Wireshark/TShark")
    types = field_registry(executable)
    missing = [name for name in FIELDS if name not in types and not name.startswith("_ws.col.")]
    if missing:
        raise RuntimeError(f"TShark lacks canonical fields: {missing}")
    version = subprocess.check_output([executable, "-v"], text=True, encoding="utf-8", timeout=10).splitlines()[0]
    incoming: queue.Queue = queue.Queue(maxsize=128)
    decoders: OrderedDict = OrderedDict()
    seen: OrderedDict = OrderedDict()
    counters = {"received": 0, "duplicate": 0, "dropped": 0, "rejected": 0, "publish_accepted": 0, "publish_failed": 0}
    publish_lock = threading.Lock()
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="AERO-ESP32-Radio-Decoder")
    client.max_queued_messages_set(128)
    client.max_inflight_messages_set(16)
    subscribed = threading.Event()

    def on_connect(c: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None) -> None:
        if rc == 0:
            c.subscribe(RADIO_TOPIC, qos=1)

    def on_subscribe(c: Any, userdata: Any, mid: int, reasons: Any, properties: Any = None) -> None:
        if not any(getattr(reason, "is_failure", False) for reason in reasons):
            subscribed.set()

    def on_message(c: Any, userdata: Any, msg: Any) -> None:
        try:
            if msg.retain or len(msg.payload) > 8192:
                raise ValueError("Retained or oversized radio frame")
            sample = parse_radio_sample(json.loads(msg.payload.decode("utf-8")), int(time.time() * 1000))
            incoming.put_nowait(sample)
        except queue.Full:
            counters["dropped"] += 1
        except (ValueError, TypeError, UnicodeError):
            counters["rejected"] += 1

    def publish(packet: dict[str, Any]) -> None:
        result = client.publish("edge/telemetry/traffic", json.dumps(packet, allow_nan=False), qos=1, retain=False)
        with publish_lock:
            counters["publish_accepted" if result.rc == mqtt.MQTT_ERR_SUCCESS else "publish_failed"] += 1

    client.on_connect, client.on_subscribe, client.on_message = on_connect, on_subscribe, on_message
    try:
        client.connect(broker_host, broker_port, keepalive=60)
        client.loop_start()
        if not subscribed.wait(5):
            raise RuntimeError("Radio MQTT subscription not acknowledged")
        next_health = time.monotonic() + 5
        while not stop_event.is_set():
            for decoder in decoders.values():
                if decoder.error:
                    raise RuntimeError(decoder.error)
            if time.monotonic() >= next_health:
                print(f"[ESP32 Radio] {counters}", flush=True)
                next_health = time.monotonic() + 5
            try:
                sample = incoming.get(timeout=0.2)
            except queue.Empty:
                continue
            if sample.identity in seen:
                counters["duplicate"] += 1
                continue
            key = (sample.device_id, sample.boot_id)
            if key not in decoders:
                # Remove old boot state for the same device; cap simultaneous devices.
                for old in list(decoders):
                    if old[0] == sample.device_id:
                        decoders.pop(old).close()
                if len(decoders) >= 4:
                    counters["dropped"] += 1
                    continue
                decoders[key] = RadioPacketDecoder(executable, types, version, publish, stop_event)
            if decoders[key].number >= 2048:
                # Bound TShark flow/reassembly history. This is a new dissection
                # segment, not a new source capture or a benchmark-equivalent replay.
                decoders.pop(key).close()
                decoders[key] = RadioPacketDecoder(executable, types, version, publish, stop_event)
            if not decoders[key].feed(sample):
                counters["dropped"] += 1
                continue
            seen[sample.identity] = None
            if len(seen) > 8192:
                seen.popitem(last=False)
            counters["received"] += 1
    finally:
        for decoder in decoders.values():
            decoder.close()
        client.disconnect()
        client.loop_stop()
        print(f"[ESP32 Radio] Final counters: {counters}", flush=True)
