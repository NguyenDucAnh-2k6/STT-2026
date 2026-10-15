"""Bounded live preview export; dumpcap remains the authoritative persistence path."""
import json
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any

from firmware.host_probe.host_sniffer import WindowStats
from firmware.host_probe.packet_capture import PacketTSharkEngine


class LiveCapture:
    def __init__(self, directory: Path, tshark: str, interface: str, capture_filter: str) -> None:
        self.directory = directory
        self.interface = interface
        self.stats = WindowStats()
        self.queue: queue.Queue = queue.Queue(maxsize=512)
        self.stop_event = threading.Event()
        self.dropped = 0
        self.exported = 0
        self.error: str | None = None
        self.engine = PacketTSharkEngine(self.stats, self.enqueue, tshark_path=tshark,
                                        capture_filter_override=capture_filter)
        self.writer = threading.Thread(target=self._write, name="twin-live-export")

    def enqueue(self, packet: dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(packet)
        except queue.Full:
            self.dropped += 1

    def start(self) -> None:
        os.environ["HOST_CAPTURE_INTERFACES"] = self.interface
        os.environ["HOST_PCAP_FILE"] = ""
        self.writer.start()
        self.engine.start()
        deadline = time.monotonic() + 8
        while not self.engine.ready.wait(.1):
            if self.engine.completed.is_set() or time.monotonic() >= deadline:
                raise RuntimeError(self.engine.error or "Live TShark capture did not become ready")

    def health(self) -> dict[str, Any]:
        return {"live_captured": self.engine.captured_packets, "live_exported": self.exported,
                "live_export_dropped": self.dropped, "live_error": self.error or self.engine.error}

    def _write(self) -> None:
        size = 0
        started = time.monotonic()
        try:
            with (self.directory / "live.ndjson").open("w", encoding="utf-8", newline="\n") as output:
                def write(record: dict[str, Any]) -> None:
                    nonlocal size
                    data = json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n"
                    size += len(data.encode("utf-8"))
                    output.write(data)
                while not self.stop_event.is_set() or not self.queue.empty():
                    try:
                        packet = self.queue.get(timeout=.05)
                    except queue.Empty:
                        packet = None
                    if packet:
                        if size < 128 * 1024 * 1024:
                            write(packet)
                            self.exported += 1
                        else:
                            self.dropped += 1
                    elapsed = time.monotonic() - started
                    if elapsed >= .5:
                        write({**self.stats.snapshot_and_reset(elapsed), **self.health(),
                               "record_kind": "window", "captured_packets": self.engine.captured_packets,
                               "timestamp": int(time.time() * 1000)})
                        started = time.monotonic()
                    output.flush()
                write({"record_kind": "live_end", **self.health()})
                output.flush()
        except Exception as error:
            self.error = type(error).__name__

    def close(self) -> None:
        self.engine.stop()
        self.stop_event.set()
        if self.writer.is_alive():
            self.writer.join(timeout=5)
            if self.writer.is_alive():
                raise RuntimeError("Live preview writer did not stop")
        if self.error:
            raise RuntimeError(f"Live preview export failed: {self.error}")
