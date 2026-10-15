"""One TShark packet -> canonical raw features; no window-to-packet synthesis."""
import csv
import io
import ipaddress
import logging
import math
import os
import re
import socket
import subprocess
import threading
import uuid
from typing import Any, Callable, Optional

from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import CATEGORICAL_FEATURES
from .tshark_engine import DpiTextualInspector, find_tshark_path, get_available_interfaces, select_best_interfaces
from .content import extract_raw_content

LOG = logging.getLogger(__name__)
META_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
               "frame.interface_id", "frame.protocols", "ip.src", "ip.dst", "ip.proto", "ipv6.src", "ipv6.dst",
               "udp.srcport", "udp.dstport", "icmp.ident", "icmp.type", "_ws.col.Protocol", "_ws.col.Info"]
FIELDS = META_FIELDS + EDGE_IIOTSET_FEATURES
ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v", "b": "\b", "\\": "\\"}


def unescape_field(value: str) -> str:
    return re.sub(r"\\([tnrfvb\\])", lambda match: ESCAPES[match[1]], value)


def field_registry(executable: str) -> dict[str, str]:
    output = subprocess.check_output([executable, "-G", "fields"], text=True,
                                     encoding="utf-8", timeout=30)
    return {parts[2]: parts[3] for line in output.splitlines()
            if len(parts := line.split("\t")) >= 4 and parts[0] == "F"}


def parse_packet(line: str, types: dict[str, str], capture_id: str,
                 version: str, offline: bool = False) -> dict[str, Any]:
    values = next(csv.reader(io.StringIO(line), delimiter="\t", strict=True))
    if len(values) != len(FIELDS):
        raise ValueError("Unexpected TShark column count")
    raw = dict(zip(FIELDS, map(unescape_field, values)))
    timestamp = float(raw["frame.time_epoch"])
    if not math.isfinite(timestamp) or timestamp < 1_000_000_000:
        raise ValueError("Invalid packet epoch timestamp")
    number = int(raw["frame.number"])
    size, captured = int(raw["frame.len"]), int(raw["frame.cap_len"])
    features: dict[str, Any] = {}
    absent: list[str] = []
    missing: list[str] = []
    for name in EDGE_IIOTSET_FEATURES:
        value = raw[name]
        if not value:
            absent.append(name)
            features[name] = "0" if name in CATEGORICAL_FEATURES else 0
        elif name in CATEGORICAL_FEATURES:
            features[name] = value
        else:
            try:
                parsed = (1 if types[name] == "FT_NONE" else
                          int(value.lower() == "true") if types[name] == "FT_BOOLEAN" and value.lower() in ("true", "false") else
                          int(value.replace(":", ""), 16) if types[name] == "FT_BYTES" else
                          int(value, 16) if value.lower().startswith("0x") else float(value))
                if not math.isfinite(parsed):
                    raise ValueError("Non-finite value")
                features[name] = parsed
            except ValueError:
                features[name] = None
                missing.append(name)
    if captured < size:
        missing = list(EDGE_IIOTSET_FEATURES)
    return {**features, **extract_raw_content(raw, types, captured < size),
            "schema_version": 2, "probe_type": "host",
            "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1",
            "device_id": os.getenv("HOST_PROBE_ID", "Host-PC-Live-Probe"),
            "capture_id": capture_id, "boot_id": capture_id, "sequence": number,
            "packet_id": f"{capture_id}:{number}", "timestamp": round(timestamp * 1000),
            "timestamp_kind": "epoch_ms", "packet_time_epoch": timestamp,
            "capture_backend": "pcap" if offline else "tshark",
            "dissection_mode": "two-pass" if offline else "live-one-pass",
            "extractor_version": "tshark-packet-v1", "tshark_version": version,
            "field_occurrence": "first", "absent_fields": absent,
            "missing_features": missing, "frame_length": size, "captured_length": captured,
            "capture_interface_id": raw["frame.interface_id"],
            "protocol_stack": raw["frame.protocols"], "protocol": raw["_ws.col.Protocol"],
            "src_ip": raw["ip.src"] or raw["ipv6.src"] or None,
            "dst_ip": raw["ip.dst"] or raw["ipv6.dst"] or None,
            "icmp_identifier": int(raw["icmp.ident"], 16 if raw["icmp.ident"].startswith("0x") else 10) if raw["icmp.ident"] else None,
            "icmp_type": int(raw["icmp.type"]) if raw["icmp.type"] else None,
            "src_port": int(raw["udp.srcport"]) if raw["udp.srcport"] else features["tcp.srcport"],
            "dst_port": int(raw["udp.dstport"]) if raw["udp.dstport"] else features["tcp.dstport"],
            "label_verified": False, "label_source": "unverified",
            "ground_truth_scenario": "Unknown"}


class PacketTSharkEngine:
    def __init__(self, stats_collector: Any, on_packet: Callable[[dict[str, Any]], None],
                 broker_port: int = 1883, pcap_path: Optional[str] = None,
                 tshark_path: Optional[str] = None, broker_host: str = "127.0.0.1",
                 dashboard_port: Optional[int] = None, capture_filter_override: Optional[str] = None) -> None:
        self.stats = stats_collector
        self.on_packet = on_packet
        self.broker_port = broker_port
        self.broker_host = broker_host
        self.dashboard_port = dashboard_port or int(os.getenv("PORT", "8000"))
        self.capture_filter_override = capture_filter_override
        self.pcap_path = pcap_path or os.getenv("HOST_PCAP_FILE") or None
        self.tshark_path = tshark_path or find_tshark_path()
        self.capture_id = uuid.uuid4().hex
        self.selected_interfaces: list[str] = []
        self.process: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.error_thread: Optional[threading.Thread] = None
        self.running = False
        self.completed = threading.Event()
        self.ready = threading.Event()
        self.error: Optional[str] = None
        self.captured_packets = 0
        self.rejected_packets = 0
        self.inspector = DpiTextualInspector()

    def build_command(self) -> list[str]:
        cmd = [self.tshark_path, "-l", "-n", "-o", "tcp.relative_sequence_numbers:TRUE",
               "-o", "tcp.analyze_sequence_numbers:TRUE"]
        if self.pcap_path:
            if not os.path.isfile(self.pcap_path):
                raise FileNotFoundError("HOST_PCAP_FILE does not exist")
            cmd += ["-2", "-r", self.pcap_path]
        else:
            interfaces = get_available_interfaces(self.tshark_path, strict=True)
            self.selected_interfaces = select_best_interfaces(interfaces)
            for entry in interfaces:
                if entry["device"] in self.selected_interfaces:
                    LOG.info("Capture adapter: %s [%s]", entry["name"] or entry["device"], entry["device"])
            if not self.selected_interfaces:
                raise RuntimeError("No capture interface; configure HOST_CAPTURE_INTERFACES")
            twin_port = os.getenv("HOST_TWIN_SERVICE_PORT")
            if self.capture_filter_override:
                cmd += ["-f", self.capture_filter_override]
            else:
                # Exclude the transport carrying our own telemetry to avoid a feedback loop.
                addresses: list[str] = []
                try:
                    addresses = sorted({str(ipaddress.ip_address(entry[4][0]))
                                        for entry in socket.getaddrinfo(self.broker_host, self.broker_port,
                                                                        type=socket.SOCK_STREAM)})
                except (socket.gaierror, OSError):
                    if self.broker_host:
                        try:
                            addresses = [str(ipaddress.ip_address(self.broker_host))]
                        except ValueError:
                            addresses = ["127.0.0.1"]
                hosts = " or ".join(f"host {address}" for address in addresses) or "host 127.0.0.1"
                local = {"127.0.0.1", "::1"}
                try:
                    local.update(str(ipaddress.ip_address(entry[4][0])) for entry in
                                 socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM))
                except (socket.gaierror, OSError):
                    pass
                dashboard = " or ".join(
                    f"(src host {address} and tcp src port {self.dashboard_port}) or "
                    f"(dst host {address} and tcp dst port {self.dashboard_port})"
                    for address in sorted(local))
                capture_filter = f"not ((tcp port {self.broker_port} and ({hosts})) or ({dashboard}))"
                twin_port = os.getenv("HOST_TWIN_SERVICE_PORT")
                if twin_port:
                    port = int(twin_port)
                    if not 1 <= port <= 65535:
                        raise ValueError("HOST_TWIN_SERVICE_PORT must be 1..65535")
                    from digital_twin.lab.profile import capture_filter as twin_capture_filter
                    capture_filter = f"({capture_filter}) and ({twin_capture_filter(port)})"
                cmd += ["-f", capture_filter]
            LOG.info("Capture scope: %s", "Twin loopback lab service" if twin_port else "selected host interfaces (MQTT/dashboard excluded)")
            for interface in self.selected_interfaces:
                cmd += ["-i", interface]
        cmd += ["-T", "fields", "-E", "separator=/t", "-E", "quote=d",
                "-E", "escape=y", "-E", "occurrence=f"]
        for name in FIELDS:
            cmd += ["-e", name]
        return cmd

    def start(self) -> bool:
        if not self.tshark_path:
            raise RuntimeError("Packet mode requires TShark; no psutil/raw fallback")
        self.types = field_registry(self.tshark_path)
        missing = [name for name in FIELDS if name not in self.types and not name.startswith("_ws.col.")]
        if missing:
            raise RuntimeError(f"TShark lacks required fields: {missing}")
        self.version = subprocess.check_output([self.tshark_path, "-v"], text=True,
                                               encoding="utf-8", timeout=10).splitlines()[0]
        self.process = subprocess.Popen(self.build_command(), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                        errors="strict", bufsize=1,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.running = True
        self.error_thread = threading.Thread(target=self._errors, name="tshark-stderr")
        self.thread = threading.Thread(target=self._read, name="tshark-packets")
        self.error_thread.start()
        self.thread.start()
        return True

    def _errors(self) -> None:
        for line in self.process.stderr:
            if "Capturing on" in line:
                self.ready.set()
            # TShark diagnostics only; never log decoded packet contents.
            LOG.info("TShark: %s", line.strip())

    def _read(self) -> None:
        try:
            for line in self.process.stdout:
                if not self.running:
                    break
                try:
                    packet = parse_packet(line, self.types, self.capture_id, self.version, bool(self.pcap_path))
                    self.on_packet(packet)
                    self.captured_packets += 1
                    flags = int(packet["tcp.flags"] or 0)
                    self.stats.add_packet(
                        proto=6 if "tcp" in packet["protocol_stack"].split(":") else
                              17 if "udp" in packet["protocol_stack"].split(":") else 0,
                        size=packet["frame_length"], src_ip=packet["src_ip"] or "",
                        dst_ip=packet["dst_ip"] or "", src_port=packet["tcp.srcport"] or None,
                        dst_port=packet["tcp.dstport"] or None, is_syn=bool(flags & 2),
                        is_ack=bool(flags & 16), is_rst=bool(flags & 4), is_fin=bool(flags & 1),
                        info=packet["protocol"], pkt_time=packet["packet_time_epoch"])
                    if hasattr(self.stats, "add_l7_content"):
                        text = " ".join(str(packet[name]) for name in
                                        ("http.file_data", "http.request.full_uri", "http.referer"))
                        threat, snippet = self.inspector.inspect_text(text)
                        self.stats.add_l7_content(
                            method=str(packet["http.request.method"]), uri=str(packet["http.request.full_uri"]),
                            body=str(packet["http.file_data"]), dns_name=str(packet["dns.qry.name"]),
                            mqtt_topic=str(packet["mqtt.topic"]), threat_type=threat, snippet=snippet)
                except (ValueError, csv.Error, OverflowError):
                    self.rejected_packets += 1
                    LOG.warning("Rejected malformed packet; total=%d", self.rejected_packets)
            code = self.process.wait(timeout=5)
            if self.running and code != 0:
                self.error = f"TShark exited with status {code}; inspect capture permissions/interface"
        except Exception as exc:
            self.error = f"Packet capture failed: {type(exc).__name__}"
            LOG.exception("Packet capture stopped")
        finally:
            self.completed.set()

    def stop(self) -> None:
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        for thread in (self.thread, self.error_thread):
            if thread:
                thread.join(timeout=5)
        if self.process:
            self.process.stdout.close()
            self.process.stderr.close()
