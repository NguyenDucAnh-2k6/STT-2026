"""Attribution records actual sockets; scenario time alone is never a label."""
import socket
import threading
import time
from typing import Any


class FlowRecorder:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.flows: dict[tuple, dict[str, Any]] = {}

    def record(self, local: tuple, remote: tuple, protocol: str, started_ms: int,
               response_ok: bool = False) -> None:
        if not local[1]:
            return
        key = (local[0], local[1], remote[0], remote[1], protocol)
        with self.lock:
            flow = self.flows.setdefault(key, {"src_ip": local[0], "src_port": local[1],
                "dst_ip": remote[0], "dst_port": remote[1], "transport": protocol,
                "started_ms": started_ms, "response_ok": False})
            flow["ended_ms"] = int(time.time() * 1000) + 500
            flow["response_ok"] = flow["response_ok"] or response_ok

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(flow) for flow in self.flows.values()]

    def annotate_request(self, local: tuple, remote: tuple, protocol: str, context: dict[str, Any]) -> None:
        key = (local[0], local[1], remote[0], remote[1], protocol)
        with self.lock:
            if key in self.flows:
                self.flows[key].update(context)

    def mark_evidence(self, started_ms: int, evidence: dict[str, Any]) -> None:
        with self.lock:
            for flow in self.flows.values():
                if flow["started_ms"] >= started_ms:
                    flow.update(evidence)


class TrackedSocket:
    def __init__(self, raw: socket.socket, recorder: FlowRecorder, protocol: str) -> None:
        self.raw, self.recorder, self.protocol = raw, recorder, protocol
        self.remote = None
        self.bound_local = None
        self.started_ms = int(time.time() * 1000)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)

    def _bind_lab_source(self, address: tuple) -> None:
        # Unconnected UDP getsockname otherwise reports 0.0.0.0, not the
        # loopback source emitted on the wire. Bind before sending, never
        # replace measured packet addresses during preprocessing.
        if address[0] in ("127.0.0.1", "127.0.0.2") and self.raw.family == socket.AF_INET:
            try:
                unbound = self.raw.getsockname()[1] == 0
            except OSError as error:
                if getattr(error, "winerror", None) != 10022:
                    raise
                unbound = True  # Windows rejects getsockname on a fresh socket.
            if unbound:
                self.raw.bind(("127.0.0.1", 0))
            self.bound_local = self.raw.getsockname()

    def _record(self) -> None:
        if self.remote:
            try:
                local = self.raw.getsockname()
                if local[0] == "0.0.0.0" and self.bound_local:
                    local = self.bound_local
                self.recorder.record(local, self.remote, self.protocol, self.started_ms)
            except OSError:
                pass

    def connect(self, address: tuple) -> None:
        self._bind_lab_source(address)
        self.remote = address
        try:
            self.raw.connect(address)
        finally:
            self._record()

    def connect_ex(self, address: tuple) -> int:
        self._bind_lab_source(address)
        self.remote = address
        try:
            return self.raw.connect_ex(address)
        finally:
            self._record()

    def sendto(self, payload: bytes, address: tuple) -> int:
        self._bind_lab_source(address)
        self.remote = address
        try:
            return self.raw.sendto(payload, address)
        finally:
            self._record()

    def sendall(self, payload: bytes) -> None:
        try:
            self.raw.sendall(payload)
        finally:
            self._record()

    def close(self) -> None:
        self._record()
        self.raw.close()


def lab_socket(family: int, kind: int, recorder: FlowRecorder | None = None) -> Any:
    raw = socket.socket(family, kind)
    return TrackedSocket(raw, recorder, "udp" if kind == socket.SOCK_DGRAM else "tcp") if recorder else raw


def packet_label(packet: dict[str, Any], flows: list[dict[str, Any]], scenario: str) -> dict[str, Any]:
    layers = packet.get("protocol_stack", "").split(":")
    # ICMP can quote UDP/TCP headers. Inner ports alone do not establish
    # attribution of the outer control message.
    if "icmp" in layers or "icmpv6" in layers:
        if scenario in ("DDoS_ICMP", "Fingerprinting") and packet.get("icmp_type") in (0, 8):
            for flow in flows:
                if (flow["transport"] == "icmp" and flow["src_port"] == packet.get("icmp_identifier")
                        and packet.get("src_ip") == flow["src_ip"] and packet.get("dst_ip") == flow["dst_ip"]
                        and flow["started_ms"] <= packet["timestamp"] <= flow["ended_ms"]):
                    return {**{key: flow[key] for key in ("evidence_contract", "fixture_effect_ok") if key in flow},
                            "requested_attack_label": scenario, "ground_truth_scenario": scenario,
                            "label_source": "controlled_flow", "label_method": "automatic_icmp_identifier",
                            "scenario_target_match": True, "scenario_label_scope": "echo_identifier_and_time"}
        return {"requested_attack_label": "Unknown", "ground_truth_scenario": "Unknown",
                "label_source": "unattributed", "scenario_target_match": False}
    transport = "udp" if "udp" in layers else "tcp"
    ports = (packet.get("src_port", packet.get("tcp.srcport")), packet.get("dst_port", packet.get("tcp.dstport")))
    endpoints = ((packet.get("src_ip"), ports[0]), (packet.get("dst_ip"), ports[1]))
    for flow in flows:
        pair = ((flow["src_ip"], flow["src_port"]), (flow["dst_ip"], flow["dst_port"]))
        if (transport == flow["transport"] and endpoints in (pair, pair[::-1]) and
                flow["started_ms"] <= packet["timestamp"] <= flow["ended_ms"]):
            context = {key: flow[key] for key in ("evidence_contract", "fixture_effect_ok", "request_variant_id", "request_template_family", "request_placement", "request_method", "request_generator_version", "http_response_status", "response_body_bytes") if key in flow}
            return {**context, "requested_attack_label": scenario, "ground_truth_scenario": scenario,
                    "label_method": "automatic_flow", "label_source": "controlled_flow",
                    "scenario_target_match": True, "scenario_label_scope": "bidirectional_flow",
                    "workload_evidence": "HTTP 200 and X-AERO-Lab normal-http-v1" if scenario == "Normal" and flow.get("response_ok", flow.get("verified", False)) else "workload_flow_only"}
    return {"requested_attack_label": "Unknown", "ground_truth_scenario": "Unknown",
            "label_source": "unattributed", "scenario_target_match": False}
