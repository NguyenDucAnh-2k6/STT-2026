"""Reconnaissance and network discovery scenario generators."""
import socket
from typing import Any

from ..flows import lab_socket
from ..profile import scan_ports
from ..raw_packets import fingerprint_probes


def run_port_scanning(workload: Any) -> int:
    """TCP connect scan across registered open and closed ports."""
    ports = scan_ports(workload.port)
    workload.rng.shuffle(ports)
    for port in ports:
        if workload.cancel.is_set():
            break
        sender = lab_socket(socket.AF_INET, socket.SOCK_STREAM, workload.recorder)
        try:
            sender.settimeout(0.1)
            sender.connect_ex(("127.0.0.1", port))
        finally:
            sender.close()
        workload.cancel.wait(0.01)
    return len(ports)


def run_fingerprinting(workload: Any, started_ms: int) -> int:
    """Multi-flag TCP and ICMP probes to inspect service and stack response."""
    evidence = fingerprint_probes(workload.port, workload.recorder, workload.cancel, workload.rng, workload.icmp_id)
    for method in ("HEAD", "OPTIONS", "GET"):
        if not workload.cancel.is_set():
            workload.http(method, "/health")
    workload.recorder.mark_evidence(started_ms, evidence)
    return 1
