"""Controlled surrogate scenarios with explicit verification contracts (v4)."""
import json
import socket
import struct
from typing import Any

from ..controlled_channel import CONTRACTS, reverse_exchange
from ..dns_fixture import query
from ..flows import lab_socket


def run_backdoor(workload: Any, started_ms: int) -> int:
    """Reverse fixture channel executing fixed commands."""
    evidence = reverse_exchange(workload.port + 2, workload.recorder, "Backdoor", workload.rng.getrandbits(32), workload.cancel)
    workload.recorder.mark_evidence(started_ms, evidence)
    with workload.lock:
        workload.completed += 1
    return 1


def run_ransomware(workload: Any, started_ms: int) -> int:
    """AES-256-GCM reversible file encryption within disposable temp sandbox."""
    evidence = reverse_exchange(workload.port + 2, workload.recorder, "Ransomware", workload.rng.getrandbits(32), workload.cancel)
    workload.recorder.mark_evidence(started_ms, evidence)
    with workload.lock:
        workload.completed += 1
    return 1


def run_mitm(workload: Any, started_ms: int) -> int:
    """DNS answer tampering and diverted HTTP request verification."""
    sender = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, workload.recorder)
    try:
        sender.settimeout(1)
        identifier = workload.rng.randint(1, 65535)
        sender.sendto(query(identifier), ("127.0.0.1", workload.port))
        response, _ = sender.recvfrom(512)
        if response[:2] != struct.pack("!H", identifier) or response[-4:] != socket.inet_aton("127.0.0.2"):
            raise ValueError("DNS tampering fixture did not produce expected answer")
        request = f"GET /lab/sensor HTTP/1.1\r\nHost: sensor.test\r\nConnection: close\r\n\r\n".encode()
        diverted = workload.request(request, host=socket.inet_ntoa(response[-4:]))
        if not diverted or json.loads(diverted["body"]).get("temperature") != 21:
            raise ValueError("Client did not observe DNS-driven changed service content")
        workload.recorder.mark_evidence(started_ms, {"evidence_contract": CONTRACTS["MITM"], "fixture_effect_ok": True})
        with workload.lock:
            workload.completed += 1
        return 1
    finally:
        sender.close()
