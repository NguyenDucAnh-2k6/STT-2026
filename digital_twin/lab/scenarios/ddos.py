"""DoS/DDoS scenario generators for digital twin lab."""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..flows import lab_socket
from ..raw_packets import send_raw_burst


def run_ddos_tcp(workload: Any) -> int:
    """SYN flood burst using crafted raw packets."""
    return send_raw_burst("DDoS_TCP", workload.port, workload.recorder, workload.cancel, workload.rng, workload.icmp_id)


def run_ddos_icmp(workload: Any) -> int:
    """ICMP echo flood burst using raw ICMP sockets."""
    return send_raw_burst("DDoS_ICMP", workload.port, workload.recorder, workload.cancel, workload.rng, workload.icmp_id)


def run_ddos_udp(workload: Any) -> int:
    """UDP volumetric burst towards lab receiver."""
    sender = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, workload.recorder)
    try:
        for _ in range(64):
            if workload.cancel.is_set():
                break
            sender.sendto(workload.rng.randbytes(workload.rng.choice([128, 512, 1024])), ("127.0.0.1", workload.port))
    finally:
        sender.close()
    return 64


def run_ddos_http(workload: Any) -> int:
    """Concurrent HTTP GET/POST flooding across endpoints."""
    requests = [
        (workload.rng.choice(["GET", "POST"]), workload.rng.choice(["/health", "/bytes/512", "/bytes/4096"]))
        for _ in range(24)
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(
            lambda item: workload.http(item[0], item[1], b"N" * 512 if item[0] == "POST" else b"")
            if not workload.cancel.is_set() else {},
            requests
        ))
    return len(requests)
