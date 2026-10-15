"""Bounded loopback-only SYN/ICMP patterns; no routing/firewall changes."""
import socket
import struct
import sys
import time
from typing import Any


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data)//2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def syn_packet(source_port: int, destination_port: int, sequence: int, flags: int = 2, window: int = 4096) -> bytes:
    src, dst = socket.inet_aton("127.0.0.2"), socket.inet_aton("127.0.0.1")
    tcp = struct.pack("!HHLLBBHHH", source_port, destination_port, sequence, 1 if flags & 16 else 0, 5<<4, flags, window, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo+tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, sequence & 65535, 0, 64, socket.IPPROTO_TCP, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp


def require_raw_capability(scenario: str) -> None:
    if scenario in ("DDoS_TCP", "Fingerprinting") and sys.platform != "linux":
        raise ValueError("SYN-only lab requires Linux/CAP_NET_RAW. Windows TCP connect bursts are not SYN floods; run this Twin backend in Linux VM/container.")
    protocol = socket.IPPROTO_RAW if scenario in ("DDoS_TCP", "Fingerprinting") else socket.IPPROTO_ICMP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol):
            pass
    except OSError as error:
        raise ValueError("Raw lab packets require local raw-socket permissions (Linux CAP_NET_RAW or supported administrator ICMP capture)") from error


def send_raw_burst(scenario: str, port: int, recorder: Any, cancel: Any, rng: Any, icmp_id: int) -> int:
    require_raw_capability(scenario)
    protocol = socket.IPPROTO_RAW if scenario == "DDoS_TCP" else socket.IPPROTO_ICMP
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol) as sender:
        sender.settimeout(1)
        if scenario == "DDoS_TCP":
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            sender.bind(("127.0.0.1", 0))
        for index in range(32):
            if cancel.is_set():
                break
            started = int(time.time()*1000)
            if scenario == "DDoS_TCP":
                source_port = rng.randint(30000, 60000)
                payload = syn_packet(source_port, port, rng.getrandbits(32))
                recorder.record(("127.0.0.2", source_port), ("127.0.0.1", port), "tcp", started)
            else:
                payload = struct.pack("!BBHHH", 8, 0, 0, icmp_id, index) + rng.randbytes(32)
                payload = payload[:2] + struct.pack("!H", checksum(payload)) + payload[4:]
                recorder.record(("127.0.0.1", icmp_id), ("127.0.0.1", icmp_id), "icmp", started)
            sender.sendto(payload, ("127.0.0.1", 0))
            sent += 1
            cancel.wait(.005)
    return sent


def fingerprint_probes(port: int, recorder: Any, cancel: Any, rng: Any, icmp_id: int) -> dict:
    """Low-rate response probes to owned open/closed ports, not an OS verdict."""
    require_raw_capability("Fingerprinting")
    started = int(time.time() * 1000)
    probes = 0
    pairs = set()
    responses = set()
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender, socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as receiver:
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        receiver.settimeout(.1)
        for destination in (port, port + 2):
            for flags in (2, 16, 18):
                if cancel.is_set():
                    raise InterruptedError("Fingerprinting cancelled")
                source = rng.randint(30000, 60000)
                pairs.add((destination, source))
                recorder.record(("127.0.0.2", source), ("127.0.0.1", destination), "tcp", started)
                sender.sendto(syn_packet(source, destination, rng.getrandbits(32), flags, rng.choice([1024, 4096, 8192])), ("127.0.0.1", 0))
                probes += 1
                cancel.wait(.025)
        deadline = time.monotonic() + .3
        while time.monotonic() < deadline:
            try:
                reply = receiver.recv(2048)
            except socket.timeout:
                continue
            offset = (reply[0] & 15) * 4
            if len(reply) >= offset + 20 and reply[12:16] == socket.inet_aton("127.0.0.1"):
                pair = struct.unpack("!HH", reply[offset:offset+4])
                if pair in pairs and reply[offset+13] & (4 | 16):
                    responses.add(pair)
        if not responses:
            raise TimeoutError("No TCP fingerprint probe responses observed")
    # Receive a matched echo reply, not merely count send() as completion.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sender:
        sender.bind(("127.0.0.1", 0))
        sender.settimeout(1)
        payload = struct.pack("!BBHHH", 8, 0, 0, icmp_id, 0) + rng.randbytes(32)
        payload = payload[:2] + struct.pack("!H", checksum(payload)) + payload[4:]
        recorder.record(("127.0.0.1", icmp_id), ("127.0.0.1", icmp_id), "icmp", started)
        sender.sendto(payload, ("127.0.0.1", 0))
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            response = sender.recv(2048)
            offset = (response[0] & 15) * 4
            if response[offset:] == b"\0" + payload[1:2] + struct.pack("!H", checksum(b"\0\0\0\0" + payload[4:])) + payload[4:]:
                return {"evidence_contract": "tcp-icmp-response-probes-v1", "fixture_effect_ok": True,
                        "tcp_probe_count": probes, "tcp_response_count": len(responses), "icmp_echo_reply": True}
        raise TimeoutError("Fingerprint echo response not observed")
