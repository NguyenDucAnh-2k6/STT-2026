"""Owned local-lab ports and scenario fidelity, separate from external allowlists."""
import os
from ml_engine.config.schema import LABEL_NAMES

VERSION = "twin-workloads-v4"
SURROGATES = {"Fingerprinting": "tcp-icmp-response-probes-not-xprobe2",
              "MITM": "dns-diversion-not-arp-poisoning",
              "Backdoor": "reverse-fixture-channel-no-shell-or-metasploit",
              "Ransomware": "aes-gcm-disposable-files-not-host-malware"}


def scan_ports(port: int) -> list[int]:
    count = int(os.getenv("TWIN_SCAN_PORT_COUNT", "12"))
    if not 3 <= count <= 32 or port + count - 1 > 65535:
        raise ValueError("TWIN_SCAN_PORT_COUNT must be 3..32 and fit above LAB_HTTP_PORT")
    return list(range(port, port + count))


def capture_filter(port: int, scenario: str | None = None, icmp_id: int | None = None) -> str:
    ports = scan_ports(port) if scenario in (None, "Port_Scanning", "Fingerprinting", "Backdoor", "Ransomware") else [port]
    tcp = f"tcp portrange {ports[0]}-{ports[-1]}" if len(ports) > 1 else f"tcp port {port}"
    udp = f"(udp port {port} or udp port {port+2})" if scenario in (None, "MITM") else f"udp port {port}"
    filters = [tcp, udp]
    if scenario in (None, "DDoS_ICMP", "Fingerprinting"):
        filters.append("icmp" + (f" and icmp[4:2] = {icmp_id}" if icmp_id is not None else ""))
    return "host 127.0.0.1 and (" + " or ".join(f"({item})" for item in filters) + ")"


def scenario_metadata(scenario: str) -> dict:
    if scenario not in LABEL_NAMES:
        raise ValueError("Unknown Twin benchmark scenario")
    return {"scenario_version": VERSION,
            "scenario_fidelity": SURROGATES.get(scenario, "bounded-protocol-experiment-not-benchmark-reproduction"),
            "supervised_training_eligible": scenario not in SURROGATES,
            "distributed_attack": False}
