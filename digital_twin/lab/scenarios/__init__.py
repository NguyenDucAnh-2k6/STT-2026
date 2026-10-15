"""Dispatcher and registry for digital twin attack workloads."""
from typing import Any, Callable

from .ddos import run_ddos_tcp, run_ddos_icmp, run_ddos_udp, run_ddos_http
from .web import run_sql_injection, run_xss, run_vulnerability_scanner, run_uploading, run_password
from .recon import run_port_scanning, run_fingerprinting
from .surrogates import run_backdoor, run_ransomware, run_mitm

SCENARIO_DISPATCH: dict[str, Callable[..., int]] = {
    # DoS / DDoS
    "DDoS_TCP": lambda w, ms: run_ddos_tcp(w),
    "DDoS_ICMP": lambda w, ms: run_ddos_icmp(w),
    "DDoS_UDP": lambda w, ms: run_ddos_udp(w),
    "DDoS_HTTP": lambda w, ms: run_ddos_http(w),
    # Web attacks
    "SQL_injection": lambda w, ms: run_sql_injection(w),
    "XSS": lambda w, ms: run_xss(w),
    "Vulnerability_scanner": lambda w, ms: run_vulnerability_scanner(w),
    "Uploading": lambda w, ms: run_uploading(w),
    "Password": lambda w, ms: run_password(w),
    # Reconnaissance
    "Port_Scanning": lambda w, ms: run_port_scanning(w),
    "Fingerprinting": lambda w, ms: run_fingerprinting(w, ms),
    # Surrogates (v4)
    "Backdoor": lambda w, ms: run_backdoor(w, ms),
    "Ransomware": lambda w, ms: run_ransomware(w, ms),
    "MITM": lambda w, ms: run_mitm(w, ms),
}


def dispatch_scenario(scenario: str, workload: Any, started_ms: int) -> int:
    """Dispatch scenario execution to its registered handler."""
    handler = SCENARIO_DISPATCH.get(scenario)
    if not handler:
        raise ValueError(f"No Twin workload dispatch for scenario: {scenario}")
    return handler(workload, started_ms)


__all__ = [
    "SCENARIO_DISPATCH",
    "dispatch_scenario",
    "run_ddos_tcp",
    "run_ddos_icmp",
    "run_ddos_udp",
    "run_ddos_http",
    "run_sql_injection",
    "run_xss",
    "run_vulnerability_scanner",
    "run_uploading",
    "run_password",
    "run_port_scanning",
    "run_fingerprinting",
    "run_backdoor",
    "run_ransomware",
    "run_mitm",
]
