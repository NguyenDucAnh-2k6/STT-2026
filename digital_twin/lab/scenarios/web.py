"""Web application attack scenario generators for digital twin lab."""
import json
from typing import Any


def run_sql_injection(workload: Any) -> int:
    """SQL injection attack using diverse syntax variants."""
    for _ in range(8):
        if workload.cancel.is_set():
            break
        variant = workload.variants.next("SQL_injection")
        workload.request(variant.wire_request("127.0.0.1", workload.port), variant.context())
    return 8


def run_xss(workload: Any) -> int:
    """Cross-Site Scripting (XSS) attack vectors into reflection fixture."""
    for _ in range(8):
        if workload.cancel.is_set():
            break
        variant = workload.variants.next("XSS")
        workload.request(variant.wire_request("127.0.0.1", workload.port), variant.context())
    return 8


def run_vulnerability_scanner(workload: Any) -> int:
    """Web vulnerability discovery probes against sensitive paths."""
    paths = ["/robots.txt", "/admin", "/.git/config", "/.env", "/backup", "/server-status"]
    count = 0
    for path in paths:
        if workload.cancel.is_set():
            break
        workload.http("GET", path)
        count += 1
    return count


def run_uploading(workload: Any) -> int:
    """Multipart form file upload attempt containing inert PHP marker."""
    boundary = "----" + str(workload.rng.getrandbits(64))
    payload = b"<?php /* INERT LOCAL FIXTURE: not executed */ ?>" + workload.rng.randbytes(512)
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="sample.php"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
        + payload
        + f"\r\n--{boundary}--\r\n".encode()
    )
    workload.http("POST", "/lab/upload", body, f"multipart/form-data; boundary={boundary}")
    return 1


def run_password(workload: Any) -> int:
    """Dictionary and trial password brute-force attack."""
    passwords = ["password", "admin", "test", "123456", str(workload.rng.getrandbits(32)), "lab-password"]
    count = 0
    for password in passwords:
        if workload.cancel.is_set():
            break
        workload.http("POST", "/lab/login", json.dumps({"username": "lab-user", "password": password}).encode())
        count += 1
    return count
