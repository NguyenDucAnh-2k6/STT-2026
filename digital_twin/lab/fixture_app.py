"""Disposable in-memory application fixtures; no shell or host file access."""
import base64
import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import closing
from urllib.parse import parse_qs

QUERY_KEYS = ("q", "value", "search", "name", "filter", "message", "input", "text")


def request_values(query: str, body: bytes, content_type: str) -> dict:
    values = {key: item[0] for key, item in parse_qs(query).items() if item}
    if "application/json" in content_type and body:
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        values.update(data)
    elif "application/x-www-form-urlencoded" in content_type and body:
        values.update({key: item[0] for key, item in parse_qs(body.decode("utf-8")).items() if item})
    return values


def query_fixture(value: str) -> dict:
    # Real SELECT injection against a new disposable database each request.
    # No ATTACH, file I/O, writes or extension loading are permitted.
    with closing(sqlite3.connect(":memory:")) as database:
        database.executescript("CREATE TABLE items(name TEXT); INSERT INTO items VALUES('alpha'),('beta'),('gamma');")
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        database.set_authorizer(lambda action, a, b, c, d: sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
        steps = [0]
        def progress() -> int:
            steps[0] += 1
            return int(steps[0] > 20)
        database.set_progress_handler(progress, 1000)
        try:
            rows = database.execute(f"SELECT name FROM items WHERE name LIKE '%{value[:4096]}%'").fetchmany(16)
            return {"result_count": len(rows), "database_error": False}
        except sqlite3.Error:
            return {"result_count": 0, "database_error": True}


class FixtureState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.uploaded_bytes = 0
        self.fixture = b"Disposable Twin fixture. No user files."

    def action(self, path: str, values: dict, body: bytes) -> dict:
        with self.lock:
            if path == "/lab/login":
                return {"authenticated": values.get("username") == "lab-user" and values.get("password") == "lab-password"}
            if path == "/lab/upload":
                # Inert multipart bytes kept as a count/hash, never a runnable file.
                self.uploaded_bytes += len(body)
                return {"uploaded_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "executed": False}
            if path == "/lab/channel":
                action = values.get("action")
                if action not in ("status", "list_fixture", "read_fixture"):
                    return {"accepted": False}
                return {"accepted": True, "fixture_bytes": len(self.fixture), "shell_execution": False}
            if path == "/lab/encrypt-fixture":
                # A reversible disposable byte fixture, not host-file ransomware.
                key = secrets.token_bytes(32)
                ciphertext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(self.fixture))
                restored = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(ciphertext))
                return {"fixture_encrypted": ciphertext != self.fixture, "roundtrip_ok": restored == self.fixture,
                        "ciphertext": base64.b64encode(ciphertext).decode(), "host_files_touched": False,
                        "algorithm": "fixture-xor-surrogate-not-rsa"}
            if path == "/lab/proxy":
                return {"relay_fixture": "sensor-temperature", "original_value": 20, "modified_value": 21,
                        "arp_dns_spoofing": False}
        return {}
