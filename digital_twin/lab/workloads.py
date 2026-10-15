"""Measured, bounded loopback workloads with explicit surrogate effect contracts."""
import http.client
import random
import socket
import threading
import time

from firmware.simulator.http_variants import HttpVariantGenerator, USER_AGENTS
from .flows import FlowRecorder, lab_socket
from .scenarios import dispatch_scenario


class TwinWorkloads:
    """Orchestrator for measured digital twin attack and background workloads."""

    def __init__(self, port: int, recorder: FlowRecorder, cancel: threading.Event, seed: int) -> None:
        self.port = port
        self.recorder = recorder
        self.cancel = cancel
        self.rng = random.Random(seed)
        self.variants = HttpVariantGenerator(seed)
        self.completed = 0
        self.failed = 0
        self.lock = threading.Lock()
        self.icmp_id = (seed % 65534) + 1

    def request(self, request: bytes, context: dict | None = None, host: str = "127.0.0.1") -> dict:
        """Issue an HTTP wire request against loopback target and record telemetry."""
        if host not in ("127.0.0.1", "127.0.0.2"):
            raise ValueError("Fixture HTTP destination must be loopback")
        connection = lab_socket(socket.AF_INET, socket.SOCK_STREAM, self.recorder)
        response = None
        try:
            connection.settimeout(2)
            connection.connect((host, self.port))
            local = connection.getsockname()
            if context:
                self.recorder.annotate_request(local, (host, self.port), "tcp", context)
            connection.sendall(request)
            response = http.client.HTTPResponse(connection, method=request.split(b" ", 1)[0].decode("ascii"))
            response.begin()
            if response.getheader("X-AERO-Lab") != "normal-http-v1":
                raise ValueError("Target is not the owned AERO local lab")
            body = response.read(65537)
            if len(body) > 65536 or response.length not in (0, None):
                raise ValueError("Incomplete/oversized lab response")
            evidence = {"http_response_status": response.status, "response_body_bytes": len(body)}
            self.recorder.annotate_request(local, (host, self.port), "tcp", evidence)
            with self.lock:
                self.completed += 1
            return {**evidence, "body": body}
        except (OSError, http.client.HTTPException, ValueError):
            with self.lock:
                self.failed += 1
            return {}
        finally:
            if response:
                response.close()
            connection.close()

    def http(self, method: str, uri: str, body: bytes = b"", content_type: str = "application/json") -> dict:
        """Helper to construct and send a well-formed HTTP request with realistic headers."""
        headers = [
            f"{method} {uri} HTTP/1.1",
            f"Host: 127.0.0.1:{self.port}",
            f"User-Agent: {self.rng.choice(USER_AGENTS)}",
            "Connection: close",
        ]
        if body:
            headers += [f"Content-Length: {len(body)}", f"Content-Type: {content_type}"]
        return self.request(("\r\n".join(headers) + "\r\n\r\n").encode() + body)

    def burst(self, scenario: str) -> int:
        """Dispatch a single burst of the requested scenario workload."""
        before = self.completed
        started_ms = int(time.time() * 1000)
        result = dispatch_scenario(scenario, self, started_ms)
        diff = self.completed - before
        return result if result is not None and scenario in ("Port_Scanning", "DDoS_TCP", "DDoS_ICMP", "DDoS_UDP") else diff
