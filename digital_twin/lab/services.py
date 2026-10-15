"""Owned loopback web/UDP services and reserved open/closed scan ports."""
import socket
import threading
from http.server import ThreadingHTTPServer
from typing import Any

from .http_target import LabRequestHandler
from .profile import scan_ports
from .dns_fixture import DNSFixture, query
from .flows import FlowRecorder


class LabServices:
    def __init__(self, port: int, protected_ports: set[int], recorder: FlowRecorder | None = None,
                 dns_proxy: bool = False, reverse_channel: bool = False) -> None:
        self.port = port
        self.protected_ports = protected_ports
        self.servers: list[ThreadingHTTPServer] = []
        self.threads: list[threading.Thread] = []
        self.reservations: list[socket.socket] = []
        self.udp: socket.socket | None = None
        self.stop = threading.Event()
        self.udp_received = 0
        self.resolver = DNSFixture(port + 2, recorder) if dns_proxy else None
        self.reverse_channel = reverse_channel

    def start(self) -> None:
        ports = scan_ports(self.port)
        if self.protected_ports.intersection(ports):
            raise ValueError("Twin port range overlaps dashboard/MQTT; change LAB_HTTP_PORT")
        try:
            for port in ports:
                if port in (self.port, self.port + 1):
                    server = ThreadingHTTPServer(("127.0.0.1", port), LabRequestHandler)
                    server.daemon_threads = True
                    self.servers.append(server)
                    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, name="twin-web")
                    thread.start()
                    self.threads.append(thread)
                else:
                    if self.reverse_channel and port == self.port + 2:
                        continue  # Owned by the bounded reverse-channel listener.
                    # Bound but not listening: closed probes cannot hit unrelated services.
                    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.reservations.append(reservation)
                    reservation.bind(("127.0.0.1", port))
            if self.resolver:
                server = ThreadingHTTPServer(("127.0.0.2", self.port), LabRequestHandler)
                server.daemon_threads = True
                self.servers.append(server)
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, name="twin-diverted-web")
                thread.start()
                self.threads.append(thread)
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind(("127.0.0.1", self.port))
            self.udp.settimeout(.1)
            if self.resolver:
                self.resolver.start()
            thread = threading.Thread(target=self._udp_loop, name="twin-udp")
            thread.start()
            self.threads.append(thread)
        except OSError as error:
            self.close()
            raise RuntimeError("Cannot own Twin port range; stop conflicting lab service or change LAB_HTTP_PORT") from error

    def _udp_loop(self) -> None:
        while not self.stop.is_set():
            try:
                data, address = self.udp.recvfrom(65536)
                self.udp_received += 1
                if self.resolver:
                    if not 12 <= len(data) <= 512 or data[12:] != query(1)[12:]:
                        continue
                    try:
                        self.udp.sendto(self.resolver.tamper(data), address)
                    except socket.timeout:
                        continue
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise

    def close(self) -> None:
        self.stop.set()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        if self.udp:
            self.udp.close()
        if self.resolver:
            self.resolver.close()
        for reservation in self.reservations:
            reservation.close()
        for thread in self.threads:
            thread.join(timeout=2)

    def evidence(self) -> dict[str, Any]:
        return {"owned_ports": scan_ports(self.port), "open_tcp_ports": [self.port, self.port+1],
                "udp_received": self.udp_received}
