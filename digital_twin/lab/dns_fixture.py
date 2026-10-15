"""Owned resolver and tampering relay; never changes host DNS/ARP configuration."""
import socket
import struct
import threading
from .flows import lab_socket, FlowRecorder


def query(identifier: int) -> bytes:
    return struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + b"\x06sensor\x04test\0" + struct.pack("!HH", 1, 1)


class DNSFixture:
    def __init__(self, port: int, recorder: FlowRecorder | None) -> None:
        self.port, self.recorder = port, recorder
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None

    def start(self) -> None:
        self.receiver.bind(("127.0.0.1", self.port))
        self.receiver.settimeout(.1)
        self.worker = threading.Thread(target=self._serve, name="twin-dns-resolver")
        self.worker.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                data, address = self.receiver.recvfrom(65536)
                if not 12 <= len(data) <= 512 or data[12:] != query(1)[12:]:
                    continue
                response = data[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + data[12:]
                response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
                self.receiver.sendto(response, address)
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise

    def tamper(self, data: bytes) -> bytes:
        sender = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, self.recorder)
        try:
            sender.settimeout(.5)
            sender.sendto(data, ("127.0.0.1", self.port))
            response, _ = sender.recvfrom(512)
            if response[:2] != data[:2] or response[-4:] != socket.inet_aton("127.0.0.1"):
                raise ValueError("Owned resolver baseline did not match")
            return response[:-4] + socket.inet_aton("127.0.0.2")
        finally:
            sender.close()

    def close(self) -> None:
        self.stop.set()
        self.receiver.close()
        if self.worker:
            self.worker.join(2)
