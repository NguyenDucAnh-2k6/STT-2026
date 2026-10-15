"""Reverse fixture channel. Fixed commands, disposable generated files, no shell."""
import base64
import hashlib
import json
import random
import socket
import tempfile
import threading
from pathlib import Path
from typing import Any

from .flows import FlowRecorder, lab_socket

CONTRACTS = {"Backdoor": "reverse-fixture-channel-v1", "Ransomware": "aes-gcm-fixture-roundtrip-v1",
             "MITM": "dns-diversion-observed-v1", "Fingerprinting": "tcp-icmp-response-probes-v1"}


def receive(stream: Any) -> dict[str, Any]:
    line = stream.readline(65537)
    if not line.endswith(b"\n") or len(line) > 65536:
        raise ValueError("Missing/oversized fixture frame")
    message = json.loads(line)
    if not isinstance(message, dict):
        raise ValueError("Expected fixture object")
    return message


def send(connection: Any, message: dict[str, Any]) -> None:
    encoded = json.dumps(message).encode() + b"\n"
    if len(encoded) > 65536:
        raise ValueError("Oversized fixture frame")
    connection.sendall(encoded)


class DisposableFiles:
    """Own only newly created fixed-name files in our temporary directory."""
    def __init__(self, seed: int) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="aero-fixtures-")
        self.root = Path(self.directory.name)
        rng = random.Random(seed)
        self.originals = {f"fixture-{index}.bin": rng.randbytes(rng.choice([256, 1024, 4096])) for index in range(3)}
        for name, body in self.originals.items():
            (self.root / name).write_bytes(body)
        self.encrypted: dict[str, bytes] = {}
        self.key: bytes | None = None

    def action(self, command: str) -> dict[str, Any]:
        if command == "inventory":
            return {"ok": True, "files": len(self.originals), "bytes": sum(map(len, self.originals.values()))}
        if command == "read_fixture":
            return {"ok": True, "data": base64.b64encode(next(iter(self.originals.values()))).decode()}
        if command == "encrypt_fixture":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import secrets
            self.key = AESGCM.generate_key(bit_length=256)
            cipher = AESGCM(self.key)
            for name, original in self.originals.items():
                nonce = secrets.token_bytes(12)
                ciphertext = nonce + cipher.encrypt(nonce, original, name.encode())
                (self.root / name).write_bytes(ciphertext)
                self.encrypted[name] = ciphertext
            return {"ok": True, "encrypted_files": len(self.encrypted), "algorithm": "AES-256-GCM",
                    "changed": all((self.root / name).read_bytes() != value for name, value in self.originals.items())}
        if command == "read_ciphertext" and self.encrypted:
            return {"ok": True, "data": base64.b64encode(next(iter(self.encrypted.values()))).decode()}
        if command == "restore_fixture" and self.key:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            for name in self.originals:
                data = (self.root / name).read_bytes()
                restored = AESGCM(self.key).decrypt(data[:12], data[12:], name.encode())
                (self.root / name).write_bytes(restored)
            return {"ok": True, "restored_files": len(self.originals),
                    "roundtrip_ok": all((self.root / name).read_bytes() == body for name, body in self.originals.items())}
        return {"ok": False, "error": "unsupported_fixture_command"}

    def close(self) -> None:
        self.key = None
        self.directory.cleanup()


def reverse_exchange(port: int, recorder: FlowRecorder, scenario: str, seed: int, cancel: threading.Event) -> dict[str, Any]:
    """Agent connects back to our listener; controller accepts no external client."""
    errors: list[Exception] = []
    nonce = hashlib.sha256(str(seed).encode()).hexdigest()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(2)
        def agent() -> None:
            connection = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
            fixtures = None
            try:
                fixtures = DisposableFiles(seed)
                connection.settimeout(2)
                connection.connect(("127.0.0.1", port))
                send(connection, {"hello": nonce})
                with connection.makefile("rb") as stream:
                    for _ in range(5):
                        command = receive(stream).get("command")
                        if command == "close":
                            break
                        if cancel.is_set():
                            raise InterruptedError("Fixture cancelled")
                        send(connection, fixtures.action(command))
            except Exception as error:
                errors.append(error)
            finally:
                connection.close()
                if fixtures:
                    fixtures.close()
        worker = threading.Thread(target=agent, name="twin-reverse-fixture")
        worker.start()
        try:
            with listener.accept()[0] as client, client.makefile("rb") as stream:
                client.settimeout(2)
                if receive(stream).get("hello") != nonce:
                    raise ValueError("Wrong fixture client")
                commands = ["inventory", "read_fixture"] if scenario == "Backdoor" else ["inventory", "encrypt_fixture", "read_ciphertext", "restore_fixture"]
                replies = []
                for command in commands:
                    send(client, {"command": command})
                    reply = receive(stream)
                    if not reply.get("ok"):
                        raise ValueError("Fixture command failed")
                    replies.append(reply)
                send(client, {"command": "close"})
                if scenario == "Ransomware" and not (replies[1].get("changed") and replies[-1].get("roundtrip_ok")):
                    raise ValueError("Encryption/restoration evidence missing")
                return {"evidence_contract": CONTRACTS[scenario], "fixture_effect_ok": True,
                        "completed_commands": len(commands), "files": replies[0]["files"], "user_files_touched": False}
        finally:
            worker.join(timeout=3)
            if worker.is_alive():
                raise RuntimeError("Reverse fixture worker did not stop")
            if errors:
                raise RuntimeError("Reverse fixture agent failed") from errors[0]
