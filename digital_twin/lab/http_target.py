"""Benign HTTP lab target shared by native and isolated Docker experiments."""
import argparse
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
if __package__:
    from .fixture_app import FixtureState, query_fixture, request_values, QUERY_KEYS
else:
    from fixture_app import FixtureState, query_fixture, request_values, QUERY_KEYS

LOG = logging.getLogger(__name__)


class LabRequestHandler(BaseHTTPRequestHandler):
    count = 0
    count_lock = threading.Lock()
    client_disconnects = 0

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError) as error:
            # Peers may cancel/close during header or body writes. This is a
            # connection outcome, not an uncaught server worker failure.
            self.close_connection = True
            with self.count_lock:
                type(self).client_disconnects += 1
            LOG.debug("Lab HTTP peer disconnected: %s", type(error).__name__)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= length <= 65536:
            self.send_error(413)
            return
        self.request_body = self.rfile.read(length)
        if len(self.request_body) != length:
            self.send_error(400)
            return
        self.do_GET()

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if len(self.path) > 8192:
            self.send_error(414)
            return
        with self.count_lock:
            type(self).count += 1
            count = type(self).count
        body = json.dumps({"service": "AERO-local-lab", "request_count": count,
                           "path": path, "executes_injected_content": False}).encode()
        content_type = "application/json"
        request_body = getattr(self, "request_body", b"")
        try:
            values = request_values(urlsplit(self.path).query, request_body, self.headers.get("Content-Type", ""))
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        if not hasattr(self.server, "fixture_state"):
            # Initialization guarded across request workers, and scoped to this server.
            with self.count_lock:
                if not hasattr(self.server, "fixture_state"):
                    self.server.fixture_state = FixtureState()
        if path.startswith("/lab/"):
            body = json.dumps(self.server.fixture_state.action(path, values, request_body)).encode()
            if path == "/lab/sensor":
                body = json.dumps({"temperature": 21 if self.server.server_address[0] == "127.0.0.2" else 20}).encode()
        elif any(key in values for key in QUERY_KEYS):
            value = str(next(values[key] for key in QUERY_KEYS if key in values))
            if path in ("/comments", "/feedback", "/profile"):
                # Deliberate reflection confined to disposable local lab content.
                body = ("<!doctype html><html><body>" + value[:4096] + "</body></html>").encode()
                content_type = "text/html; charset=utf-8"
            else:
                body = json.dumps(query_fixture(value)).encode()
        if path.startswith("/bytes/"):
            try:
                size = int(path.rsplit("/", 1)[1])
                if not 0 <= size <= 65536:
                    raise ValueError()
            except ValueError:
                self.send_error(400)
                return
            body = b"N" * size
            content_type = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Security-Policy", "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-AERO-Lab", "normal-http-v1")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.bind, args.port), LabRequestHandler)
    server.daemon_threads = True
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
