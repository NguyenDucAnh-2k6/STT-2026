"""Local HTTP test endpoint; records request counts, never executes injected content."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from .lab_config import http_port


class LabRequestHandler(BaseHTTPRequestHandler):
    count = 0
    count_lock = threading.Lock()

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(3)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 <= length <= 65536:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return
        # Uploaded bytes are neither saved nor executed by this endpoint.
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
                           "path": path, "executes_injected_content": False}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        # Query strings and packet content are not written to console logs.
        return


def main() -> None:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    # Local endpoint deliberately binds only loopback.
    server = ThreadingHTTPServer(("127.0.0.1", http_port()), LabRequestHandler)
    server.daemon_threads = True
    print(f"Local lab HTTP: http://127.0.0.1:{server.server_port}/health")
    print("HTTP workload endpoint; SQLi/XSS strings are never executed.")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
