"""Benign localhost exchanges and mocked SQLi/XSS dispatch, no exploit traffic."""
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from digital_twin.lab.flows import FlowRecorder
from digital_twin.lab.http_target import LabRequestHandler
from firmware.simulator.attack_traffic_generator import _send_http_request, burst_sql_injection, burst_xss_attack


class LabHttpLifecycleTests(unittest.TestCase):
    def test_benign_exchange_reads_body_before_close_and_tracks_flow(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), LabRequestHandler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
        worker.start()
        recorder = FlowRecorder()
        before = LabRequestHandler.client_disconnects
        try:
            request = b"GET /bytes/16384 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            self.assertTrue(_send_http_request("127.0.0.1", server.server_port, request, recorder,
                request_context={"request_variant_id": "benign-test", "request_template_family": "benign"}))
            self.assertTrue(recorder.snapshot())
            self.assertEqual(recorder.snapshot()[0]["request_variant_id"], "benign-test")
            self.assertEqual(LabRequestHandler.client_disconnects, before)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)
        self.assertFalse(worker.is_alive())

    def test_sqli_and_xss_use_complete_exchange_and_honor_cancel(self) -> None:
        with patch("firmware.simulator.attack_traffic_generator._send_http_request", return_value=True) as send:
            for burst in [burst_sql_injection, burst_xss_attack]:
                send.reset_mock()
                self.assertEqual(burst("127.0.0.1", 8088, count=2), 2)
                self.assertEqual(send.call_count, 2)
                self.assertIn(b"Connection: close", send.call_args.args[2])
                cancel = threading.Event()
                cancel.set()
                self.assertEqual(burst("127.0.0.1", 8088, count=2, cancel_event=cancel), 0)
                self.assertEqual(send.call_count, 2)

    def test_disconnect_is_handled_but_programming_errors_propagate(self) -> None:
        handler = object.__new__(LabRequestHandler)
        before = LabRequestHandler.client_disconnects
        with patch("http.server.BaseHTTPRequestHandler.handle_one_request", side_effect=ConnectionAbortedError(10053, "peer closed")):
            handler.handle_one_request()
        self.assertTrue(handler.close_connection)
        self.assertEqual(LabRequestHandler.client_disconnects, before + 1)
        with patch("http.server.BaseHTTPRequestHandler.handle_one_request", side_effect=RuntimeError("unexpected bug")):
            with self.assertRaisesRegex(RuntimeError, "unexpected bug"):
                handler.handle_one_request()

    def test_incomplete_response_fails_and_releases_resources(self) -> None:
        connection = MagicMock()
        response = MagicMock()
        response.length = 3
        response.read.return_value = b"x"
        with patch("firmware.simulator.attack_traffic_generator.lab_socket", return_value=connection), \
             patch("firmware.simulator.attack_traffic_generator.http.client.HTTPResponse", return_value=response):
            self.assertFalse(_send_http_request("127.0.0.1", 8088, b"GET / HTTP/1.1\r\n\r\n"))
        response.close.assert_called_once()
        connection.close.assert_called_once()
