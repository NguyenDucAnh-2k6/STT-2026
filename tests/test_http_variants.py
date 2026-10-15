"""Generate diverse requests offline. No sockets, browser rendering or exploit execution."""
import json
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from firmware.simulator.http_variants import HttpVariantGenerator, SQL_FAMILIES, XSS_FAMILIES, USER_AGENTS
from firmware.simulator.attack_traffic_generator import burst_sql_injection, burst_xss_attack
from digital_twin.lab.flows import FlowRecorder, packet_label


class HttpVariantTests(unittest.TestCase):
    def test_reproducible_diverse_and_structurally_valid_requests(self) -> None:
        for scenario, families in [("SQL_injection", SQL_FAMILIES), ("XSS", XSS_FAMILIES)]:
            generator = HttpVariantGenerator(42)
            replay = HttpVariantGenerator(42)
            identifiers = set()
            locations = set()
            observed_families = set()
            for _ in range(10000):
                variant = generator.next(scenario)
                self.assertEqual(variant, replay.next(scenario))
                wire = variant.wire_request("127.0.0.1", 8088)
                headers, body = wire.split(b"\r\n\r\n", 1)
                self.assertEqual(body, variant.body)
                self.assertLess(len(wire), 8192)
                self.assertNotIn(b"Sqlmap", wire)
                self.assertIn(variant.user_agent, USER_AGENTS)
                if variant.placement == "json":
                    values = json.loads(body)
                elif variant.placement == "form":
                    values = parse_qs(body.decode())
                else:
                    values = parse_qs(urlsplit(variant.uri).query)
                self.assertEqual(len(values), 2)
                if body:
                    self.assertIn(f"Content-Length: {len(body)}".encode(), headers)
                identifiers.add(variant.variant_id)
                locations.add(variant.placement)
                observed_families.add(variant.family)
            self.assertEqual(len(identifiers), 10000)
            self.assertEqual(locations, {"query", "form", "json"})
            self.assertEqual(observed_families, set(families))
            print(scenario, "10000 unique variants;", len(families), "families; all placements")

    def test_generator_continues_across_bursts(self) -> None:
        for burst in (burst_sql_injection, burst_xss_attack):
            generator = HttpVariantGenerator(7)
            with patch("firmware.simulator.attack_traffic_generator._send_http_request", return_value=True) as send:
                burst("127.0.0.1", 8088, count=8, variant_generator=generator)
                first = {call.args[2] for call in send.call_args_list}
                send.reset_mock()
                burst("127.0.0.1", 8088, count=8, variant_generator=generator)
                second = {call.args[2] for call in send.call_args_list}
            self.assertFalse(first & second)
            self.assertEqual(generator.metadata()["generated_requests"], 16)

    def test_variant_context_tracks_flow_but_is_not_model_feature(self) -> None:
        recorder = FlowRecorder()
        recorder.record(("127.0.0.1", 1234), ("127.0.0.1", 8088), "tcp", 1)
        context = HttpVariantGenerator(42).next("XSS").context()
        recorder.annotate_request(("127.0.0.1", 1234), ("127.0.0.1", 8088), "tcp", context)
        packet = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 1234, "dst_port": 8088,
                  "protocol_stack": "ip:tcp:http", "timestamp": 2}
        label = packet_label(packet, recorder.snapshot(), "XSS")
        self.assertEqual(label["request_variant_id"], context["request_variant_id"])
        from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
        self.assertFalse(set(context) & set(EDGE_IIOTSET_FEATURES))
