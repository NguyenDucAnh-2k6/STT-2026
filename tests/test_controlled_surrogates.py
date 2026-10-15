import socket
import threading
import unittest
from unittest.mock import patch

import pandas as pd

from digital_twin.lab.controlled_channel import DisposableFiles, reverse_exchange, CONTRACTS
from digital_twin.lab.flows import FlowRecorder
from digital_twin.lab.services import LabServices
from digital_twin.lab.workloads import TwinWorkloads
from data_lake.quality import select_training_records
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES


class ControlledSurrogateTests(unittest.TestCase):
    def test_fixture_crypto_restores_and_rejects_arbitrary_paths(self) -> None:
        fixture = DisposableFiles(42)
        root = fixture.root
        try:
            self.assertFalse(fixture.action("exec")["ok"])
            self.assertFalse(fixture.action("../../file")["ok"])
            self.assertTrue(fixture.action("encrypt_fixture")["changed"])
            self.assertTrue(fixture.action("restore_fixture")["roundtrip_ok"])
        finally:
            fixture.close()
        self.assertFalse(root.exists())

    def test_reverse_channel_has_owned_flows_and_effect(self) -> None:
        for scenario in ("Backdoor", "Ransomware"):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            recorder = FlowRecorder()
            evidence = reverse_exchange(port, recorder, scenario, 42, threading.Event())
            self.assertEqual(evidence["evidence_contract"], CONTRACTS[scenario])
            self.assertTrue(evidence["fixture_effect_ok"])
            self.assertEqual(len(recorder.snapshot()), 1)
            self.assertEqual(recorder.snapshot()[0]["dst_port"], port)

    def test_dns_diversion_has_observed_service_effect(self) -> None:
        recorder = FlowRecorder()
        with patch.dict("os.environ", {"TWIN_SCAN_PORT_COUNT": "3"}):
            lab = LabServices(24388, set(), recorder, dns_proxy=True)
            try:
                lab.start()
                runner = TwinWorkloads(lab.port, recorder, threading.Event(), 42)
                self.assertGreater(runner.burst("MITM"), 0)
                flows = recorder.snapshot()
                self.assertTrue(any(f["dst_ip"] == "127.0.0.2" for f in flows))
                self.assertTrue(all(f["fixture_effect_ok"] for f in flows))
            finally:
                lab.close()

    def test_true_flag_does_not_promote_old_or_unproven_rows(self) -> None:
        row = {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1",
               "schema_version": 2, "device_id": "fixture", "packet_id": "1", "timestamp": 1800000000000,
               "capture_backend": "pcap", "label_source": "controlled_flow", "ground_truth_scenario": "Backdoor",
               "missing_features": [], "data_provenance": "twin-controlled-lab", "supervised_training_eligible": True,
               "experiment_manifest_version": 4}
        self.assertTrue(select_training_records(pd.DataFrame([row]))[0].empty)
        row.update(evidence_contract=CONTRACTS["Backdoor"], fixture_effect_ok=True)
        self.assertEqual(len(select_training_records(pd.DataFrame([row]))[0]), 1)
        row["experiment_manifest_version"] = 3
        self.assertTrue(select_training_records(pd.DataFrame([row]))[0].empty)


if __name__ == "__main__":
    unittest.main()
