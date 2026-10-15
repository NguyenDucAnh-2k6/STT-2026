"""Operator review preserves known lab traffic/attack labels and reversible data."""
import tempfile
import unittest
from pathlib import Path

from data_lake.lakehouse import DataLakeManager
from data_lake.relabel import relabel_operator_normal


class OperatorNormalTests(unittest.TestCase):
    def test_review_catalog_backup_and_idempotence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lake = DataLakeManager(directory)
            for port, truth in [(443, "Unknown"), (8088, "Unknown"), (8088, "DDoS_UDP")]:
                lake.record_telemetry({"device_id": "fixture", "record_kind": "packet", "timestamp": 1800000000000,
                    "src_port": 12000, "dst_port": port, "label_source": "unverified",
                    "raw_http_body": "  private test body\n"}, ground_truth=truth)
            lake.close_session()
            original_path = next((root/"raw").rglob("*.parquet"))
            original = original_path.read_bytes()
            preview = relabel_operator_normal(root)
            self.assertEqual(preview["normal_rows"], 1)
            self.assertEqual(original_path.read_bytes(), original)
            report = relabel_operator_normal(root, apply=True)
            self.assertEqual(report["normal_rows"], 1)
            self.assertEqual(report["skipped_lab_unknown"], 1)
            frame = lake.load_all_training_data()
            self.assertEqual(frame.ground_truth_scenario.tolist(), ["Normal", "Unknown", "DDoS_UDP"])
            self.assertEqual(frame.iloc[0].label_source, "manual_review")
            self.assertEqual(frame.iloc[0].previous_ground_truth_scenario, "Unknown")
            self.assertTrue(frame.raw_http_body.eq("  private test body\n").all())
            backup = root/"label_backups"/report["annotation_id"]/original_path.relative_to(root/"raw")
            self.assertEqual(backup.read_bytes(), original)
            self.assertEqual(lake.get_summary_stats()["normal_records"], 1)
            self.assertEqual(relabel_operator_normal(root, apply=True)["normal_rows"], 0)
