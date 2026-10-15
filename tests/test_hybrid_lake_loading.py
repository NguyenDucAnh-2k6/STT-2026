"""Projected lake reads and precise no-Normal messaging; no real model artifacts touched."""
import io
import tempfile
import time
import unittest
import warnings
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from data_lake.lakehouse import DataLakeManager
from data_lake.quality import TRAINING_REQUIRED_COLUMNS
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES


def record(number: int, label: str) -> dict:
    return {**dict.fromkeys(EDGE_IIOTSET_FEATURES, 0), "tcp.len": number,
        "record_kind": "packet", "feature_semantics": "edgeiiot-packet-v1", "schema_version": 2,
        "device_id": "test", "packet_id": str(number), "timestamp": int(time.time()*1000),
        "capture_backend": "pcap", "label_source": "controlled_flow", "ground_truth_scenario": label,
        "missing_features": []}


class HybridLakeLoadingTests(unittest.TestCase):
    def test_batch_projection_matches_packet_extraction_and_encoding(self) -> None:
        import numpy as np
        from ml_engine.train import lake_feature_frame, transform_lake_telemetry_batch
        from ml_engine.preprocessing import EdgeTrafficPreprocessor
        rows = [record(1, "Normal"), record(2, "DDoS_TCP"), record(3, "Normal")]
        rows[0].update({"http.request.method": "GET", "http.file_data": "000123", "tcp.checksum": "0x0a"})
        rows[1].update({"http.request.method": "POST", "http.file_data": " x & y ", "tcp.checksum": "0xff"})
        frame = pd.DataFrame(rows, index=[20, 8, 99])
        preprocessor = EdgeTrafficPreprocessor()
        legacy = pd.concat([preprocessor.extract_features(row.to_dict()) for _, row in frame.iterrows()], ignore_index=True)
        preprocessor.fit(legacy, frame.ground_truth_scenario.to_numpy())
        with patch.object(preprocessor, "extract_features", side_effect=AssertionError("per-packet extraction")):
            projected = lake_feature_frame(frame, preprocessor)
            actual = transform_lake_telemetry_batch(frame, preprocessor)
        self.assertEqual(list(projected.columns), EDGE_IIOTSET_FEATURES)
        self.assertNotIn("ground_truth_scenario", projected)
        np.testing.assert_allclose(actual, preprocessor.transform(legacy), rtol=0, atol=0)
        with self.assertRaises(ValueError):
            lake_feature_frame(frame.drop(columns=["tcp.len"]), preprocessor)

    def test_mixed_nullable_schemas_keep_rows_without_future_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lake = DataLakeManager(directory)
            pd.DataFrame([record(1, "Normal") | {"optional": None}]).to_parquet(Path(lake.raw_dir)/"old.parquet")
            pd.DataFrame([record(2, "DDoS_TCP") | {"optional": None, "raw_http_body": "new content"}]).to_parquet(Path(lake.raw_dir)/"new.parquet")
            with warnings.catch_warnings(record=True) as emitted:
                warnings.simplefilter("always")
                frame = lake.load_all_training_data()
            self.assertEqual(len(frame), 2)
            self.assertIn("optional", frame)
            self.assertTrue(frame.optional.isna().all())
            self.assertFalse(any(isinstance(item.message, FutureWarning) for item in emitted))
            projected = lake.load_labeled_dataset(columns=TRAINING_REQUIRED_COLUMNS)
            self.assertNotIn("raw_http_body", projected)
            self.assertEqual(len(projected), 2)

    def test_hybrid_loads_once_and_keeps_attack_rows_without_lake_normal(self) -> None:
        from ml_engine.train import run_training_pipeline
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lake = DataLakeManager(str(root/"lake"))
            pd.DataFrame([record(200+i, "DDoS_TCP") for i in range(4)]).to_parquet(Path(lake.raw_dir)/"attack.parquet")
            dataset = root/"benchmark.csv"
            pd.DataFrame([record(i, "Normal" if i % 2 == 0 else "DDoS_TCP") | {"Attack_type": "Normal" if i % 2 == 0 else "DDoS_TCP"} for i in range(96)]).to_csv(dataset, index=False)
            output = io.StringIO()
            with patch("ml_engine.train.get_lakehouse_manager", return_value=lake), \
                 patch.object(lake, "load_all_training_data", wraps=lake.load_all_training_data) as reading, \
                 patch("ml_engine.train.export_model_to_c_header"), \
                 patch("ml_engine.algorithms.feature_importance.plot_and_save_feature_importance", return_value=None), \
                 redirect_stdout(output):
                run_training_pipeline(dataset_path=str(dataset), output_dir=str(root/"models"), data_source="hybrid", cv=2, test_size=.25)
            self.assertEqual(reading.call_count, 1)
            self.assertIn("Khong co Normal hop le", output.getvalue())
            self.assertIn("Concat 4 mau CO NHAN", output.getvalue())
            self.assertNotIn("Kho du lieu chua co ban ghi thuc te", output.getvalue())
