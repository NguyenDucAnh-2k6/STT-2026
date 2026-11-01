"""Unit tests for multi-mode Data Lake partitioning and training concatenation."""
import os
import tempfile
import unittest
import pandas as pd
import numpy as np

from data_lake.lakehouse import DataLakeManager, resolve_record_traffic_mode
from data_lake.quality import (
    select_training_records,
    TRAINING_REQUIRED_COLUMNS_DECRYPTED,
    TRAINING_REQUIRED_COLUMNS_ENCRYPTED,
    TRAINING_REQUIRED_COLUMNS_WIRELESS
)
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, AWID3_WIFI_FEATURES


class TestLakehouseMultiMode(unittest.TestCase):
    def test_resolve_record_traffic_mode(self):
        # 1. Decrypted
        row_dec = {"feature_semantics": "edgeiiot-packet-v1"}
        self.assertEqual(resolve_record_traffic_mode(row_dec), "decrypted")

        # 2. Encrypted
        row_enc = {"feature_semantics": "esp32-l234-packet-v1"}
        self.assertEqual(resolve_record_traffic_mode(row_enc), "encrypted")

        # 3. Wireless
        row_wifi = {"feature_semantics": "awid3-wifi-v1"}
        self.assertEqual(resolve_record_traffic_mode(row_wifi), "wireless")

    def test_partitioned_lake_flush_and_loading(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lake = DataLakeManager(base_dir=temp_dir)
            lake.start_session()

            # Record 1: Decrypted row
            dec_row = {
                "device_id": "host-01",
                "packet_id": "pkt-01",
                "timestamp": 1_700_000_000_000,
                "record_kind": "packet",
                "feature_semantics": "edgeiiot-packet-v1",
                "schema_version": 2,
                "capture_backend": "tshark",
                "label_source": "controlled_flow",
                "missing_features": [],
                "ground_truth_scenario": "Normal"
            }
            for feat in EDGE_IIOTSET_FEATURES:
                dec_row[feat] = 1.0
            lake.record_telemetry(dec_row, ground_truth="Normal")

            # Record 2: Encrypted row
            enc_row = {
                "device_id": "esp32-01",
                "packet_id": "pkt-02",
                "timestamp": 1_700_000_000_100,
                "record_kind": "packet",
                "feature_semantics": "esp32-l234-packet-v1",
                "schema_version": 2,
                "capture_backend": "esp32_sniffer",
                "label_source": "controlled_flow",
                "missing_features": [],
                "ground_truth_scenario": "Cridex"
            }
            for feat in ESP32_PACKET_FEATURES:
                enc_row[feat] = 2.0
            lake.record_telemetry(enc_row, ground_truth="Cridex")

            # Record 3: Wireless row
            wifi_row = {
                "device_id": "wifi-probe-01",
                "packet_id": "pkt-03",
                "timestamp": 1_700_000_000_200,
                "record_kind": "packet",
                "feature_semantics": "awid3-wifi-v1",
                "schema_version": 2,
                "capture_backend": "wifi_sniffer",
                "label_source": "controlled_flow",
                "missing_features": [],
                "ground_truth_scenario": "Deauth"
            }
            for feat in AWID3_WIFI_FEATURES:
                wifi_row[feat] = 3.0
            lake.record_telemetry(wifi_row, ground_truth="Deauth")

            # Flush to disk
            lake.flush()

            # Verify partitioned directories exist
            raw_dir = lake.raw_dir
            self.assertTrue(os.path.exists(os.path.join(raw_dir, "decrypted")))
            self.assertTrue(os.path.exists(os.path.join(raw_dir, "encrypted")))
            self.assertTrue(os.path.exists(os.path.join(raw_dir, "wireless")))

            # Load labeled dataset for decrypted
            dec_loaded = lake.load_labeled_dataset(traffic_mode="decrypted")
            self.assertEqual(len(dec_loaded), 1)
            self.assertEqual(dec_loaded.iloc[0]["ground_truth_scenario"], "Normal")

            # Load labeled dataset for encrypted
            enc_loaded = lake.load_labeled_dataset(traffic_mode="encrypted")
            self.assertEqual(len(enc_loaded), 1)
            self.assertEqual(enc_loaded.iloc[0]["ground_truth_scenario"], "Cridex")

            # Load labeled dataset for wireless
            wifi_loaded = lake.load_labeled_dataset(traffic_mode="wireless")
            self.assertEqual(len(wifi_loaded), 1)
            self.assertEqual(wifi_loaded.iloc[0]["ground_truth_scenario"], "Deauth")


if __name__ == "__main__":
    unittest.main()
