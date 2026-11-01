"""
Tests for Artifact Registry and Dataset/Profile Routing
======================================================
Verifies deterministic resolution of model artifacts, profile compatibility,
and blocking of synthetic/demo directories from production inference.
"""

import os
import tempfile
import unittest
import json
from pathlib import Path

from ml_engine.config.artifacts import (
    inspect_artifact_dir,
    list_available_artifacts,
    resolve_artifact_dir,
    normalize_traffic_mode,
    normalize_profile
)
from ml_engine.config.edge_profiles import (
    ESP32_PACKET_PROFILE,
    HOST_DPI_PROFILE,
    AWID3_WIFI_PROFILE
)


class ArtifactRegistryTests(unittest.TestCase):
    def test_normalize_traffic_mode_and_profile(self) -> None:
        self.assertEqual(normalize_traffic_mode("awid3"), "wireless")
        self.assertEqual(normalize_traffic_mode("wifi"), "wireless")
        self.assertEqual(normalize_traffic_mode("wireless"), "wireless")
        self.assertEqual(normalize_traffic_mode("ustc-tfc2016"), "encrypted")
        self.assertEqual(normalize_traffic_mode("esp32"), "encrypted")
        self.assertEqual(normalize_traffic_mode("decrypted"), "decrypted")
        self.assertEqual(normalize_traffic_mode("edge-iiotset"), "decrypted")

        self.assertEqual(normalize_profile("awid3"), AWID3_WIFI_PROFILE)
        self.assertEqual(normalize_profile("encrypted"), ESP32_PACKET_PROFILE)
        self.assertEqual(normalize_profile("decrypted"), HOST_DPI_PROFILE)

    def test_inspect_valid_and_demo_artifacts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        models_root = root / "ml_engine" / "models"

        # 1. Edge-IIoTset unpartitioned root model
        edge_model = models_root / "random_forest_isolation_forest"
        if edge_model.is_dir():
            desc = inspect_artifact_dir(str(edge_model))
            self.assertIsNotNone(desc)
            self.assertEqual(desc.traffic_mode, "decrypted")
            self.assertEqual(desc.profile, "edgeiiot-packet-v1")
            self.assertFalse(desc.is_demo)

        # 2. Encrypted model
        enc_model = models_root / "encrypted" / "random_forest_isolation_forest"
        if enc_model.is_dir():
            desc = inspect_artifact_dir(str(enc_model))
            self.assertIsNotNone(desc)
            self.assertEqual(desc.traffic_mode, "encrypted")
            self.assertEqual(desc.profile, "esp32-l234-packet-v1")
            self.assertFalse(desc.is_demo)

        # 3. Demo model
        demo_model = models_root / "esp32_rf_if_packet_demo"
        if demo_model.is_dir():
            desc = inspect_artifact_dir(str(demo_model))
            self.assertIsNotNone(desc)
            self.assertTrue(desc.is_demo)

    def test_resolve_artifact_dir_selects_correct_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            
            # Create decrypted bundle
            dec_dir = tmp_path / "decrypted" / "random_forest_isolation_forest"
            dec_dir.mkdir(parents=True)
            (dec_dir / "attack_classifier.joblib").write_text("dummy")
            (dec_dir / "isolation_forest.joblib").write_text("dummy")
            (dec_dir / "scaler.joblib").write_text("dummy")
            (dec_dir / "model_metadata.json").write_text(json.dumps({
                "traffic_mode": "decrypted",
                "profile": "edgeiiot-packet-v1",
                "features_count": 56,
                "classifier_type": "random_forest",
                "anomaly_detector_type": "isolation_forest"
            }))

            # Create encrypted bundle
            enc_dir = tmp_path / "encrypted" / "decision_tree_isolation_forest"
            enc_dir.mkdir(parents=True)
            (enc_dir / "attack_classifier.joblib").write_text("dummy")
            (enc_dir / "isolation_forest.joblib").write_text("dummy")
            (enc_dir / "scaler.joblib").write_text("dummy")
            (enc_dir / "model_metadata.json").write_text(json.dumps({
                "traffic_mode": "encrypted",
                "profile": "esp32-l234-packet-v1",
                "features_count": 10,
                "classifier_type": "decision_tree",
                "anomaly_detector_type": "isolation_forest"
            }))

            # Resolving decrypted
            dir_dec, desc_dec = resolve_artifact_dir(traffic_mode="decrypted", base_models_dir=tmp)
            self.assertEqual(desc_dec.traffic_mode, "decrypted")
            self.assertEqual(desc_dec.features_count, 56)
            self.assertFalse(desc_dec.is_demo)

            # Resolving encrypted
            dir_enc, desc_enc = resolve_artifact_dir(traffic_mode="encrypted", base_models_dir=tmp)
            self.assertEqual(desc_enc.traffic_mode, "encrypted")
            self.assertEqual(desc_enc.features_count, 10)
            self.assertFalse(desc_enc.is_demo)

    def test_resolve_blocks_demo_unless_preferred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            demo_dir = tmp_path / "esp32_test_demo"
            demo_dir.mkdir()
            (demo_dir / "attack_classifier.joblib").write_text("dummy")
            (demo_dir / "isolation_forest.joblib").write_text("dummy")
            (demo_dir / "scaler.joblib").write_text("dummy")
            (demo_dir / "model_metadata.json").write_text(json.dumps({
                "traffic_mode": "encrypted",
                "profile": "esp32-l234-packet-v1",
                "demo_scope": "Simulated vectors"
            }))

            desc = inspect_artifact_dir(str(demo_dir))
            self.assertIsNotNone(desc)
            self.assertTrue(desc.is_demo)

            # Default resolution should reject demo
            with self.assertRaises(ValueError):
                resolve_artifact_dir(traffic_mode="encrypted", base_models_dir=str(tmp_path), prefer_demo=False)

            # Explicit prefer_demo=True should accept it
            resolved, d = resolve_artifact_dir(traffic_mode="encrypted", base_models_dir=str(tmp_path), prefer_demo=True)
            self.assertEqual(resolved, str(demo_dir))
            self.assertTrue(d.is_demo)


if __name__ == "__main__":
    unittest.main()
