"""
Unit tests for AERO Multi-Stream Router
"""

import unittest
import tempfile
from pathlib import Path

from ml_engine.routing import (
    STREAM_DECRYPTED,
    STREAM_ENCRYPTED,
    STREAM_WIRELESS,
    ALL_STREAMS,
    normalize_stream,
    get_stream_spec,
    get_stream_models_dir,
    resolve_training_output_dir,
    clear_all_artifacts
)


class MultiStreamRoutingTests(unittest.TestCase):
    def test_normalize_stream_aliases(self) -> None:
        # Decrypted aliases
        self.assertEqual(normalize_stream("decrypted"), STREAM_DECRYPTED)
        self.assertEqual(normalize_stream("host"), STREAM_DECRYPTED)
        self.assertEqual(normalize_stream("dpi"), STREAM_DECRYPTED)
        self.assertEqual(normalize_stream("edge-iiotset"), STREAM_DECRYPTED)
        self.assertEqual(normalize_stream(None), STREAM_DECRYPTED)

        # Encrypted aliases
        self.assertEqual(normalize_stream("encrypted"), STREAM_ENCRYPTED)
        self.assertEqual(normalize_stream("ustc"), STREAM_ENCRYPTED)
        self.assertEqual(normalize_stream("ustc-tfc2016"), STREAM_ENCRYPTED)
        self.assertEqual(normalize_stream("esp32"), STREAM_ENCRYPTED)

        # Wireless aliases
        self.assertEqual(normalize_stream("wireless"), STREAM_WIRELESS)
        self.assertEqual(normalize_stream("wifi"), STREAM_WIRELESS)
        self.assertEqual(normalize_stream("wids"), STREAM_WIRELESS)
        self.assertEqual(normalize_stream("awid"), STREAM_WIRELESS)
        self.assertEqual(normalize_stream("awid3"), STREAM_WIRELESS)
        self.assertEqual(normalize_stream("802.11"), STREAM_WIRELESS)

    def test_stream_spec_features_and_profiles(self) -> None:
        dec = get_stream_spec("decrypted")
        self.assertEqual(dec.features_count, 56)
        self.assertEqual(dec.profile, "edgeiiot-packet-v1")
        self.assertEqual(dec.default_probe, "host")

        enc = get_stream_spec("encrypted")
        self.assertEqual(enc.features_count, 10)
        self.assertEqual(enc.profile, "esp32-l234-packet-v1")
        self.assertEqual(enc.default_probe, "esp32")

        wrl = get_stream_spec("wireless")
        self.assertEqual(wrl.features_count, 14)
        self.assertEqual(wrl.profile, "awid3-wifi-v1")
        self.assertEqual(wrl.default_probe, "esp32")

    def test_resolve_training_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = resolve_training_output_dir("wireless", "random_forest", "isolation_forest", base_models_dir=tmp)
            self.assertTrue(out_dir.is_dir())
            self.assertEqual(out_dir.name, "random_forest_isolation_forest")
            self.assertEqual(out_dir.parent.name, "wireless")

            out_dir_enc = resolve_training_output_dir("encrypted", "decision_tree", "isolation_forest", base_models_dir=tmp)
            self.assertTrue(out_dir_enc.is_dir())
            self.assertEqual(out_dir_enc.name, "decision_tree_isolation_forest")
            self.assertEqual(out_dir_enc.parent.name, "encrypted")

    def test_clear_all_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for s in ALL_STREAMS:
                s_dir = tmp_path / s / "dummy_combo"
                s_dir.mkdir(parents=True)
                (s_dir / "attack_classifier.joblib").write_text("model")
            
            report = clear_all_artifacts(base_models_dir=tmp)
            self.assertEqual(report[STREAM_DECRYPTED], 1)
            self.assertEqual(report[STREAM_ENCRYPTED], 1)
            self.assertEqual(report[STREAM_WIRELESS], 1)

            # Check that partitioned folders still exist with .gitkeep
            for s in ALL_STREAMS:
                self.assertTrue((tmp_path / s).is_dir())
                self.assertTrue((tmp_path / s / ".gitkeep").exists())
                self.assertFalse((tmp_path / s / "dummy_combo").exists())


if __name__ == "__main__":
    unittest.main()
