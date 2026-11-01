"""
Tests for AWID3 Dataset Preprocessor & 802.11 Frame Extractor
=============================================================
Validates extraction of IEEE 802.11 / Radiotap wireless features,
label mapping, and preprocessing transformation.
"""

import unittest
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pandas as pd

from ml_engine.config.edge_profiles import AWID3_WIFI_FEATURES, AWID3_WIFI_PROFILE
from ml_engine.config.schema import AWID3_LABELS
from ml_engine.preprocessing import AWID3TrafficPreprocessor


class AWID3PreprocessorTests(unittest.TestCase):
    def test_schema_conformance(self) -> None:
        self.assertEqual(len(AWID3_WIFI_FEATURES), 14)
        self.assertIn("frame.len", AWID3_WIFI_FEATURES)
        self.assertIn("radiotap.channel.freq", AWID3_WIFI_FEATURES)
        self.assertIn("wlan.fc.type_subtype", AWID3_WIFI_FEATURES)
        self.assertIn("wlan.fc.protected", AWID3_WIFI_FEATURES)
        self.assertEqual(len(AWID3_LABELS), 14)
        self.assertIn("Normal", AWID3_LABELS)
        self.assertIn("Deauth", AWID3_LABELS)
        self.assertIn("Disass", AWID3_LABELS)
        self.assertIn("Evil_Twin", AWID3_LABELS)

    def test_fit_transform_and_feature_extraction(self) -> None:
        preprocessor = AWID3TrafficPreprocessor()
        self.assertEqual(preprocessor.profile, AWID3_WIFI_PROFILE)

        # Synthetic samples
        rows = []
        labels = ["Normal", "Deauth", "Disass", "Normal"]
        for i, l in enumerate(labels):
            row = {
                "frame.len": 128.0 + i * 20,
                "radiotap.channel.freq": 2412.0,
                "radiotap.dbm_antsignal": -55.0 + i,
                "wlan.fc.type": 0.0,
                "wlan.fc.subtype": 12.0 if l == "Deauth" else 10.0 if l == "Disass" else 8.0,
                "wlan.fc.type_subtype": 12.0 if l == "Deauth" else 10.0 if l == "Disass" else 8.0,
                "wlan.fc.ds": 0.0,
                "wlan.fc.frag": 0.0,
                "wlan.fc.retry": 0.0,
                "wlan.fc.pwrmgt": 0.0,
                "wlan.fc.moredata": 0.0,
                "wlan.fc.protected": 0.0,
                "wlan.duration": 0.0,
                "wlan.seq": float(i * 100)
            }
            rows.append(row)

        df_X = pd.DataFrame(rows)
        s_y = pd.Series(labels)

        X_trans, y_trans = preprocessor.fit_transform(df_X, s_y)
        self.assertEqual(X_trans.shape, (4, 14))
        self.assertEqual(len(y_trans), 4)

        # Extraction from dict
        single_row = preprocessor.extract_features(rows[0])
        self.assertEqual(list(single_row.columns), AWID3_WIFI_FEATURES)
        single_trans = preprocessor.transform(single_row)
        self.assertEqual(single_trans.shape, (1, 14))

    def test_extract_from_radio_frame_hex(self) -> None:
        preprocessor = AWID3TrafficPreprocessor()
        # Mock 24-byte 802.11 Deauth packet hex
        deauth_bytes = bytearray(24)
        deauth_bytes[0] = 0xC0  # Type 0 (Mgmt), Subtype 12 (Deauth)
        deauth_bytes[1] = 0x00
        hex_str = deauth_bytes.hex()

        telemetry = {
            "record_kind": "radio_frame",
            "frame_hex": hex_str,
            "rssi": -45,
            "channel": 6
        }
        extracted = preprocessor.extract_features(telemetry)
        self.assertEqual(extracted["wlan.fc.type"].iloc[0], 0.0)
        self.assertEqual(extracted["wlan.fc.subtype"].iloc[0], 12.0)
        self.assertEqual(extracted["radiotap.dbm_antsignal"].iloc[0], -45.0)
        self.assertEqual(extracted["radiotap.channel.freq"].iloc[0], 2437.0)



if __name__ == "__main__":
    unittest.main()
