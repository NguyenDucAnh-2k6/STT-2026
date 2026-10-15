"""Native exporter parity on fitted fixtures. No live traffic or existing model writes."""
import json
import tempfile
import unittest
import uuid
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.covariance import EllipticEnvelope
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

from ml_engine.exporter.esp32_model_exporter import export_model_header
from ml_engine.edge.validate_export import validate_export
from ml_engine.preprocessing import EdgeTrafficPreprocessor

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / ".esp32_validation_env/Lib/site-packages/ziglang/zig.exe"


class ModelExportTests(unittest.TestCase):
    def setUp(self) -> None:
        rng = np.random.default_rng(42)
        self.X = rng.normal(size=(120, 3)).astype(np.float32)
        self.y = np.where(self.X[:, 0] > .5, 2, np.where(self.X[:, 1] > 0, 1, 0))
        self.scaler = StandardScaler().fit(self.X)
        self.scaled = self.scaler.transform(self.X)
        self.normal = self.scaled[self.y == 0]
        self.iso = IsolationForest(n_estimators=19, max_samples=16, random_state=42).fit(self.normal)
        self.features = ["feature0", "feature1", "feature2"]
        self.labels = ["Normal", "AttackA", "AttackB"]

    @unittest.skipUnless(COMPILER.is_file(), "Zig compiler unavailable")
    def test_supported_model_families_have_native_parity(self) -> None:
        classifiers = [DecisionTreeClassifier(max_depth=4, random_state=42),
            RandomForestClassifier(n_estimators=17, max_depth=4, random_state=42),
            ExtraTreesClassifier(n_estimators=11, max_depth=4, random_state=42),
            LogisticRegression(max_iter=500)]
        detectors = [self.iso, OneClassSVM(gamma=.2, nu=.1).fit(self.normal), EllipticEnvelope(random_state=42).fit(self.normal)]
        pairs = [(model.fit(self.scaled, self.y), self.iso) for model in classifiers]
        pairs += [(classifiers[0], detector) for detector in detectors[1:]]
        # Binary and liblinear multiclass probability paths differ from softmax.
        pairs += [(LogisticRegression(max_iter=500).fit(self.scaled, self.y > 0), self.iso)]
        if "multi_class" in LogisticRegression().get_params():
            pairs.append((LogisticRegression(solver="liblinear", max_iter=500).fit(self.scaled, self.y), self.iso))
        for classifier, detector in pairs:
            with self.subTest(classifier=type(classifier).__name__, detector=type(detector).__name__), tempfile.TemporaryDirectory(dir=ROOT / ".esp32_validation_env") as directory:
                bundle = Path(directory)
                reference_sample = detector.score_samples(self.scaled)
                minimum, maximum = self.iso.score_samples(self.normal).min(), self.iso.score_samples(self.normal).max()
                if isinstance(detector, OneClassSVM):
                    normalized = 1 / (1 + np.exp(detector.decision_function(self.scaled)))
                elif isinstance(detector, EllipticEnvelope):
                    threshold = -detector.offset_
                    normalized = 1 / (1 + np.exp(-2 * (-reference_sample - threshold) / max(threshold, 1e-4)))
                else:
                    distance = (maximum-reference_sample) / max(maximum-minimum, 1e-6)
                    normalized = 1 / (1+np.exp(-4*(distance-.5)))
                metadata = {"features": self.features, "labels": self.labels, "artifact_id": uuid.uuid4().hex,
                    "profile": "native-model-test", "anomaly_threshold": .51,
                    "isolation_score_min": float(minimum), "isolation_score_max": float(maximum)}
                report = export_model_header(classifier, detector, self.scaler, self.features, self.labels, metadata, bundle / "esp32_packet_model.h")
                self.assertFalse(report["trees_truncated"])
                if isinstance(classifier, RandomForestClassifier):
                    self.assertEqual(report["exported_trees"], 17+19)
                (bundle / "model_metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
                np.savez(bundle / "parity_vectors.npz", raw=self.X, scaled=self.scaled,
                    probabilities=classifier.predict_proba(self.scaled), classes=classifier.classes_,
                    score_samples=reference_sample, normalized_scores=normalized)
                validated = validate_export(bundle, COMPILER, ROOT)
                self.assertEqual(validated["vectors"], 120)

    def test_budget_failure_does_not_truncate_or_write(self) -> None:
        classifier = RandomForestClassifier(n_estimators=17, max_depth=4, random_state=42).fit(self.scaled, self.y)
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "model.h"
            with self.assertRaisesRegex(ValueError, "no trees were truncated"):
                export_model_header(classifier, self.iso, self.scaler, self.features, self.labels,
                    {"artifact_id": "a"*32, "profile": "test", "anomaly_threshold": .5,
                     "isolation_score_min": -.8, "isolation_score_max": -.3}, header, max_constant_bytes=100)
            self.assertFalse(header.exists())

    def test_unsupported_model_is_explicit(self) -> None:
        classifier = KNeighborsClassifier().fit(self.scaled, self.y)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(NotImplementedError, "No verified ESP32"):
            export_model_header(classifier, self.iso, self.scaler, self.features, self.labels,
                {"artifact_id": "a"*32, "profile": "test", "anomaly_threshold": .5}, Path(directory) / "model.h")

    def test_fitted_encoding_is_same_as_runtime_transform(self) -> None:
        import pandas as pd
        frame = pd.DataFrame({"http.request.method": ["GET", "POST", "GET"], "tcp.len": [0, 50, 100]})
        processor = EdgeTrafficPreprocessor(feature_names=["http.request.method", "tcp.len"]).fit(frame, pd.Series(["Normal"]*3))
        np.testing.assert_array_equal(processor.scaler.transform(processor.encode_features(frame)), processor.transform(frame))


if __name__ == "__main__":
    unittest.main()
