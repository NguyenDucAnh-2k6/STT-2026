"""Convert a trusted existing ML bundle to C tables, preserving every fitted tree.

This is a prepared-feature inference demo, not a claim of on-chip DPI/capture.
"""
import argparse
import hashlib
import json
import shutil
import uuid
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.exceptions import InconsistentVersionWarning

from ml_engine.exporter.esp32_model_exporter import export_model_header, unwrap_model
from ml_engine.preprocessing import EdgeTrafficPreprocessor
from ml_engine.preprocessing.edge_iiotset_preprocessor import DEFAULT_EDGE_IIOTSET_PATH


def export_existing_bundle(source: Path, output: Path, dataset: Path,
                           max_constant_bytes: int = 8 * 1024 * 1024) -> dict:
    if output.exists():
        raise FileExistsError("Choose a fresh output directory; source artifacts are preserved")
    source_metadata = json.loads((source / "model_metadata.json").read_text(encoding="utf-8"))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            classifier = unwrap_model(joblib.load(source / "attack_classifier.joblib"))
            anomaly = unwrap_model(joblib.load(source / "isolation_forest.joblib"))
            processor = EdgeTrafficPreprocessor.load(str(source / "preprocessor.joblib"))
    except InconsistentVersionWarning as exc:
        raise ValueError(f"Export with sklearn {exc.original_sklearn_version}; the fitted bundle was created with that version") from exc
    features, labels = processor.feature_names, source_metadata["labels"]
    if features != source_metadata["features"] or list(processor.label_encoder.classes_) != labels:
        raise ValueError("Saved feature/label order does not match artifact metadata")
    mappings = {name: mapping for sub in processor.sub_preprocessors.values()
                for name, mapping in getattr(sub, "_cat_maps", {}).items()}
    vocabulary_bytes = sum(len(value.encode("utf-8")) + 1 for mapping in mappings.values() for value in mapping)
    metadata = {"artifact_id": uuid.uuid4().hex, "profile": "edgeiiot-encoded-56-v2",
        "features": features, "labels": labels, "features_count": len(features), "labels_count": len(labels),
        "classifier_type": type(classifier).__name__, "anomaly_detector_type": type(anomaly).__name__,
        "anomaly_threshold": source_metadata.get("anomaly_threshold", .55),
        "isolation_score_min": source_metadata["isolation_score_min"], "isolation_score_max": source_metadata["isolation_score_max"],
        "preprocessing_version": source_metadata["preprocessing_version"], "versions": {"sklearn": sklearn.__version__, "numpy": np.__version__},
        "source_artifacts_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in
            ["attack_classifier.joblib", "isolation_forest.joblib", "preprocessor.joblib", "model_metadata.json"]},
        "source_artifact_name": source.name, "source_classifier_trees": len(classifier.estimators_),
        "source_anomaly_trees": len(anomaly.estimators_), "training_performed": False,
        "input_domain": "encoded_numeric_features", "raw_categorical_encoding_on_chip": False,
        "vocabulary_entries": {name: len(mapping) for name, mapping in mappings.items()},
        "vocabulary_utf8_bytes_excluding_indices": vocabulary_bytes, "hardware_validated": False,
        "export_parity_validated": False, "deployment_ready": False,
        "demo_scope": "Full fitted 56-feature RF/IF computation on prepared canonical feature vectors; not a radio capture benchmark"}
    # Structural selection for conversion parity only; no fitting/metric-based selection.
    frame = pd.read_csv(dataset, usecols=features + ["Attack_type"], low_memory=False)
    rows = pd.concat([frame.loc[frame.Attack_type.eq(label)].head(8) for label in labels]).drop(columns="Attack_type")
    encoded = processor.encode_features(rows)
    np.testing.assert_array_equal(processor.scaler.transform(encoded), processor.transform(rows))
    scaled = processor.scaler.transform(encoded)
    if not np.isfinite(scaled).all():
        raise ValueError("Non-finite representative feature vectors")
    output.mkdir(parents=True)
    report = export_model_header(classifier, anomaly, processor.scaler, features, labels, metadata,
                                 output / "esp32_packet_model.h", max_constant_bytes)
    report["raw_vocabulary_utf8_bytes_excluding_indices"] = vocabulary_bytes
    report["nominal_4mb_flash_fit"] = report["estimated_numeric_constant_bytes"] < 4 * 1024 * 1024
    (output / "export_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    shutil.copy2(source / "preprocessor.joblib", output / "preprocessor_reference.joblib")
    np.savez(output / "parity_vectors.npz", raw=encoded, scaled=scaled, probabilities=classifier.predict_proba(scaled),
             classes=classifier.classes_, score_samples=anomaly.score_samples(scaled))
    metadata["encoding_reference_sha256"] = metadata["source_artifacts_sha256"]["preprocessor.joblib"]
    metadata["representative_dataset_sha256"] = hashlib.sha256(dataset.read_bytes()).hexdigest()
    (output / "model_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, default=Path(DEFAULT_EDGE_IIOTSET_PATH))
    parser.add_argument("--max-constant-bytes", type=int, default=8 * 1024 * 1024)
    args = parser.parse_args()
    export_existing_bundle(args.models_dir, args.output, args.dataset, args.max_constant_bytes)


if __name__ == "__main__":
    main()
