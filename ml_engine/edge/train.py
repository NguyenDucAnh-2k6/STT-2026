"""Offline ESP32 packet profile training. Never invoked by the runtime launcher."""
import argparse
import hashlib
import json
import platform
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, ESP32_PACKET_PROFILE
from ml_engine.config.schema import LABEL_NAMES
from ml_engine.exporter.esp32_packet_exporter import export_packet_model
from ml_engine.preprocessing.edge_iiotset_preprocessor import DEFAULT_EDGE_IIOTSET_PATH
from ml_engine.preprocessing.modules.base import numeric_series


def train_packet_profile(dataset: Path, output: Path, classifier_name: str = "decision_tree", trees: int = 16) -> dict:
    if output.exists():
        raise FileExistsError("Choose a new output directory; existing artifacts are never overwritten")
    if not dataset.is_file():
        raise FileNotFoundError("A real Edge-IIoTset benchmark is required; no synthetic fallback")
    feature_names = ESP32_PACKET_FEATURES
    frame = pd.read_csv(dataset, usecols=feature_names + ["Attack_type", "ip.src_host", "ip.dst_host", "udp.stream"], low_memory=False)
    source_rows = len(frame)
    values = frame[feature_names].apply(numeric_series)
    valid = values.notna().all(axis=1) & frame.Attack_type.isin(LABEL_NAMES)
    # Protocol-absent UDP-only vectors carry no observations for this profile.
    valid &= values.ne(0).any(axis=1)
    frame, values = frame.loc[valid].copy(), values.loc[valid].copy()
    duplicates = values.assign(label=frame.Attack_type).duplicated()
    frame, values = frame.loc[~duplicates], values.loc[~duplicates]
    endpoints = frame[["ip.src_host", "ip.dst_host"]].fillna("").astype(str).apply(lambda row: "|".join(sorted(row)), axis=1)
    ports = values[["tcp.srcport", "tcp.dstport"]].astype(str).apply(lambda row: "|".join(sorted(row)), axis=1)
    flow_groups = pd.util.hash_pandas_object(pd.DataFrame({"endpoints": endpoints, "ports": ports,
        "udp_stream": frame["udp.stream"].fillna(0).astype(str)}), index=False).to_numpy()
    # Merge flows sharing an identical input vector: no projected duplicates cross splits.
    projection = pd.util.hash_pandas_object(values, index=False).to_numpy()
    parent: dict[int, int] = {}
    def find(item: int) -> int:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item
    first: dict[int, int] = {}
    for vector, flow in zip(projection, flow_groups):
        root = find(int(flow))
        if int(vector) in first:
            parent[root] = find(first[int(vector)])
        else:
            first[int(vector)] = root
    groups = np.array([find(int(flow)) for flow in flow_groups], dtype=np.uint64)
    indices = np.arange(len(frame))
    train_validation, test = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=42).split(indices, groups=groups))
    train_local, validation_local = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=43).split(train_validation, groups=groups[train_validation]))
    train, validation = train_validation[train_local], train_validation[validation_local]
    labels = list(LABEL_NAMES)
    y = frame.Attack_type.map({label: index for index, label in enumerate(labels)}).to_numpy()
    X = values.to_numpy(dtype=np.float32)
    scaler = StandardScaler().fit(X[train])
    scaled = scaler.transform(X)
    options = {
        "decision_tree": lambda: DecisionTreeClassifier(max_depth=8, min_samples_leaf=16, class_weight="balanced", random_state=42),
        "random_forest": lambda: RandomForestClassifier(n_estimators=trees, max_depth=8, min_samples_leaf=16, class_weight="balanced", random_state=42, n_jobs=1),
        "extra_trees": lambda: ExtraTreesClassifier(n_estimators=trees, max_depth=8, min_samples_leaf=16, class_weight="balanced", random_state=42, n_jobs=1),
        "logistic_regression": lambda: LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
    }
    if classifier_name not in options or not 1 <= trees <= 128:
        raise ValueError("Unsupported classifier or tree budget")
    classifier = options[classifier_name]().fit(scaled[train], y[train])
    normal = y[train] == labels.index("Normal")
    if normal.sum() < 2:
        raise ValueError("Split contains insufficient verified normal training records")
    anomaly = IsolationForest(n_estimators=8, max_samples=128, random_state=42, n_jobs=1).fit(scaled[train][normal])
    normal_scores = anomaly.score_samples(scaled[train][normal])
    minimum, maximum = float(normal_scores.min()), float(normal_scores.max())
    def scores(indices: np.ndarray) -> np.ndarray:
        distance = (maximum - anomaly.score_samples(scaled[indices])) / max(maximum - minimum, 1e-6)
        return 1 / (1 + np.exp(-4 * (distance - .5)))
    validation_normal = y[validation] == labels.index("Normal")
    if not validation_normal.any():
        raise ValueError("Validation split has no normal records for threshold calibration")
    threshold = float(np.quantile(scores(validation)[validation_normal], .99))
    # Test records are used only after all training/calibration choices are fixed.
    anomaly_test = scores(test)
    classifier_test = classifier.predict(scaled[test])
    final_test = np.where(anomaly_test >= threshold,
        np.where(classifier_test == labels.index("Normal"), len(labels), classifier_test), labels.index("Normal"))
    pipeline_labels = labels + ["ZeroDay_Anomaly"]
    is_attack = y[test] != labels.index("Normal")
    test_normal = ~is_attack
    fingerprint = hashlib.sha256(dataset.read_bytes()).hexdigest()
    metadata = {"artifact_id": uuid.uuid4().hex, "profile": ESP32_PACKET_PROFILE,
        "features": feature_names, "labels": labels, "preprocessing_version": 1,
        "classifier_type": type(classifier).__name__, "anomaly_detector_type": "IsolationForest",
        "anomaly_threshold": threshold, "isolation_score_min": minimum, "isolation_score_max": maximum,
        "source_file": dataset.name, "dataset_sha256": fingerprint, "source_rows": source_rows,
        "profile_rows": len(frame), "removed_invalid_or_protocol_absent_rows": int((~valid).sum()),
        "removed_projected_duplicates": int(duplicates.sum()), "seed": 42,
        "split_strategy": "disjoint endpoint/port/UDP-stream groups merged by identical projected vectors",
        "split_indices": {"train": train.tolist(), "validation": validation.tolist(), "test": test.tolist()},
        "split_groups": {name: len(set(groups[index].tolist())) for name, index in [("train", train), ("validation", validation), ("test", test)]},
        "train_rows": len(train), "validation_rows": len(validation), "test_rows": len(test),
        "classifier_macro_f1": float(f1_score(y[test], classifier_test, labels=np.arange(len(labels)), average="macro", zero_division=0)),
        "pipeline_macro_f1": float(f1_score(y[test], final_test, labels=np.arange(len(pipeline_labels)), average="macro", zero_division=0)),
        "pipeline_per_class": classification_report(y[test], final_test, labels=np.arange(len(pipeline_labels)), target_names=pipeline_labels, output_dict=True, zero_division=0),
        "anomaly_roc_auc": float(roc_auc_score(is_attack, anomaly_test)) if len(np.unique(is_attack)) == 2 else None,
        "normal_false_alarm_fraction": float((anomaly_test[test_normal] >= threshold).mean()) if test_normal.any() else None,
        "false_alarms_per_interval": None, "detection_delay_ms": None,
        "temporal_metrics_unavailable_reason": "CSV packet rows lack attributable capture sessions/elapsed-time windows",
        "deployment_scope": "plaintext unfragmented IPv4 TCP/ICMP or ARP; encrypted and UDP-only frames unavailable",
        "hardware_validated": False, "export_parity_validated": False,
        "classifier_parameters": classifier.get_params(), "anomaly_parameters": anomaly.get_params(),
        "versions": {"python": platform.python_version(), "numpy": np.__version__, "sklearn": sklearn.__version__}}
    output.mkdir(parents=True)
    for filename, artifact in [("attack_classifier.joblib", classifier), ("isolation_forest.joblib", anomaly), ("scaler.joblib", scaler)]:
        joblib.dump(artifact, output / filename)
    export_packet_model(classifier, anomaly, scaler, labels, metadata, output / "esp32_packet_model.h")
    # Held-out vectors for native parity validation, not model fitting.
    representative = np.concatenate([test[:128], train[:64]])
    np.savez(output / "parity_vectors.npz", raw=X[representative], scaled=scaled[representative],
             probabilities=classifier.predict_proba(scaled[representative]), classes=classifier.classes_,
             score_samples=anomaly.score_samples(scaled[representative]))
    (output / "model_metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({key: metadata[key] for key in ["profile", "train_rows", "validation_rows", "test_rows", "pipeline_macro_f1", "normal_false_alarm_fraction"]}, indent=2))
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path(DEFAULT_EDGE_IIOTSET_PATH))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--classifier", choices=["decision_tree", "random_forest", "extra_trees", "logistic_regression"], default="decision_tree")
    parser.add_argument("--trees", type=int, default=16)
    parser.add_argument("--reevaluate", action="store_true", help="Repair/report evaluation of an existing trusted bundle without fitting")
    args = parser.parse_args()
    if args.reevaluate:
        reevaluate_pipeline(args.dataset, args.output)
    else:
        train_packet_profile(args.dataset, args.output, args.classifier, args.trees)
        reevaluate_pipeline(args.dataset, args.output)


def reevaluate_pipeline(dataset: Path, bundle: Path) -> None:
    """Re-evaluate a fixed artifact, retaining ZeroDay as a distinct pipeline outcome."""
    path = bundle / "model_metadata.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if hashlib.sha256(dataset.read_bytes()).hexdigest() != metadata["dataset_sha256"]:
        raise ValueError("Evaluation dataset identity changed")
    frame = pd.read_csv(dataset, usecols=ESP32_PACKET_FEATURES + ["Attack_type"], low_memory=False)
    values = frame[ESP32_PACKET_FEATURES].apply(numeric_series)
    valid = values.notna().all(axis=1) & frame.Attack_type.isin(LABEL_NAMES) & values.ne(0).any(axis=1)
    frame, values = frame.loc[valid], values.loc[valid]
    duplicates = values.assign(label=frame.Attack_type).duplicated()
    frame, values = frame.loc[~duplicates], values.loc[~duplicates]
    if len(frame) != metadata["profile_rows"]:
        raise ValueError("Evaluation row selection changed")
    labels = metadata["labels"]
    test = metadata["split_indices"]["test"]
    y = frame.Attack_type.map({label: index for index, label in enumerate(labels)}).to_numpy()[test]
    scaled = joblib.load(bundle / "scaler.joblib").transform(values.to_numpy(dtype=np.float32)[test])
    predicted = joblib.load(bundle / "attack_classifier.joblib").predict(scaled)
    sample = joblib.load(bundle / "isolation_forest.joblib").score_samples(scaled)
    distance = (metadata["isolation_score_max"] - sample) / max(metadata["isolation_score_max"] - metadata["isolation_score_min"], 1e-6)
    scores = 1 / (1 + np.exp(-4 * (distance - .5)))
    final = np.where(scores >= metadata["anomaly_threshold"], np.where(predicted == labels.index("Normal"), len(labels), predicted), labels.index("Normal"))
    pipeline_labels = labels + ["ZeroDay_Anomaly"]
    metadata.update(pipeline_macro_f1=float(f1_score(y, final, labels=np.arange(len(pipeline_labels)), average="macro", zero_division=0)),
        classifier_accuracy=float((predicted == y).mean()),
        pipeline_per_class=classification_report(y, final, labels=np.arange(len(pipeline_labels)), target_names=pipeline_labels, output_dict=True, zero_division=0),
        pipeline_decision_rule="anomaly_gate_then_classifier_with_zero_day", features_count=len(ESP32_PACKET_FEATURES),
        labels_count=len(labels), deployment_ready=False,
        deployment_limitation="Experimental profile: final alert recall is low and physical radio-domain performance has not been evaluated")
    # Broaden native parity coverage across every available test class and feature extrema.
    raw_all = values.to_numpy(dtype=np.float32)
    chosen = list(range(min(32, len(test))))
    for label in range(len(labels)):
        chosen.extend(np.flatnonzero(y == label)[:8].tolist())
    for column in range(raw_all.shape[1]):
        chosen.extend([int(np.argmin(raw_all[test, column])), int(np.argmax(raw_all[test, column]))])
    chosen = sorted(set(chosen))
    representative = raw_all[np.asarray(test)[chosen]]
    scaled_representative = joblib.load(bundle / "scaler.joblib").transform(representative)
    classifier = joblib.load(bundle / "attack_classifier.joblib")
    anomaly = joblib.load(bundle / "isolation_forest.joblib")
    np.savez(bundle / "parity_vectors.npz", raw=representative, scaled=scaled_representative,
        probabilities=classifier.predict_proba(scaled_representative), classes=classifier.classes_,
        score_samples=anomaly.score_samples(scaled_representative))
    metadata["export_parity_validated"] = False  # Must validate the refreshed fixture set.
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    print(json.dumps({key: metadata[key] for key in ["classifier_macro_f1", "pipeline_macro_f1", "anomaly_roc_auc", "normal_false_alarm_fraction", "deployment_ready"]}, indent=2))


if __name__ == "__main__":
    main()
