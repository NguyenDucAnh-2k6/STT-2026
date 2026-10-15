"""Read-only audit of a frozen file inventory; output aggregates, never payloads."""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.quality import select_training_records
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES as FEATURES
from ml_engine.preprocessing.validation import CATEGORICAL_FEATURES, invalid_feature_counts, invalid_record_mask
from ml_engine.preprocessing.modules.base import normalize_categorical_value, numeric_series


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def counts(series: pd.Series) -> dict[str, int]:
    return {str(key): int(value) for key, value in series.value_counts(dropna=False).items()}


def normalized(frame: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({name: frame[name].map(normalize_categorical_value) if name in CATEGORICAL_FEATURES
        else numeric_series(frame[name]) for name in FEATURES})


def main() -> None:
    inventory = sorted((ROOT / "data_lake/raw").rglob("*.parquet"))
    report = {"audit_utc": datetime.now(timezone.utc).isoformat(), "inventory_files": len(inventory),
              "files": [], "read_errors": []}
    frames = []
    for path in inventory:
        try:
            before = path.stat()
            metadata = pq.ParquetFile(path)
            frame = pd.read_parquet(path)
            after = path.stat()
            report["files"].append({"path": str(path.relative_to(ROOT)), "rows": len(frame),
                "columns": len(frame.columns), "schema_missing_features": sorted(set(FEATURES) - set(frame)),
                "arrow_types": {name: str(metadata.schema_arrow.field(name).type) for name in FEATURES if name in frame},
                "sha256": fingerprint(path), "changed_during_read": before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size})
            frames.append(frame)
        except Exception as error:
            report["read_errors"].append({"path": str(path.relative_to(ROOT)), "error": type(error).__name__})
    if not frames:
        raise RuntimeError("No readable Parquet batches")
    frame = pd.concat(frames, ignore_index=True)
    print(f"Read snapshot: {len(frames)} files, {len(frame)} rows", flush=True)
    accepted, eligibility = select_training_records(frame)
    missing = [name for name in FEATURES if name not in frame]
    if missing:
        raise RuntimeError(f"Canonical columns missing: {missing}")
    numeric = frame[[name for name in FEATURES if name not in CATEGORICAL_FEATURES]].apply(pd.to_numeric, errors="coerce")
    malformed = invalid_record_mask(frame)
    absent = Counter(name for values in frame.absent_fields for name in values)
    verified = frame.label_verified.eq(True)
    loopback = frame.src_ip.fillna("").str.startswith("127.") & frame.dst_ip.fillna("").str.startswith("127.")
    requested = frame.get("requested_attack_label", pd.Series("Unknown", index=frame.index))
    matched = frame.get("scenario_target_match", pd.Series(False, index=frame.index)).eq(True)
    nonzero = {name: int(numeric[name].fillna(0).ne(0).sum()) for name in numeric}
    normalized_lake = normalized(frame)
    hashes = pd.util.hash_pandas_object(normalized_lake, index=False)
    # Aggregate flow concentration without writing IPs, ports or payload values.
    flow_counts = Counter(tuple(sorted(((str(src), int(sport)), (str(dst), int(dport)))))
        for src, dst, sport, dport in frame[["src_ip", "dst_ip", "tcp.srcport", "tcp.dstport"]].itertuples(index=False, name=None))
    report["lake"] = {
        "rows": len(frame), "columns": len(frame.columns), "canonical_features": len(FEATURES),
        "canonical_null_cells": int(frame[FEATURES].isna().sum().sum()),
        "numeric_nonfinite_cells": int((~np.isfinite(numeric.to_numpy(dtype=float))).sum()),
        "malformed_rows": int(malformed.sum()), "malformed_fields": invalid_feature_counts(frame),
        "missing_feature_rows": int(frame.missing_features.map(len).gt(0).sum()),
        "truncated_rows": int(frame.captured_length.lt(frame.frame_length).sum()),
        "duplicate_packet_identity_rows": int(frame.duplicated(["device_id", "packet_id"]).sum()),
        "duplicate_feature_vectors": int(normalized_lake.duplicated().sum()),
        "distinct_feature_vectors": int(len(normalized_lake.drop_duplicates())),
        "constant_canonical_features": [name for name in FEATURES if normalized_lake[name].nunique() == 1],
        "tcp_flow_count": len(flow_counts),
        "largest_tcp_flow_rows": max(flow_counts.values()),
        "top_three_tcp_flows_rows": sum(sorted(flow_counts.values(), reverse=True)[:3]),
        "tcp_one_byte_payload_rows": int(frame['tcp.len'].eq(1).sum()),
        "verified_rows": int(verified.sum()), "training_eligibility": eligibility,
        "ground_truth": counts(frame.ground_truth_scenario), "label_sources": counts(frame.label_source),
        "requested_labels": counts(requested), "requested_by_target_match": pd.crosstab(requested, matched).to_dict(),
        "protocols": counts(frame.protocol), "record_kind": counts(frame.record_kind),
        "semantics": counts(frame.feature_semantics), "schema_versions": counts(frame.schema_version),
        "capture_backends": counts(frame.capture_backend), "dissection_modes": counts(frame.dissection_mode),
        "extractor_versions": counts(frame.extractor_version), "tshark_versions": counts(frame.tshark_version),
        "absent_count_quantiles": frame.absent_fields.map(len).quantile([0, .5, .95, 1]).to_dict(),
        "absent_by_feature": dict(absent), "nonzero_numeric_rows": nonzero,
        "ipv4_loopback_rows": int(loopback.sum()),
        "ipv6_rows": int((frame.src_ip.fillna("").str.contains(":") | frame.dst_ip.fillna("").str.contains(":")).sum()),
        "own_mqtt_tcp_1883_rows": int((loopback & (frame['tcp.srcport'].eq(1883) | frame['tcp.dstport'].eq(1883))).sum()),
        "own_dashboard_tcp_8000_rows": int((loopback & (frame['tcp.srcport'].eq(8000) | frame['tcp.dstport'].eq(8000))).sum()),
        "http_lab_tcp_8088_rows": int((frame['tcp.srcport'].eq(8088) | frame['tcp.dstport'].eq(8088)).sum()),
        "captures": [],
    }
    for index, (_, group) in enumerate(frame.groupby("capture_id"), 1):
        unique = group.sequence.nunique()
        span = int(group.sequence.max() - group.sequence.min() + 1)
        report["lake"]["captures"].append({"capture": index, "rows": len(group),
            "duration_sec": float(group.packet_time_epoch.max() - group.packet_time_epoch.min()),
            "sequence_min": int(group.sequence.min()), "sequence_max": int(group.sequence.max()),
            "sequence_missing_within_observed_range": span - unique,
            "persisted_fraction_within_observed_sequence_range": unique / span,
            "ground_truth": counts(group.ground_truth_scenario), "requested_labels": counts(requested.loc[group.index]),
            "protocols": counts(group.protocol)})
    # Full local ML benchmark, never a fitted transform or model. DNN header only:
    # the 1.2 GB DNN dataset is not silently substituted with a small row sample.
    benchmark_dir = ROOT / "ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL"
    path = benchmark_dir / "ML-EdgeIIoT-dataset.csv"
    benchmark = pd.read_csv(path, usecols=FEATURES + ["Attack_type"], low_memory=False)
    benchmark_valid = benchmark.loc[~invalid_record_mask(benchmark)]
    bench = normalized(benchmark_valid)
    benchmark_hashes = pd.util.hash_pandas_object(bench, index=False)
    report["benchmark_ml"] = {"rows": len(benchmark), "valid_numeric_rows": len(benchmark_valid),
        "malformed_rows": len(benchmark) - len(benchmark_valid), "sha256": fingerprint(path),
        "labels": counts(benchmark.Attack_type), "matching_feature_hash_lake_rows": int(hashes.isin(set(benchmark_hashes)).sum()),
        "comparison_scope": "Full ML benchmark after excluding malformed numeric rows; hash overlap is diagnostic, not proof of equality"}
    report["benchmark_dnn"] = {"scope": "Header only", "canonical_columns": int(pd.read_csv(benchmark_dir / "DNN-EdgeIIoT-dataset.csv", nrows=0).columns.isin(FEATURES).sum())}
    comparison = {}
    for name in FEATURES:
        left, right = normalized_lake[name], bench[name]
        item = {"lake_unique": int(left.nunique()), "ml_unique": int(right.nunique()),
                "lake_absent_pct": 100 * absent.get(name, 0) / len(frame)}
        if name in CATEGORICAL_FEATURES:
            item.update(lake_zero_pct=100 * float(left.eq("0").mean()),
                ml_zero_pct=100 * float(right.eq("0").mean()),
                lake_category_unseen_in_ml_pct=100 * float((~left.isin(set(right))).mean()))
        else:
            item.update(lake_zero_pct=100 * float(left.eq(0).mean()), ml_zero_pct=100 * float(right.eq(0).mean()),
                lake_quantiles=left.quantile([0, .5, .95, 1]).to_dict(), ml_quantiles=right.quantile([0, .5, .95, 1]).to_dict())
        comparison[name] = item
    report["feature_comparison"] = comparison
    output = ROOT / "scratch/parquet_training_audit_2026-10-11.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"snapshot_files": len(frames), "lake": report["lake"], "benchmark_ml": report["benchmark_ml"]}, ensure_ascii=False, indent=2))
    print(f"Report: {output}")


if __name__ == "__main__":
    main()
