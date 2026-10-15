"""Read-only aggregate audit; never print packet payloads or endpoint addresses."""
import ast
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
CATEGORICAL_FEATURES = set()
for module, variable in [("http_application", "HTTP_CAT_COLS"), ("iot_protocols", "IOT_CAT_COLS"), ("tcp_transport", "TCP_CAT_COLS")]:
    tree = ast.parse((ROOT / f"ml_engine/preprocessing/modules/{module}.py").read_text(encoding="utf-8"))
    node = next(node for node in tree.body if isinstance(node, ast.AnnAssign) and node.target.id == variable)
    CATEGORICAL_FEATURES.update(ast.literal_eval(node.value))


def invalid_feature_counts(frame: pd.DataFrame) -> dict:
    return {name: int(pd.to_numeric(frame[name], errors="coerce").isna().sum())
            for name in EDGE_IIOTSET_FEATURES if name not in CATEGORICAL_FEATURES
            and pd.to_numeric(frame[name], errors="coerce").isna().any()}


def summary(frame: pd.DataFrame) -> dict:
    absent = Counter(name for values in frame.absent_fields for name in values)
    counts = frame.absent_fields.map(len)
    verified = frame.label_verified.eq(True) & frame.label_source.isin(["manual_review", "controlled_flow"])
    gate = {"verified_label_rows": int(verified.sum()), "unverified_label_rows": int((~verified).sum())}
    numeric = frame[EDGE_IIOTSET_FEATURES].drop(columns=list(CATEGORICAL_FEATURES), errors="ignore")
    return {"rows": len(frame), "columns": len(frame.columns),
        "missing_canonical_columns": [name for name in EDGE_IIOTSET_FEATURES if name not in frame],
        "malformed_numeric": invalid_feature_counts(frame),
        "canonical_null_cells": int(frame[EDGE_IIOTSET_FEATURES].isna().sum().sum()),
        "nonfinite_numeric_cells": int((~np.isfinite(numeric.to_numpy(dtype=float))).sum()),
        "missing_feature_rows": int(frame.missing_features.map(len).gt(0).sum()),
        "truncated_rows": int(frame.captured_length.lt(frame.frame_length).sum()),
        "duplicate_packet_ids": int(frame.duplicated(["device_id", "packet_id"]).sum()),
        "absent_count": {"min": int(counts.min()), "median": float(counts.median()), "max": int(counts.max())},
        "absent_by_field": dict(absent),
        "varying_feature_count": int(frame[EDGE_IIOTSET_FEATURES].nunique().gt(1).sum()),
        "protocols": frame.protocol.value_counts().to_dict(),
        "protocol_stacks": frame.protocol_stack.value_counts().to_dict(),
        "dissection_modes": frame.dissection_mode.value_counts().to_dict(),
        "labels": frame.ground_truth_scenario.value_counts().to_dict(), "training_gate": gate,
        "span_sec": float(frame.packet_time_epoch.max() - frame.packet_time_epoch.min())}


if __name__ == "__main__":
    tree = ast.parse((ROOT / "view_parquet.py").read_text(encoding="utf-8"))
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == "read_parquet")
    source = ROOT / ast.literal_eval(call.args[0])
    frame = pd.read_parquet(source)
    csv_frame = pd.read_csv(ROOT / "output.csv", dtype={name: "string" for name in CATEGORICAL_FEATURES})
    same = len(frame) == len(csv_frame)
    mismatches = []
    for name in EDGE_IIOTSET_FEATURES:
        if name in CATEGORICAL_FEATURES:
            match = frame[name].astype(str).eq(csv_frame[name].astype(str)).all()
        else:
            match = np.allclose(frame[name], csv_frame[name], equal_nan=True)
        if not match:
            mismatches.append(name)
    report = {"selected_batch": summary(frame), "csv_rows": len(csv_frame),
              "csv_matches_parquet": same and not mismatches, "csv_mismatched_features": mismatches}
    paths = sorted((ROOT / "data_lake/raw/date=2026-10-11").glob("*.parquet"))
    all_rows = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
    report["lake_snapshot"] = summary(all_rows)
    report["lake_snapshot"]["files"] = len(paths)
    report["lake_snapshot"]["sequence_gaps"] = sum(
        int(group.sequence.max() - group.sequence.min() + 1 - group.sequence.nunique())
        for _, group in all_rows.groupby("capture_id"))
    loopback = all_rows.src_ip.fillna("").str.startswith("127.") & all_rows.dst_ip.fillna("").str.startswith("127.")
    report["lake_snapshot"]["ipv4_loopback_rows"] = int(loopback.sum())
    report["lake_snapshot"]["loopback_dashboard_port_8000_rows"] = int((loopback &
        (all_rows["tcp.srcport"].eq(8000) | all_rows["tcp.dstport"].eq(8000))).sum())
    benchmark_path = ROOT / "ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv"
    if benchmark_path.exists():
        benchmark = pd.read_csv(benchmark_path, usecols=["Attack_type", "mqtt.topic", "mbtcp.len"], dtype="string")
        attack = benchmark.Attack_type.ne("Normal")
        report["local_benchmark"] = {"rows": len(benchmark),
            "modbus_len_nonzero_rows": int(pd.to_numeric(benchmark["mbtcp.len"], errors="coerce").fillna(0).ne(0).sum()),
            "mqtt_topic_placeholder_shortcut_accuracy": float(benchmark["mqtt.topic"].eq("0.0").eq(attack).mean())}
    (ROOT / "scratch/host_capture_health.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
