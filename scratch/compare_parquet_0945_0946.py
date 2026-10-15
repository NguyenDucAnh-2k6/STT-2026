"""Read-only frozen inventory comparison, client timezone Asia/Bangkok."""
import json
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import CATEGORICAL_FEATURES, invalid_record_mask

TZ = ZoneInfo("Asia/Bangkok")
CUTOFF = datetime(2026, 10, 12, 9, 46, tzinfo=TZ)


def proportions(values: pd.Series) -> dict:
    return {str(key): float(value) for key, value in values.fillna("missing").astype(str).value_counts(normalize=True).items()}


def tv(left: dict, right: dict) -> float:
    return sum(abs(left.get(key, 0) - right.get(key, 0)) for key in left.keys() | right.keys()) / 2


def ks(left: pd.Series, right: pd.Series) -> float:
    a = np.sort(pd.to_numeric(left, errors="coerce").dropna().to_numpy())
    b = np.sort(pd.to_numeric(right, errors="coerce").dropna().to_numpy())
    points = np.unique(np.concatenate([a, b]))
    return float(np.max(np.abs(np.searchsorted(a, points, side="right") / len(a) - np.searchsorted(b, points, side="right") / len(b))))


def summary(frame: pd.DataFrame, files: list) -> dict:
    endpoints = frame[["src_ip", "src_port", "dst_ip", "dst_port"]].astype(str).agg("|".join, axis=1).value_counts()
    captures = frame.groupby("capture_id").sequence.agg(["min", "max", "nunique"])
    span = int((captures["max"] - captures["min"] + 1).sum())
    result = {"files": len(files) if files else None, "rows": len(frame),
        "lab_8088_rows": int((frame.src_port.eq(8088) | frame.dst_port.eq(8088)).sum()),
        "packet_start": datetime.fromtimestamp(frame.timestamp.min()/1000, TZ).isoformat(),
        "packet_end": datetime.fromtimestamp(frame.timestamp.max()/1000, TZ).isoformat(),
        "protocol": proportions(frame.protocol), "capture_backend": proportions(frame.capture_backend),
        "labels": proportions(frame.ground_truth_scenario), "verified_rows": int(frame.label_verified.eq(True).sum()),
        "sessions": frame.session_id.value_counts().to_dict(), "captures": frame.capture_id.value_counts().to_dict(),
        "loopback_endpoint_fraction": float((frame.src_ip.isin(["127.0.0.1", "::1"]) & frame.dst_ip.isin(["127.0.0.1", "::1"])).mean()),
        "tcp_payload_nonzero_fraction": float(pd.to_numeric(frame["tcp.len"], errors="coerce").gt(0).mean()),
        "frame_size": frame.frame_length.quantile([0, .25, .5, .75, .95, 1]).to_dict(),
        "tcp_len": pd.to_numeric(frame["tcp.len"], errors="coerce").quantile([0, .5, .95, 1]).to_dict(),
        "endpoint_groups": len(endpoints), "top3_endpoint_share": float(endpoints.head(3).sum()/len(frame)),
        "sequence_coverage": float(captures["nunique"].sum()/span), "sequence_span": span,
        "constant_features": sum(frame[name].nunique(dropna=False)==1 for name in EDGE_IIOTSET_FEATURES),
        "malformed_rows": int(invalid_record_mask(frame).sum()), "duplicate_identity": int(frame.packet_id.duplicated().sum())}
    if "experiment_id" in frame:
        result["experiment_rows"] = int(frame.experiment_id.notna().sum())
    return result


def main() -> None:
    inventory = []
    parts = {"before": [], "after": []}
    files = {"before": [], "after": []}
    exact_0945 = []
    for path in sorted((ROOT / "data_lake/raw").rglob("*.parquet")):
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, TZ)
        if modified.date() != CUTOFF.date():
            continue
        frame = pd.read_parquet(path)
        part = "before" if modified < CUTOFF else "after"
        parts[part].append(frame)
        files[part].append(path)
        if modified.hour == 9 and modified.minute == 45:
            exact_0945.append(frame)
        inventory.append({"path": str(path.relative_to(ROOT)), "modified": modified.isoformat(),
            "rows": len(frame), "part": part, "changed_during_read": stat.st_mtime_ns != path.stat().st_mtime_ns})
    a, b = [pd.concat(parts[key], ignore_index=True) for key in ["before", "after"]]
    deltas = []
    for name in EDGE_IIOTSET_FEATURES:
        statistic = tv(proportions(a[name]), proportions(b[name])) if name in CATEGORICAL_FEATURES else ks(a[name], b[name])
        deltas.append({"feature": name, "metric": "TV" if name in CATEGORICAL_FEATURES else "KS", "distance": statistic})
    report = {"boundary": CUTOFF.isoformat(), "inventory": inventory,
        "before": summary(a, files["before"]), "after": summary(b, files["after"]),
        "protocol_tv": tv(proportions(a.protocol), proportions(b.protocol)),
        "frame_size_ks": ks(a.frame_length, b.frame_length),
        "features": sorted(deltas, key=lambda item:item["distance"], reverse=True),
        "shared_packet_ids": len(set(a.packet_id) & set(b.packet_id)),
        "strict_0945_protocol_tv": tv(proportions(pd.concat(exact_0945).protocol), proportions(b.protocol))}
    report["after_sources"] = {}
    for backend in ["tshark", "pcap"]:
        subset = b[b.capture_backend.eq(backend)]
        details = summary(subset, [])
        details["protocol_tv_vs_before"] = tv(proportions(a.protocol), proportions(subset.protocol))
        details["frame_size_ks_vs_before"] = ks(a.frame_length, subset.frame_length)
        report["after_sources"][backend] = details
    labeled = b[b.ground_truth_scenario.ne("Unknown")]
    report["attributed_workload"] = summary(labeled, []) if len(labeled) else None
    if len(labeled):
        report["attributed_workload"]["frame_size_ks_vs_before"] = ks(a.frame_length, labeled.frame_length)
    report["changed_files"] = sum(row["changed_during_read"] for row in inventory)
    report["identical_feature_distributions"] = sum(row["distance"] == 0 for row in deltas)
    path = ROOT / "scratch/parquet_distribution_0945_0946_2026-10-12.json"
    path.write_text(json.dumps(report, indent=2, default=lambda value:int(value)), encoding="utf-8")
    print(json.dumps({key:value for key,value in report.items() if key != "inventory"}, indent=2, default=lambda value:int(value)), flush=True)


if __name__ == "__main__":
    main()
