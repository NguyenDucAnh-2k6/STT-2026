"""Read-only audit of the session ending at batch 204 and linked Twin imports."""
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.quality import select_training_records
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import invalid_record_mask


def audit(frame: pd.DataFrame) -> dict:
    accepted, eligibility = select_training_records(frame)
    sequences = frame.groupby("capture_id").sequence.agg(["min", "max", "nunique"])
    span = int((sequences["max"] - sequences["min"] + 1).sum())
    return {"rows": len(frame), "time_min_ms": int(frame.timestamp.min()), "time_max_ms": int(frame.timestamp.max()),
        "observed_sequence_span": span, "unique_sequence_rows": int(sequences["nunique"].sum()),
        "frame_length_quantiles": frame.frame_length.quantile([0, .5, .95, 1]).to_dict(),
        "tcp_payload_nonzero": int(pd.to_numeric(frame["tcp.len"], errors="coerce").gt(0).sum()),
        "labels": frame.ground_truth_scenario.value_counts().to_dict(),
        "verified": int(frame.label_verified.eq(True).sum()),
        "protocols": frame.protocol.value_counts().to_dict(),
        "duplicate_packet_ids": int(frame.packet_id.duplicated().sum()),
        "malformed": int(invalid_record_mask(frame).sum()),
        "null_features": int(frame[EDGE_IIOTSET_FEATURES].isna().any(axis=1).sum()),
        "constant_features": sum(frame[name].nunique(dropna=False) == 1 for name in EDGE_IIOTSET_FEATURES),
        "training": eligibility}


def main() -> None:
    endpoint = next((ROOT / "data_lake/raw").rglob("*000204.parquet"))
    prefix = endpoint.name.split("_batch_")[0]
    inventory = sorted(p for p in endpoint.parent.glob(prefix + "_batch_*.parquet")
                       if int(p.stem.split("_batch_")[-1]) <= 204)
    frame = pd.concat([pd.read_parquet(p) for p in inventory], ignore_index=True)
    report = {"ending_file": str(endpoint.relative_to(ROOT)), "files": len(inventory), "live": audit(frame), "experiments": []}
    cutoff = int(frame.timestamp.max())
    other_files = [p for p in (ROOT / "data_lake/raw").rglob("*.parquet") if p not in inventory]
    others = pd.concat([pd.read_parquet(p) for p in other_files], ignore_index=True)
    for path in (ROOT / "data_lake/experiments").glob("*/manifest.json"):
        manifest = json.loads(path.read_text())
        if not (int(frame.timestamp.min()) <= manifest["timestamp"] <= cutoff):
            continue
        subset = others[others.capture_id.eq(manifest["experiment_id"])]
        entry = {k: manifest.get(k) for k in ["experiment_id", "scenario", "phase", "pcap_packets", "parsed_packets", "rejected_packets", "saved_rows", "labeled_rows", "unknown_rows"]}
        if len(subset):
            entry["audit"] = audit(subset)
            reasons = Counter()
            offsets = []
            for packet in subset[subset.ground_truth_scenario.eq("Unknown")].to_dict("records"):
                if packet["protocol"] == "ICMP":
                    reasons["ICMP_not_an_attributable_transport_flow"] += 1
                    continue
                candidates = [flow for flow in manifest["flows"] if
                    (packet["src_port"], packet["dst_port"]) in [(flow["src_port"], flow["dst_port"]), (flow["dst_port"], flow["src_port"])]]
                if not candidates:
                    reasons["no_endpoint_port_pair"] += 1
                elif any(flow["src_ip"] == "0.0.0.0" for flow in candidates):
                    reasons["wildcard_manifest_source"] += 1
                elif any(flow["started_ms"] <= packet["timestamp"] <= flow["ended_ms"] for flow in candidates):
                    reasons["other_mismatch"] += 1
                else:
                    delta = min((packet["timestamp"] - flow["started_ms"] if packet["timestamp"] < flow["started_ms"] else packet["timestamp"] - flow["ended_ms"] for flow in candidates), key=abs)
                    offsets.append(delta)
                    reasons["before_flow_start" if delta < 0 else "after_flow_end"] += 1
            entry["unknown_reasons"] = dict(reasons)
            entry["unknown_time_offset_ms"] = {"min": min(offsets), "max": max(offsets)} if offsets else None
        report["experiments"].append(entry)
    path = ROOT / "scratch/session_204_audit_2026-10-12.json"
    path.write_text(json.dumps(report, indent=2, default=lambda value: int(value)), encoding="utf-8")
    print(json.dumps(report, indent=2, default=lambda value: int(value)), flush=True)


if __name__ == "__main__":
    main()
