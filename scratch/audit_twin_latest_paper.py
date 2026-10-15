"""Frozen latest Twin batch audit; aggregate diagnostics only, no raw payload export."""
import json
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.quality import select_training_records, TRAINING_REQUIRED_COLUMNS
from digital_twin.lab.flows import packet_label


def summarize(frame: pd.DataFrame) -> dict:
    def numeric(name: str) -> pd.Series:
        return pd.to_numeric(frame[name], errors="coerce")
    tcp = frame[numeric("tcp.srcport").gt(0)]
    udp = frame[numeric("udp.port").gt(0)]
    flags = pd.to_numeric(tcp["tcp.flags"], errors="coerce").fillna(0).astype(int)
    return {"rows": len(frame), "tcp_rows": len(tcp), "udp_rows": len(udp),
        "tcp_destination_ports": pd.to_numeric(tcp["tcp.dstport"], errors="coerce").value_counts().head(12).to_dict(),
        "unique_tcp_destination_ports": int(tcp["tcp.dstport"].nunique()),
        "syn_only": int(flags.eq(2).sum()), "syn_ack": int(flags.eq(18).sum()),
        "unique_syn_destination_ports": int(tcp.loc[flags.eq(2), "tcp.dstport"].nunique()),
        "syn_destination_top_ports": tcp.loc[flags.eq(2), "tcp.dstport"].value_counts().head(8).to_dict(),
        "ack_bit": int((flags & 16).ne(0).sum()), "rst_bit": int((flags & 4).ne(0).sum()),
        "http_methods": frame["http.request.method"].fillna("0").astype(str).value_counts().to_dict(),
        "http_payload_rows": int((~frame["http.file_data"].fillna("0").astype(str).isin(["0", "0.0", "", "nan"])).sum()),
        "udp_delta_median": float(pd.to_numeric(udp["udp.time_delta"], errors="coerce").median()) if len(udp) else None}


def main() -> None:
    manifests = [json.loads(p.read_text(encoding="utf-8")) for p in (ROOT/"data_lake/experiments").glob("*/manifest.json")]
    manifests.sort(key=lambda m: m["timestamp"])
    batch = [manifests[-1]]
    for manifest in reversed(manifests[:-1]):
        if batch[-1]["timestamp"] - manifest["timestamp"] > 30*60*1000:
            break
        batch.append(manifest)
    batch.reverse()
    ids = {m["experiment_id"] for m in batch}
    columns = list(dict.fromkeys(TRAINING_REQUIRED_COLUMNS + ["experiment_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol_stack", "raw_http_uri", "label_method"]))
    frames = []
    for path in (ROOT/"data_lake/raw").rglob("*.parquet"):
        with pq.ParquetFile(path) as file:
            names = file.schema_arrow.names
            if "experiment_id" not in names:
                continue
            membership = file.read(columns=["experiment_id"]).to_pandas().experiment_id.isin(ids)
            if membership.any():
                frames.append(file.read(columns=[name for name in columns if name in names]).to_pandas().loc[membership])
    all_rows = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    report = {"paper": "https://doi.org/10.1109/ACCESS.2022.3165809", "experiments": [], "benchmark": {}}
    for manifest in batch:
        frame = all_rows[all_rows.experiment_id.eq(manifest["experiment_id"])]
        item = {key: manifest.get(key) for key in ["experiment_id", "scenario", "phase", "error", "saved_rows", "labeled_rows", "unknown_rows", "capture_filter"]}
        item["started_local"] = datetime.fromtimestamp(manifest["timestamp"]/1000, ZoneInfo("Asia/Bangkok")).isoformat()
        item["flow_count"] = len(manifest.get("flows", []))
        item["unique_target_ports_from_flows"] = len({flow["dst_port"] for flow in manifest.get("flows", [])})
        if len(frame):
            _, gate = select_training_records(frame)
            item.update(summarize(frame), eligibility=gate, labels=frame.ground_truth_scenario.value_counts().to_dict(),
                flow_attribution_mismatches=sum(packet_label(row, manifest["flows"], manifest["scenario"])["ground_truth_scenario"] != row["ground_truth_scenario"] for row in frame.to_dict("records")))
        report["experiments"].append(item)
    dataset = next((ROOT/"ml_engine/datasets").rglob("ML-EdgeIIoT-dataset.csv"))
    selected_columns = ["Attack_type", "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.port", "udp.time_delta", "http.request.method", "http.file_data"]
    benchmark = pd.read_csv(dataset, usecols=selected_columns, low_memory=False)
    for label in all_rows.ground_truth_scenario.unique():
        matching = benchmark[benchmark.Attack_type.eq(label)]
        if len(matching):
            report["benchmark"][label] = summarize(matching)
    destination = ROOT/"scratch/twin_latest_paper_audit_20261012.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
