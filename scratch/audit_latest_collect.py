"""Frozen latest runtime + associated Twin audit. Never export raw payload or Info."""
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.quality import select_training_records
from digital_twin.lab.flows import packet_label
from firmware.host_probe.tshark_engine import find_tshark_path
from firmware.host_probe.packet_capture import unescape_field
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES, LABEL_NAMES
from ml_engine.preprocessing.validation import invalid_record_mask

TZ = ZoneInfo("Asia/Bangkok")


def payload_bytes(value: object) -> bytes:
    value = str(value).replace(":", "").strip()
    return b"" if value in ("", "0", "None", "nan") else bytes.fromhex(value)


def analyze(frame: pd.DataFrame) -> dict:
    eligible, gate = select_training_records(frame)
    payload_stats = Counter()
    bodies = []
    request_templates = set()
    for row in frame.to_dict("records"):
        try:
            body = payload_bytes(row["tcp.payload"])
            payload_stats["present" if body else "absent"] += 1
            if body:
                bodies.append(hashlib.sha256(body).hexdigest())
                payload_stats["length_matches_tcp_len" if len(body) == row["tcp.len"] else "length_mismatch"] += 1
                text = unquote(body.decode("utf-8", errors="replace")).lower()
                payload_stats["http_request"] += int(bool(re.match(r"^(get|post|head|put|delete) ", text)))
                if re.match(r"^(get|post|head|put|delete) ", text):
                    request_templates.add(hashlib.sha256(text.split("\r\n", 1)[0].encode()).hexdigest())
                payload_stats["http_response"] += int(text.startswith("http/"))
                payload_stats["sqli_signature"] += int(any(token in text for token in ["union select", "information_schema", "sleep(5)", "drop table", "or '1'='1", "or 1=1"]))
                payload_stats["xss_signature"] += int(any(token in text for token in ["<script", "onerror=", "javascript:alert", "onfocus="]))
                payload_stats["sqlmap_user_agent"] += int("user-agent: sqlmap" in text)
                payload_stats["benign_target_json_response"] += int('"executes_injected_content": false' in text)
            elif row["tcp.len"] > 0:
                payload_stats["missing_despite_tcp_len"] += 1
        except (ValueError, TypeError):
            payload_stats["invalid_hex"] += 1
    seq = frame.groupby("capture_id").sequence.agg(["min", "max", "nunique"])
    span = int((seq["max"] - seq["min"] + 1).sum())
    raw_stats = {}
    for name in ("raw_tcp_payload_hex", "raw_tcp_payload_text", "raw_http_query", "raw_http_body", "raw_mqtt_message", "raw_packet_info"):
        raw_stats[name] = {"column_present": name in frame, "nonempty": int(frame[name].notna().sum()) if name in frame else 0}
    if "raw_tcp_payload_decode_status" in frame:
        raw_stats["decode_status"] = frame.raw_tcp_payload_decode_status.value_counts().to_dict()
        raw_stats["text_byte_roundtrip_mismatch"] = sum(
            row["raw_tcp_payload_text"].encode("utf-8") != payload_bytes(row["raw_tcp_payload_hex"])
            for row in frame[frame.raw_tcp_payload_text.notna()].to_dict("records"))
    return {"raw_content": raw_stats, "rows": len(frame), "labels": frame.ground_truth_scenario.value_counts().to_dict(), "eligibility": gate,
        "time_start": datetime.fromtimestamp(frame.timestamp.min()/1000, TZ).isoformat(),
        "time_end": datetime.fromtimestamp(frame.timestamp.max()/1000, TZ).isoformat(),
        "protocols": frame.protocol.value_counts().to_dict(), "payload": dict(payload_stats),
        "unique_payloads": len(set(bodies)), "unique_request_templates": len(request_templates), "info_column_present": "info" in frame,
        "info_nonempty": int(frame["info"].fillna("").astype(str).ne("").sum()) if "info" in frame else 0,
        "null_features": int(frame[EDGE_IIOTSET_FEATURES].isna().any(axis=1).sum()),
        "malformed": int(invalid_record_mask(frame).sum()),
        "missing_feature_rows": int(frame.missing_features.map(len).gt(0).sum()),
        "truncated_rows": int(frame.captured_length.lt(frame.frame_length).sum()),
        "duplicate_packet_id": int(frame.packet_id.duplicated().sum()),
        "feature_only_duplicates": int(frame[EDGE_IIOTSET_FEATURES].duplicated().sum()),
        "constant_features": [name for name in EDGE_IIOTSET_FEATURES if frame[name].nunique(dropna=False) == 1],
        "sequence_span": span, "sequence_coverage": float(seq["nunique"].sum()/span),
        "frame_quantiles": frame.frame_length.quantile([.5, .95, 1]).to_dict()}


def main() -> None:
    inventory = sorted((ROOT / "data_lake/raw").rglob("*.parquet"), key=lambda path:path.stat().st_mtime)
    prefix = inventory[-1].name.split("_batch_")[0]
    live_files = [path for path in inventory if path.name.startswith(prefix + "_batch_")]
    live = pd.concat([pd.read_parquet(path) for path in live_files], ignore_index=True)
    manifests = [json.loads(path.read_text()) for path in (ROOT / "data_lake/experiments").glob("*/manifest.json")]
    linked = [m for m in manifests if live.timestamp.min() <= m["timestamp"] <= live.timestamp.max()]
    report = {"live_session": prefix, "live_files": len(live_files), "live": analyze(live), "experiments": []}
    all_frames = {path:pd.read_parquet(path) for path in inventory if path not in live_files}
    latest_ids = {m["experiment_id"] for m in linked}
    # Include earlier captures using the new content schema, but mark them
    # separately from the latest live runtime so session boundaries stay explicit.
    raw_ids = set()
    for frame in all_frames.values():
        if "content_schema_version" in frame:
            raw_ids.update(frame.loc[frame.content_schema_version.eq(1), "capture_id"].unique())
    additional = [m for m in manifests if m["experiment_id"] in raw_ids and m["experiment_id"] not in latest_ids]
    report["additional_content_experiment_ids"] = [m["experiment_id"] for m in additional]
    linked.extend(additional)
    frames = []
    for manifest in linked:
        pieces = [frame for frame in all_frames.values() if frame.capture_id.eq(manifest["experiment_id"]).any()]
        if not pieces:
            continue
        frame = pd.concat(pieces, ignore_index=True)
        frame = frame[frame.capture_id.eq(manifest["experiment_id"])]
        frames.append(frame)
        result = {"id": manifest["experiment_id"], "scenario": manifest["scenario"], "files": len(pieces),
            "within_latest_live_session": manifest["experiment_id"] in latest_ids,
            "manifest": {key:manifest.get(key) for key in ["phase", "pcap_packets", "parsed_packets", "rejected_packets", "saved_rows", "labeled_rows", "unknown_rows", "labeling_policy", "capture_filter"]},
            "flow_count": len(manifest["flows"]), "audit": analyze(frame)}
        result["client_port_range"] = [min(f["src_port"] for f in manifest["flows"]), max(f["src_port"] for f in manifest["flows"])]
        result["flow_label_mismatch"] = sum(packet_label(row, manifest["flows"], manifest["scenario"])["ground_truth_scenario"] != row["ground_truth_scenario"] for row in frame.to_dict("records"))
        path = ROOT / "data_lake/experiments" / manifest["experiment_id"] / "capture.pcapng"
        fields = ["frame.number", "_ws.col.Info", "tcp.payload", "http.request.uri.query", "http.file_data", "mqtt.msg"]
        command = [find_tshark_path(), "-2", "-r", str(path), "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=f"]
        for field in fields:
            command.extend(["-e", field])
        data = subprocess.check_output(command, text=True, encoding="utf-8", timeout=30)
        descriptions = Counter()
        raw_match = 0
        stored = frame.set_index("sequence")["tcp.payload"]
        raw_stored = frame.set_index("sequence")
        content_mismatch = Counter()
        for values in csv.reader(io.StringIO(data), delimiter="\t"):
            number, info, payload, query, body, mqtt = map(unescape_field, values)
            category = "HTTP GET" if info.startswith("GET ") else "HTTP response" if info.startswith("HTTP/") else "TCP ACK" if "[ACK]" in info else "TCP SYN" if "[SYN" in info else "TCP FIN" if "[FIN" in info else "Other"
            descriptions[category] += 1
            raw_match += int(payload_bytes(payload) == payload_bytes(stored.loc[int(number)]))
            for column, value in [("raw_packet_info", info), ("raw_tcp_payload_hex", payload), ("raw_http_query", query), ("raw_http_body", body), ("raw_mqtt_message", mqtt)]:
                if column not in raw_stored:
                    content_mismatch[column] += 1
                else:
                    actual = raw_stored.loc[int(number), column]
                    content_mismatch[column] += int(("" if pd.isna(actual) else actual) != value)
        result["pcap_info_categories"] = dict(descriptions)
        result["parquet_payload_matches_pcap"] = raw_match
        result["raw_content_mismatch_vs_pcap"] = dict(content_mismatch)
        report["experiments"].append(result)
    if frames:
        report["combined_twin"] = analyze(pd.concat(frames, ignore_index=True))
    report["missing_classes_in_latest_twin"] = sorted(set(LABEL_NAMES) - {m["scenario"] for m in linked})
    stamp = datetime.fromtimestamp(live.timestamp.min()/1000, TZ).strftime("%Y%m%d_%H%M%S")
    path = ROOT / "scratch" / f"collect_quality_{stamp}.json"
    path.write_text(json.dumps(report, indent=2, default=lambda value:int(value)), encoding="utf-8")
    print(json.dumps(report, indent=2, default=lambda value:int(value)), flush=True)


if __name__ == "__main__":
    main()
