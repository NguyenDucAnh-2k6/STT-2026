"""Operator-confirmed Normal annotations with reversible batch backups."""
import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

import pandas as pd

from ml_engine.config.schema import LABEL_NAMES
from digital_twin.lab.profile import scan_ports


def normal_review_mask(frame: pd.DataFrame, lab_port: int = 8088) -> tuple[pd.Series, pd.Series]:
    unknown = frame.ground_truth_scenario.fillna("Unknown").isin(["Unknown", "", "Unlabeled"])
    lab = pd.Series(False, index=frame.index)
    for name in ["experiment_id", "requested_experiment_class"]:
        if name in frame:
            lab |= frame[name].notna() & frame[name].astype(str).ne("")
    if "data_provenance" in frame:
        lab |= frame.data_provenance.eq("twin-controlled-lab")
    if "requested_attack_label" in frame:
        lab |= frame.requested_attack_label.isin(set(LABEL_NAMES) - {"Normal"})
    for name in ["src_port", "dst_port", "tcp.srcport", "tcp.dstport"]:
        if name in frame:
            lab |= pd.to_numeric(frame[name], errors="coerce").isin(scan_ports(lab_port))
    packets = frame.record_kind.eq("packet") if "record_kind" in frame else pd.Series(False, index=frame.index)
    return unknown & packets & ~lab, unknown & lab


def relabel_operator_normal(base_dir: Path, apply: bool = False, lab_port: int = 8088) -> dict:
    base_dir = base_dir.resolve()
    raw = base_dir / "raw"
    annotation_id = uuid.uuid4().hex
    backup_root = base_dir / "label_backups" / annotation_id
    report = {"annotation_id": annotation_id, "basis": "operator_report_no_attacks", "normal_rows": 0,
              "skipped_lab_unknown": 0, "files": [], "applied": False}
    staged = []
    applied_paths = []
    try:
        for path in sorted(raw.rglob("*.parquet")):
            relative = path.resolve().relative_to(raw.resolve())
            before = path.stat()
            frame = pd.read_parquet(path)
            if "ground_truth_scenario" not in frame:
                continue
            mask, lab = normal_review_mask(frame, lab_port)
            report["skipped_lab_unknown"] += int(lab.sum())
            count = int(mask.sum())
            if not count:
                continue
            report["normal_rows"] += count
            entry = {"path": str(relative), "normal_rows": count}
            report["files"].append(entry)
            if not apply:
                continue
            backup = backup_root / relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup)
            entry["original_sha256"] = hashlib.sha256(backup.read_bytes()).hexdigest()
            for field, source in [("previous_ground_truth_scenario", "ground_truth_scenario"), ("previous_label_source", "label_source")]:
                if field not in frame:
                    frame[field] = pd.Series(None, index=frame.index, dtype=object)
                frame.loc[mask, field] = frame.loc[mask, source] if source in frame else None
            for field, value in {"ground_truth_scenario": "Normal", "label_source": "manual_review",
                                 "label_method": "operator_assertion", "label_reason": report["basis"],
                                 "label_annotation_id": annotation_id, "label_reviewed_at_ms": int(time.time()*1000),
                                 "is_attack": 0}.items():
                if field not in frame:
                    frame[field] = pd.Series(None, index=frame.index, dtype=object)
                frame.loc[mask, field] = value
            temporary = path.with_suffix(".normal-review.tmp")
            frame.to_parquet(temporary, index=False, compression="snappy")
            if before.st_mtime_ns != path.stat().st_mtime_ns or before.st_size != path.stat().st_size:
                raise RuntimeError("Batch changed during review; refusing overwrite")
            normal = int(frame.ground_truth_scenario.eq("Normal").sum())
            attack = int((~frame.ground_truth_scenario.isin(["Normal", "Unknown"]) & frame.ground_truth_scenario.notna()).sum())
            staged.append((path, temporary, backup, normal, attack))
        if apply and staged:
            report["applied"] = True
            (backup_root / "review.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            with closing(sqlite3.connect(base_dir / "catalog.db", timeout=30)) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    catalog_paths = {Path(row[0]).resolve(): row[0] for row in connection.execute("SELECT path FROM packet_batches")}
                    for path, temporary, backup, normal, attack in staged:
                        os.replace(temporary, path)
                        applied_paths.append((path, backup))
                        catalog_path = catalog_paths.get(path.resolve(), str(path))
                        connection.execute("UPDATE packet_batches SET normal=?, attack=?, size_kb=? WHERE path=?",
                                           (normal, attack, path.stat().st_size/1024, catalog_path))
        return report
    except Exception:
        for path, backup in reversed(applied_paths):
            shutil.copy2(backup, path)
        if backup_root.exists():
            report["applied"] = False
            (backup_root / "review.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise
    finally:
        for _, temporary, _, _, _ in staged:
            temporary.unlink(missing_ok=True)
