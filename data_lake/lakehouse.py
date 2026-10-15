"""Append immutable Parquet batches; raw measurements and labels stay separate."""
import json
import logging
import math
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from typing import Any, Optional, Callable

import pandas as pd
import pyarrow.parquet as pq
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import CATEGORICAL_FEATURES
from ml_engine.preprocessing.modules.base import normalize_categorical_value
from .quality import select_training_records, TRAINING_OPTIONAL_COLUMNS

LOG = logging.getLogger(__name__)


def raw_numeric(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        parsed = int(value, 16) if isinstance(value, str) and value.lower().startswith("0x") else float(value)
        return parsed if math.isfinite(parsed) else None
    except (ValueError, TypeError, OverflowError):
        return None


class DataLakeManager:
    def __init__(self, base_dir: Optional[str] = None) -> None:
        self.base_dir = str(base_dir or Path(__file__).resolve().parent)
        self.raw_dir = str(Path(self.base_dir) / "raw")
        Path(self.raw_dir).mkdir(parents=True, exist_ok=True)
        self.catalog_db_path = str(Path(self.base_dir) / "catalog.db")
        self._lock = threading.RLock()
        self.current_session_id = None
        self.last_training_report: dict = {}
        self.buffer: list[dict[str, Any]] = []
        self.flush_threshold = 500
        self.session_total_records = 0
        self.session_normal_records = 0
        self.session_attack_records = 0
        self._batch = 0
        self.current_probe_type = "host"
        self.current_sniffer_mode = "host-interface"
        with closing(sqlite3.connect(self.catalog_db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS packet_batches (path TEXT PRIMARY KEY, session_id TEXT, created REAL, records INTEGER, normal INTEGER, attack INTEGER, size_kb REAL)")
            conn.commit()

    def start_session(self, probe_type: str = "host", sniffer_mode: str = "host-interface") -> str:
        with self._lock:
            if self.current_session_id:
                self.close_session()
            self.current_session_id = "sess_" + uuid.uuid4().hex
            self.current_probe_type, self.current_sniffer_mode = probe_type, sniffer_mode
            self.session_total_records = self.session_normal_records = self.session_attack_records = 0
            self._batch = 0
            return self.current_session_id

    def record_telemetry(self, telemetry: dict[str, Any], ground_truth: str = "Unknown",
                         prediction: Optional[dict[str, Any]] = None,
                         extracted_features: Optional[dict[str, Any]] = None) -> None:
        with self._lock:
            if not self.current_session_id:
                self.start_session()
            row = dict(telemetry)
            if row.get("timestamp_kind") == "uptime_ms":
                row["source_timestamp"] = row.get("timestamp")
                row["timestamp"] = int(time.time() * 1000)
                row["timestamp_kind"] = "receipt_epoch_ms"
            row.update(session_id=self.current_session_id, sniffer_mode=telemetry.get("sniffer_mode", self.current_sniffer_mode),
                       probe_type=telemetry.get("probe_type", self.current_probe_type),
                       receipt_timestamp=int(time.time() * 1000), ground_truth_scenario=ground_truth,
                       is_attack=None if ground_truth == "Unknown" else int(ground_truth != "Normal"))
            pred = prediction or {}
            row.update(predicted_threat=pred.get("threat_type", "Unknown"),
                       inference_status=pred.get("inference_status", "unavailable"),
                       anomaly_score=pred.get("anomaly_score"), confidence=pred.get("confidence"))
            # Persist canonical raw values exactly once, never scaled/encoded outputs.
            for name in EDGE_IIOTSET_FEATURES:
                if name in row:
                    row[name] = (normalize_categorical_value(row[name]) if name in CATEGORICAL_FEATURES
                                 and row[name] is not None else
                                 raw_numeric(row[name]) if name not in CATEGORICAL_FEATURES else None)
            # Nested UI payloads do not become implicit Arrow structures with unstable schemas.
            for name, value in list(row.items()):
                if isinstance(value, dict) or (isinstance(value, list) and name not in ("missing_features", "absent_fields")):
                    row[name] = json.dumps(value, ensure_ascii=False, allow_nan=False)
            # Ensure identifiers are always strings to prevent Arrow schema conflict (e.g. mixed int/str capture_id)
            for id_field in ("capture_id", "boot_id", "device_id", "packet_id", "session_id", "dissection_id"):
                if id_field in row and row[id_field] is not None:
                    row[id_field] = str(row[id_field])
            if len(self.buffer) >= self.flush_threshold:
                self._flush_locked()
            self.buffer.append(row)

    def annotate_pending_scenarios(self, annotate: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        """Refresh only experiment context on owned, not-yet-persisted records."""
        with self._lock:
            for row in self.buffer:
                row.update(annotate(row))

    def _flush_locked(self) -> None:
        if not self.buffer:
            return
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        partition = Path(self.raw_dir) / f"date={today}"
        partition.mkdir(parents=True, exist_ok=True)
        path = partition / f"session_{self.current_session_id}_batch_{self._batch:06d}.parquet"
        temporary = path.with_suffix(".parquet.tmp")
        frame = pd.DataFrame(self.buffer)
        for id_field in ("capture_id", "boot_id", "device_id", "packet_id", "session_id", "dissection_id"):
            if id_field in frame.columns:
                frame[id_field] = frame[id_field].astype(str)
        frame.to_parquet(temporary, index=False, compression="snappy")
        os.replace(temporary, path)
        normal = int(frame.ground_truth_scenario.eq("Normal").sum())
        attack = int((~frame.ground_truth_scenario.isin(["Normal", "Unknown"])).sum())
        with closing(sqlite3.connect(self.catalog_db_path)) as conn:
            conn.execute("INSERT OR REPLACE INTO packet_batches VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (str(path), self.current_session_id, time.time(), len(frame), normal, attack, path.stat().st_size / 1024))
            conn.commit()
        self.session_total_records += len(frame)
        self.session_normal_records += normal
        self.session_attack_records += attack
        self.buffer.clear()
        self._batch += 1

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def close_session(self) -> dict[str, Any]:
        with self._lock:
            self._flush_locked()
            summary = {"session_id": self.current_session_id, "total_records": self.session_total_records,
                       "normal_records": self.session_normal_records, "attack_records": self.session_attack_records}
            self.current_session_id = None
            return summary

    def get_summary_stats(self) -> dict[str, Any]:
        # The catalog can outlive files removed externally. Count only batches
        # still on disk; keep catalog entries so restored files remain visible.
        with self._lock, closing(sqlite3.connect(self.catalog_db_path)) as conn:
            batches = conn.execute("SELECT path, session_id, records, normal, attack, size_kb, created FROM packet_batches").fetchall()
            sessions: dict[str, list[Any]] = {}
            for path, session_id, count, normal, attack, size_kb, created in batches:
                if not Path(path).is_file():
                    continue
                row = sessions.setdefault(session_id, [session_id, 0, 0, 0, 0.0, created, created])
                for index, value in enumerate((count, normal, attack, size_kb), start=1):
                    row[index] += value
                row[5], row[6] = min(row[5], created), max(row[6], created)
            rows = sorted(sessions.values(), key=lambda row: row[6], reverse=True)
        recent = [{"session_id": r[0], "total_records": r[1], "records_count": r[1], "start_time": r[5], "normal_records": r[2],
                   "attack_records": r[3], "unknown_records": r[1] - r[2] - r[3],
                   "attack_scenario": "Normal" if r[2] == r[1] else "Unknown" if r[2] + r[3] == 0 else "Mixed",
                   "file_size_kb": r[4], "datetime": datetime.fromtimestamp(r[5]).isoformat(),
                   "probe_type": "host", "sniffer_mode": "host-interface"} for r in rows[:5]]
        return {"total_sessions": len(rows), "total_records": sum(r[1] for r in rows),
                "buffered_records": len(self.buffer), "current_session_id": self.current_session_id,
                "current_session_records": next((r[1] for r in rows if r[0] == self.current_session_id), 0),
                "normal_records": sum(r[2] for r in rows), "attack_records": sum(r[3] for r in rows),
                "unknown_records": sum(r[1] - r[2] - r[3] for r in rows),
                "total_storage_kb": sum(r[4] for r in rows), "recent_sessions": recent}

    def load_all_training_data(self, columns: Optional[list[str]] = None) -> pd.DataFrame:
        frames = []
        all_columns: list[str] = []
        for path in sorted(Path(self.raw_dir).rglob("*.parquet")):
            selected = None
            # Read the footer and projected data through the same file handle.
            # Small batches otherwise pay two file opens/metadata reads each.
            with pq.ParquetFile(path) as parquet:
                if columns is not None:
                    available = set(parquet.schema_arrow.names)
                    selected = [name for name in columns if name in available]
                frame = parquet.read(columns=selected).to_pandas()
            for name in frame.columns:
                if name not in all_columns:
                    all_columns.append(name)
            if len(frame):
                # Explicitly remove all-null blocks before concat, then restore
                # columns. Nullable metadata in old/new schemas must not drive
                # pandas' changing dtype inference or lose row identities.
                frames.append(frame.loc[:, frame.notna().any(axis=0)])
        return pd.concat(frames, ignore_index=True).reindex(columns=all_columns) if frames else pd.DataFrame(columns=all_columns)

    def load_labeled_dataset(self, valid_labels: Optional[list[str]] = None,
                             columns: Optional[list[str]] = None) -> pd.DataFrame:
        if columns is not None:
            columns = list(dict.fromkeys(columns + TRAINING_OPTIONAL_COLUMNS))
        frame, report = select_training_records(self.load_all_training_data(columns=columns))
        self.last_training_report = report
        LOG.info("Training eligibility: %s", report)
        return frame[frame.ground_truth_scenario.isin(valid_labels)] if valid_labels and not frame.empty else frame

    def load_normal_baseline_dataset(self, days: int = 30) -> pd.DataFrame:
        frame = self.load_labeled_dataset(["Normal"])
        return frame[frame.timestamp.ge((time.time() - days * 86400) * 1000)] if not frame.empty else frame

    @staticmethod
    def sanitize_features_for_training(frame: pd.DataFrame) -> pd.DataFrame:
        return frame[EDGE_IIOTSET_FEATURES].copy()

    def sync_to_remote(self) -> dict:
        from .remote_storage import get_remote_storage_manager
        return get_remote_storage_manager().sync_lake_to_remote()

    def sync_from_remote(self) -> dict:
        from .remote_storage import get_remote_storage_manager
        return get_remote_storage_manager().sync_remote_to_lake()


_manager: Optional[DataLakeManager] = None


def get_lakehouse_manager() -> DataLakeManager:
    global _manager
    if _manager is None:
        _manager = DataLakeManager()
    return _manager
