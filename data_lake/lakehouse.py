#!/usr/bin/env python3
"""
Data Lakehouse Manager Module
==============================
Quản lý lưu trữ dữ liệu mạng hàng ngày theo chuẩn Apache Parquet và SQLite Catalog:
1. Phân vùng dữ liệu theo ngày: data_lake/raw/date=YYYY-MM-DD/session_{id}.parquet
2. Lưu siêu dữ liệu vào SQLite: data_lake/catalog.db
3. Cung cấp API trích xuất dữ liệu Normal cho Anomaly Detector và toàn bộ dữ liệu cho Classifier.
4. Đảm bảo hiệu năng cao với bộ đệm bộ nhớ (in-memory buffer) và nén Snappy.
"""

import os
import sys
import time
import sqlite3
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DataLakeManager:
    """
    Trình quản lý kho dữ liệu Data Lakehouse cho hệ thống Edge AI.
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.join(ROOT_DIR, "data_lake")
        self.raw_dir = os.path.join(self.base_dir, "raw")
        self.catalog_db_path = os.path.join(self.base_dir, "catalog.db")
        os.makedirs(self.raw_dir, exist_ok=True)

        self._lock = threading.Lock()
        self.current_session_id: Optional[str] = None
        self.current_probe_type: str = "esp32"
        self.current_sniffer_mode: str = "all-networks"
        self.session_start_time: float = 0.0
        self.current_parquet_path: Optional[str] = None

        self.buffer: List[Dict[str, Any]] = []
        self.flush_threshold: int = 50
        self.last_flush_time: float = time.time()

        self.session_total_records: int = 0
        self.session_normal_records: int = 0
        self.session_attack_records: int = 0

        self._init_catalog_db()

    def _init_catalog_db(self):
        """Khởi tạo bảng cơ sở dữ liệu siêu dữ liệu (SQLite Catalog)."""
        with sqlite3.connect(self.catalog_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    start_time REAL,
                    end_time REAL,
                    date_partition TEXT,
                    probe_type TEXT,
                    sniffer_mode TEXT,
                    total_records INTEGER,
                    normal_records INTEGER,
                    attack_records INTEGER,
                    parquet_path TEXT,
                    file_size_kb REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_partitions (
                    date_partition TEXT PRIMARY KEY,
                    total_sessions INTEGER,
                    total_records INTEGER,
                    normal_records INTEGER,
                    attack_records INTEGER,
                    last_updated REAL
                )
            """)
            conn.commit()

    def start_session(self, probe_type: str = "esp32", sniffer_mode: str = "all-networks") -> str:
        """Bắt đầu một phiên thu thập dữ liệu mới."""
        with self._lock:
            # Nếu đang có session cũ chưa đóng, đóng trước
            if self.current_session_id and len(self.buffer) > 0:
                self._flush_locked()
                self._update_session_db_locked(is_final=True)

            now = datetime.now()
            date_str = now.strftime("%Y-%m-%d")
            ts_str = now.strftime("%H%M%S")
            self.current_session_id = f"sess_{date_str.replace('-', '')}_{ts_str}_{os.getpid()}"
            self.current_probe_type = probe_type
            self.current_sniffer_mode = sniffer_mode
            self.session_start_time = time.time()

            self.session_total_records = 0
            self.session_normal_records = 0
            self.session_attack_records = 0
            self.buffer = []
            self.last_flush_time = time.time()

            # Đường dẫn phân vùng Parquet
            partition_dir = os.path.join(self.raw_dir, f"date={date_str}")
            os.makedirs(partition_dir, exist_ok=True)
            self.current_parquet_path = os.path.join(partition_dir, f"session_{self.current_session_id}.parquet")

            # Ghi nhận session khởi tạo vào SQLite
            with sqlite3.connect(self.catalog_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO sessions 
                    (session_id, start_time, end_time, date_partition, probe_type, sniffer_mode, total_records, normal_records, attack_records, parquet_path, file_size_kb)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.current_session_id,
                    self.session_start_time,
                    self.session_start_time,
                    date_str,
                    self.current_probe_type,
                    self.current_sniffer_mode,
                    0, 0, 0,
                    self.current_parquet_path,
                    0.0
                ))
                conn.commit()

            print(f"[DataLake] Da khoi tao phien thu thap moi: '{self.current_session_id}'")
            print(f"           Phan vung: date={date_str} | File: {os.path.basename(self.current_parquet_path)}")
            return self.current_session_id

    def record_telemetry(
        self,
        telemetry: Dict[str, Any],
        ground_truth: str = "Normal",
        prediction: Optional[Dict[str, Any]] = None,
        extracted_features: Optional[Dict[str, float]] = None
    ):
        """Ghi nhận một điểm dữ liệu telemetry vào bộ đệm của phiên hiện tại."""
        with self._lock:
            if not self.current_session_id:
                self.start_session()

            now_ts = time.time()
            is_attack = 0 if ground_truth.lower() == "normal" else 1

            row: Dict[str, Any] = {
                "session_id": self.current_session_id,
                "timestamp": telemetry.get("timestamp", int(now_ts * 1000)),
                "datetime_iso": datetime.fromtimestamp(now_ts).isoformat(),
                "probe_type": self.current_probe_type,
                "sniffer_mode": self.current_sniffer_mode,
                "channel": str(telemetry.get("channel", "1")),
                # Đặc trưng lưu lượng cơ sở
                "packet_rate": float(telemetry.get("packet_rate", 0.0)),
                "byte_rate": float(telemetry.get("byte_rate", 0.0)),
                "avg_packet_size": float(telemetry.get("avg_packet_size", 0.0)),
                "syn_ratio": float(telemetry.get("syn_ratio", 0.0)),
                "ack_ratio": float(telemetry.get("ack_ratio", 0.0)),
                "udp_ratio": float(telemetry.get("udp_ratio", 0.0)),
                "icmp_ratio": float(telemetry.get("icmp_ratio", 0.0)),
                "unique_dst_ports": int(telemetry.get("unique_dst_ports", 0)),
                "tcp_count": int(telemetry.get("tcp_count", 0)),
                "udp_count": int(telemetry.get("udp_count", 0)),
                "icmp_count": int(telemetry.get("icmp_count", 0)),
                # Nhãn Ground-Truth
                "ground_truth_scenario": ground_truth,
                "is_attack": is_attack,
            }

            # Thông tin dự đoán mô hình (nếu có)
            if prediction:
                row["predicted_threat"] = prediction.get("threat_type", "Normal")
                row["anomaly_score"] = float(prediction.get("anomaly_score", 0.0))
                row["confidence"] = float(prediction.get("confidence", 1.0))
                row["edge_prediction"] = prediction.get("edge_prediction", "Normal")
                row["edge_flag"] = int(bool(prediction.get("edge_flag", False)))
            else:
                row["predicted_threat"] = telemetry.get("edge_prediction", "Normal")
                row["anomaly_score"] = 0.0
                row["confidence"] = 1.0
                row["edge_prediction"] = telemetry.get("edge_prediction", "Normal")
                row["edge_flag"] = int(bool(telemetry.get("edge_flag", False)))

            # Đặc trưng mở rộng Edge-IIoTset (56 features) nếu được trích xuất
            if extracted_features and isinstance(extracted_features, dict):
                for k, v in extracted_features.items():
                    row[f"feat_{k}"] = float(v)

            self.buffer.append(row)
            self.session_total_records += 1
            if is_attack == 1:
                self.session_attack_records += 1
            else:
                self.session_normal_records += 1

            # Tự động flush nếu đạt ngưỡng số lượng hoặc chu kỳ 10 giây
            if len(self.buffer) >= self.flush_threshold or (now_ts - self.last_flush_time >= 10.0):
                self._flush_locked()

    def _flush_locked(self):
        """Ghi buffer hiện tại sang file Parquet (yêu cầu đã giữ _lock)."""
        if not self.buffer or not self.current_parquet_path:
            return

        try:
            df_new = pd.DataFrame(self.buffer)

            # Nếu file parquet đã tồn tại, đọc và nối thêm
            if os.path.exists(self.current_parquet_path):
                df_existing = pd.read_parquet(self.current_parquet_path)
                df_combined = pd.concat([df_existing, df_new], ignore_index=True)
            else:
                df_combined = df_new

            df_combined.to_parquet(self.current_parquet_path, engine="pyarrow", compression="snappy", index=False)
            self.buffer.clear()
            self.last_flush_time = time.time()

            self._update_session_db_locked(is_final=False)
        except Exception as e:
            print(f"[DataLake] Canh bao khi flush Parquet: {e}")

    def _update_session_db_locked(self, is_final: bool = False):
        """Cập nhật trạng thái session và partition vào catalog SQLite."""
        if not self.current_session_id or not self.current_parquet_path:
            return

        file_size_kb = 0.0
        if os.path.exists(self.current_parquet_path):
            file_size_kb = round(os.path.getsize(self.current_parquet_path) / 1024.0, 2)

        now_ts = time.time()
        date_str = datetime.fromtimestamp(self.session_start_time).strftime("%Y-%m-%d")

        try:
            with sqlite3.connect(self.catalog_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE sessions SET
                        end_time = ?,
                        total_records = ?,
                        normal_records = ?,
                        attack_records = ?,
                        file_size_kb = ?
                    WHERE session_id = ?
                """, (
                    now_ts if is_final else self.last_flush_time,
                    self.session_total_records,
                    self.session_normal_records,
                    self.session_attack_records,
                    file_size_kb,
                    self.current_session_id
                ))

                # Cập nhật daily_partitions
                cursor.execute("""
                    SELECT COUNT(*), SUM(total_records), SUM(normal_records), SUM(attack_records)
                    FROM sessions WHERE date_partition = ?
                """, (date_str,))
                row = cursor.fetchone()
                if row and row[0] is not None:
                    tot_sess, tot_rec, norm_rec, atk_rec = row
                    cursor.execute("""
                        INSERT OR REPLACE INTO daily_partitions
                        (date_partition, total_sessions, total_records, normal_records, attack_records, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (date_str, tot_sess, tot_rec or 0, norm_rec or 0, atk_rec or 0, now_ts))

                conn.commit()
        except Exception as e:
            print(f"[DataLake] Canh bao cap nhat catalog SQLite: {e}")

    def close_session(self) -> Dict[str, Any]:
        """Đóng phiên thu thập hiện tại, đảm bảo toàn bộ dữ liệu đã được ghi đĩa an toàn."""
        with self._lock:
            if not self.current_session_id:
                return {}

            self._flush_locked()
            self._update_session_db_locked(is_final=True)

            summary = {
                "session_id": self.current_session_id,
                "start_time": self.session_start_time,
                "end_time": time.time(),
                "duration_sec": round(time.time() - self.session_start_time, 1),
                "total_records": self.session_total_records,
                "normal_records": self.session_normal_records,
                "attack_records": self.session_attack_records,
                "parquet_path": self.current_parquet_path,
                "file_size_kb": round(os.path.getsize(self.current_parquet_path) / 1024.0, 2) if (self.current_parquet_path and os.path.exists(self.current_parquet_path)) else 0.0
            }

            print("\n" + "=" * 65)
            print(" [DataLake] PHIEN THU THAP DU LIEU DA DUOC LUU AN TOAN VAO KHO:")
            print(f"  * Session ID     : {summary['session_id']}")
            print(f"  * Tong so mau    : {summary['total_records']:,} (Normal: {summary['normal_records']:,} | Attacks: {summary['attack_records']:,})")
            print(f"  * Thoi luong     : {summary['duration_sec']}s")
            print(f"  * Parquet File   : {summary['parquet_path']} ({summary['file_size_kb']} KB)")
            print("=" * 65 + "\n")

            # Tự động đẩy file lên MinIO/S3 nếu cấu hình MINIO_AUTO_SYNC=true
            auto_sync = os.getenv("MINIO_AUTO_SYNC", "false").lower() in ("true", "1", "yes")
            if auto_sync and summary["parquet_path"] and os.path.exists(summary["parquet_path"]):
                try:
                    from data_lake.remote_storage import get_minio_storage_manager
                    minio_mgr = get_minio_storage_manager()
                    rel_parquet = os.path.relpath(summary["parquet_path"], self.base_dir).replace("\\", "/")
                    remote_key = f"data_lake/{rel_parquet}"
                    ok = minio_mgr.upload_file(summary["parquet_path"], remote_key)
                    if ok:
                        minio_mgr.upload_file(self.catalog_db_path, "data_lake/catalog.db")
                        print(f" [DataLake/MinIO] Da tu dong dong bo session len MinIO: {remote_key}")
                except Exception as e:
                    print(f" [DataLake/MinIO] Khong the auto-sync len MinIO: {e}")

            self.current_session_id = None
            return summary

    def sync_to_remote(self) -> Dict[str, Any]:
        """Đẩy toàn bộ phân vùng Parquet và catalog lên MinIO."""
        from data_lake.remote_storage import get_minio_storage_manager
        return get_minio_storage_manager().sync_lake_to_remote()

    def sync_from_remote(self) -> Dict[str, Any]:
        """Tải các phân vùng Parquet mới từ MinIO về máy."""
        from data_lake.remote_storage import get_minio_storage_manager
        return get_minio_storage_manager().sync_remote_to_lake()


    def get_summary_stats(self) -> Dict[str, Any]:
        """Truy vấn siêu dữ liệu tổng quan kho Data Lake phục vụ Web Dashboard."""
        with sqlite3.connect(self.catalog_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), SUM(total_records), SUM(normal_records), SUM(attack_records), SUM(file_size_kb) FROM sessions")
            row = cursor.fetchone()
            total_sessions = row[0] or 0
            total_records = row[1] or 0
            normal_records = row[2] or 0
            attack_records = row[3] or 0
            total_storage_kb = round(row[4] or 0.0, 2)

            # Lấy thống kê ngày hôm nay
            today_str = datetime.now().strftime("%Y-%m-%d")
            cursor.execute("SELECT total_sessions, total_records, normal_records, attack_records FROM daily_partitions WHERE date_partition = ?", (today_str,))
            today_row = cursor.fetchone()
            today_stats = {
                "date": today_str,
                "sessions": today_row[0] if today_row else 0,
                "total_records": today_row[1] if today_row else 0,
                "normal_records": today_row[2] if today_row else 0,
                "attack_records": today_row[3] if today_row else 0
            }

            # Lấy 5 session gần nhất
            cursor.execute("""
                SELECT session_id, date_partition, probe_type, sniffer_mode, total_records, normal_records, attack_records, file_size_kb, start_time
                FROM sessions ORDER BY start_time DESC LIMIT 5
            """)
            recent_sessions = []
            for r in cursor.fetchall():
                recent_sessions.append({
                    "session_id": r[0],
                    "date": r[1],
                    "probe_type": r[2],
                    "sniffer_mode": r[3],
                    "total_records": r[4],
                    "normal_records": r[5],
                    "attack_records": r[6],
                    "file_size_kb": r[7],
                    "datetime": datetime.fromtimestamp(r[8]).strftime("%Y-%m-%d %H:%M:%S")
                })

            return {
                "total_sessions": total_sessions,
                "total_records": total_records,
                "normal_records": normal_records,
                "attack_records": attack_records,
                "total_storage_kb": total_storage_kb,
                "today": today_stats,
                "recent_sessions": recent_sessions
            }

    def load_normal_baseline_dataset(self, days: int = 30) -> pd.DataFrame:
        """
        Trích xuất toàn bộ dữ liệu Normal sạch từ các phân vùng Parquet
        phục vụ huấn luyện mô hình Anomaly Detector (Isolation Forest).
        """
        dfs = []
        for root, _, files in os.walk(self.raw_dir):
            for f in files:
                if f.endswith(".parquet"):
                    file_path = os.path.join(root, f)
                    try:
                        df = pd.read_parquet(file_path)
                        # Lọc chỉ lấy các dòng Normal thực tế
                        df_normal = df[df["ground_truth_scenario"] == "Normal"]
                        if not df_normal.empty:
                            dfs.append(df_normal)
                    except Exception as e:
                        print(f"[DataLake] Canh bao doc {file_path}: {e}")

        if not dfs:
            return pd.DataFrame()
        return pd.concat(dfs, ignore_index=True)

    def load_all_training_data(self) -> pd.DataFrame:
        """Trích xuất toàn bộ dữ liệu (cả Normal và Attacks) từ các phân vùng Parquet."""
        dfs = []
        for root, _, files in os.walk(self.raw_dir):
            for f in files:
                if f.endswith(".parquet"):
                    file_path = os.path.join(root, f)
                    try:
                        df = pd.read_parquet(file_path)
                        if not df.empty:
                            dfs.append(df)
                    except Exception as e:
                        print(f"[DataLake] Canh bao doc {file_path}: {e}")

        if not dfs:
            return pd.DataFrame()
        return pd.concat(dfs, ignore_index=True)


# Singleton instance
_lake_manager_instance: Optional[DataLakeManager] = None


def get_lakehouse_manager() -> DataLakeManager:
    global _lake_manager_instance
    if _lake_manager_instance is None:
        _lake_manager_instance = DataLakeManager()
    return _lake_manager_instance
