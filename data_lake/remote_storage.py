#!/usr/bin/env python3
"""
MinIO / S3 Remote Object Storage Manager for Data Lakehouse
===========================================================
Cung cấp khả năng đồng bộ phân vùng Parquet và SQLite Catalog lên kho lưu trữ đối tượng
(MinIO / AWS S3 / Cloudflare R2) để cả nhóm nghiên cứu có thể chia sẻ và cập nhật tập dữ liệu.

Tính năng:
1. Đồng bộ 2 chiều:
   - Push: Đẩy các file Parquet mới và file catalog.db lên MinIO bucket.
   - Pull: Tải các phân vùng Parquet mới từ nhóm về thư mục data_lake/raw/ local.
2. Tự động kiểm tra và tạo Bucket nếu chưa tồn tại.
3. Hỗ trợ Local-first & Graceful Degradation: Nếu không có kết nối MinIO hoặc chưa cài thư viện,
   hệ thống vẫn ghi dữ liệu local bình thường và cảnh báo nhẹ, không gây crash.
"""

import os
import sys
import glob
import sqlite3
from typing import Dict, Any, List, Optional, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Nạp cấu hình từ .env nếu có
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT_DIR, ".env"))
except ImportError:
    pass


class MinIOStorageManager:
    """
    Quản lý lưu trữ đối tượng MinIO/S3 cho Data Lakehouse.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        bucket_name: Optional[str] = None,
        secure: Optional[bool] = None,
        base_lake_dir: Optional[str] = None
    ):
        self.endpoint = endpoint or os.getenv("MINIO_ENDPOINT", "127.0.0.1:9000")
        self.access_key = access_key or os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = secret_key or os.getenv("MINIO_SECRET_KEY", "minioadmin")
        self.bucket_name = bucket_name or os.getenv("MINIO_BUCKET", "edge-lakehouse")

        sec_env = os.getenv("MINIO_SECURE", "false").lower()
        self.secure = secure if secure is not None else (sec_env in ("true", "1", "yes"))

        self.base_lake_dir = base_lake_dir or os.path.join(ROOT_DIR, "data_lake")
        self.raw_dir = os.path.join(self.base_lake_dir, "raw")
        self.catalog_db_path = os.path.join(self.base_lake_dir, "catalog.db")

        self.client = None
        self._init_client()

    def _init_client(self) -> bool:
        """Khởi tạo kết nối đến MinIO client."""
        try:
            from minio import Minio
            self.client = Minio(
                endpoint=self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure
            )
            return True
        except ImportError:
            self.client = None
            return False
        except Exception as e:
            self.client = None
            return False

    def is_configured_and_available(self) -> Tuple[bool, str]:
        """Kiểm tra xem MinIO đã sẵn sàng kết nối và truy cập được bucket chưa."""
        if self.client is None:
            return False, "Thư viện 'minio' chưa được cài đặt (cần 'pip install minio')."

        try:
            # Thử ping MinIO server bằng cách kiểm tra bucket
            found = self.client.bucket_exists(self.bucket_name)
            if not found:
                try:
                    self.client.make_bucket(self.bucket_name)
                    return True, f"Bucket '{self.bucket_name}' vừa được tự động khởi tạo thành công trên MinIO."
                except Exception as eb:
                    return False, f"Không thể tạo bucket '{self.bucket_name}' trên MinIO ({eb})."
            return True, f"Kết nối MinIO thành công tới {self.endpoint}, bucket: '{self.bucket_name}'."
        except Exception as e:
            return False, f"Không thể kết nối MinIO tại {self.endpoint}: {e}"

    def upload_file(self, local_path: str, remote_object_name: str) -> bool:
        """Tải một file cục bộ lên MinIO bucket."""
        available, msg = self.is_configured_and_available()
        if not available:
            return False

        try:
            self.client.fput_object(
                bucket_name=self.bucket_name,
                object_name=remote_object_name,
                file_path=local_path
            )
            return True
        except Exception as e:
            print(f"[MinIO] Lỗi upload {local_path} -> {remote_object_name}: {e}")
            return False

    def download_file(self, remote_object_name: str, local_path: str) -> bool:
        """Tải một đối tượng từ MinIO về máy cục bộ."""
        available, msg = self.is_configured_and_available()
        if not available:
            return False

        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            self.client.fget_object(
                bucket_name=self.bucket_name,
                object_name=remote_object_name,
                file_path=local_path
            )
            return True
        except Exception as e:
            print(f"[MinIO] Lỗi download {remote_object_name} -> {local_path}: {e}")
            return False

    def sync_lake_to_remote(self) -> Dict[str, Any]:
        """
        Đồng bộ toàn bộ dữ liệu Data Lakehouse cục bộ lên MinIO:
        - Quét toàn bộ thư mục data_lake/raw/ tìm các file .parquet
        - Quét và tải lên catalog.db
        """
        available, msg = self.is_configured_and_available()
        if not available:
            return {"success": False, "message": msg, "uploaded_count": 0}

        uploaded_files = []
        # 1. Quét parquet files
        for root, _, files in os.walk(self.raw_dir):
            for file in files:
                if file.endswith(".parquet"):
                    local_path = os.path.join(root, file)
                    rel_path = os.path.relpath(local_path, self.base_lake_dir).replace("\\", "/")
                    remote_key = f"data_lake/{rel_path}"
                    try:
                        self.client.fput_object(self.bucket_name, remote_key, local_path)
                        uploaded_files.append(remote_key)
                    except Exception as e:
                        print(f"[MinIO] Loi day file {rel_path}: {e}")

        # 2. Quét SQLite catalog.db
        if os.path.exists(self.catalog_db_path):
            remote_catalog = "data_lake/catalog.db"
            try:
                self.client.fput_object(self.bucket_name, remote_catalog, self.catalog_db_path)
                uploaded_files.append(remote_catalog)
            except Exception as e:
                print(f"[MinIO] Loi day catalog.db: {e}")

        return {
            "success": True,
            "message": f"Đã đồng bộ {len(uploaded_files)} tệp lên MinIO bucket '{self.bucket_name}'.",
            "uploaded_count": len(uploaded_files),
            "files": uploaded_files
        }

    def sync_remote_to_lake(self) -> Dict[str, Any]:
        """
        Đồng bộ dữ liệu từ MinIO bucket về Data Lakehouse cục bộ của thành viên:
        - Tải các file Parquet còn thiếu về data_lake/raw/
        - Tải catalog.db từ remote nếu local chưa có hoặc merge danh mục.
        """
        available, msg = self.is_configured_and_available()
        if not available:
            return {"success": False, "message": msg, "downloaded_count": 0}

        downloaded_files = []
        try:
            objects = self.client.list_objects(self.bucket_name, prefix="data_lake/", recursive=True)
            for obj in objects:
                remote_key = obj.object_name
                # Lấy đường dẫn relative bên trong data_lake
                rel_path = remote_key.replace("data_lake/", "", 1)
                local_path = os.path.join(self.base_lake_dir, rel_path)

                if os.path.exists(local_path):
                    # Nếu file đã tồn tại và kích thước tương đương, bỏ qua
                    local_size = os.path.getsize(local_path)
                    if local_size == obj.size:
                        continue

                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                self.client.fget_object(self.bucket_name, remote_key, local_path)
                downloaded_files.append(rel_path)

            return {
                "success": True,
                "message": f"Đã tải về {len(downloaded_files)} tệp mới từ MinIO bucket '{self.bucket_name}'.",
                "downloaded_count": len(downloaded_files),
                "files": downloaded_files
            }
        except Exception as e:
            return {"success": False, "message": f"Lỗi trong quá trình kéo dữ liệu từ MinIO: {e}", "downloaded_count": 0}


# Singleton instance
_minio_manager_instance: Optional[MinIOStorageManager] = None


def get_minio_storage_manager() -> MinIOStorageManager:
    global _minio_manager_instance
    if _minio_manager_instance is None:
        _minio_manager_instance = MinIOStorageManager()
    return _minio_manager_instance
