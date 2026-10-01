#!/usr/bin/env python3
"""
Cloudflare R2 / S3 Remote Object Storage Manager for Data Lakehouse
===================================================================
Cung cấp khả năng đồng bộ phân vùng Parquet và SQLite Catalog lên kho lưu trữ đối tượng
Cloudflare R2 (hoặc AWS S3 / MinIO) để cả nhóm nghiên cứu có thể chia sẻ và cập nhật tập dữ liệu
ở bất kỳ đâu qua Internet mà không bị giới hạn mạng cục bộ.

Ưu điểm của Cloudflare R2:
- 10 GB lưu trữ miễn phí vĩnh viễn.
- 0đ phí Egress (Băng thông tải về hoàn toàn miễn phí cho cả nhóm).
- Tương thích 100% chuẩn S3 API.
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


class RemoteStorageManager:
    """
    Quản lý lưu trữ đối tượng Cloudflare R2 / S3 / MinIO cho Data Lakehouse.
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
        # Ưu tiên biến môi trường Cloudflare R2, sau đó fallback MinIO/S3
        raw_endpoint = (
            endpoint
            or os.getenv("R2_ENDPOINT")
            or os.getenv("S3_ENDPOINT")
            or os.getenv("MINIO_ENDPOINT")
            or "127.0.0.1:9000"
        )
        # Chuẩn hóa endpoint: loại bỏ tiền tố https:// hoặc http:// nếu có
        self.secure = True
        if raw_endpoint.startswith("https://"):
            raw_endpoint = raw_endpoint.replace("https://", "")
            self.secure = True
        elif raw_endpoint.startswith("http://"):
            raw_endpoint = raw_endpoint.replace("http://", "")
            self.secure = False
        self.endpoint = raw_endpoint.rstrip("/")

        self.access_key = (
            access_key
            or os.getenv("R2_ACCESS_KEY_ID")
            or os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("MINIO_ACCESS_KEY")
            or "minioadmin"
        )
        self.secret_key = (
            secret_key
            or os.getenv("R2_SECRET_ACCESS_KEY")
            or os.getenv("AWS_SECRET_ACCESS_KEY")
            or os.getenv("MINIO_SECRET_KEY")
            or "minioadmin"
        )
        self.bucket_name = (
            bucket_name
            or os.getenv("R2_BUCKET")
            or os.getenv("S3_BUCKET")
            or os.getenv("MINIO_BUCKET")
            or "edge-lakehouse"
        )

        if secure is not None:
            self.secure = secure
        else:
            sec_env = (os.getenv("R2_SECURE") or os.getenv("MINIO_SECURE") or "true").lower()
            if self.endpoint in ("127.0.0.1:9000", "localhost:9000"):
                self.secure = sec_env in ("true", "1", "yes") and "R2_SECURE" in os.environ
            else:
                self.secure = sec_env in ("true", "1", "yes")

        self.base_lake_dir = base_lake_dir or os.path.join(ROOT_DIR, "data_lake")
        self.raw_dir = os.path.join(self.base_lake_dir, "raw")
        self.catalog_db_path = os.path.join(self.base_lake_dir, "catalog.db")

        self.client = None
        self._provider_name = "Cloudflare R2" if "r2.cloudflarestorage.com" in self.endpoint else "S3/MinIO"
        self._init_client()

    def _init_client(self) -> bool:
        """Khởi tạo kết nối đến S3/MinIO client."""
        try:
            from minio import Minio
            # Với Cloudflare R2, region thường là 'auto'
            region = "auto" if "r2.cloudflarestorage.com" in self.endpoint else None
            self.client = Minio(
                endpoint=self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
                region=region
            )
            return True
        except ImportError:
            self.client = None
            return False
        except Exception:
            self.client = None
            return False

    def is_configured_and_available(self) -> Tuple[bool, str]:
        """Kiểm tra xem Storage đã sẵn sàng kết nối và truy cập được bucket chưa."""
        if self.client is None:
            return False, "Thư viện 'minio' chưa được cài đặt (cần 'pip install minio')."

        # Kiểm tra nếu chưa điền key
        if self.access_key in ("", "minioadmin") and "r2.cloudflarestorage.com" in self.endpoint:
            return False, "Chưa cấu hình R2_ACCESS_KEY_ID hoặc R2_SECRET_ACCESS_KEY trong file .env."

        try:
            found = self.client.bucket_exists(self.bucket_name)
            if not found:
                try:
                    self.client.make_bucket(self.bucket_name)
                    return True, f"Bucket '{self.bucket_name}' vừa được khởi tạo thành công trên {self._provider_name}."
                except Exception as eb:
                    return False, f"Không thể tạo bucket '{self.bucket_name}' trên {self._provider_name} ({eb})."
            return True, f"Kết nối {self._provider_name} thành công tới {self.endpoint}, bucket: '{self.bucket_name}'."
        except Exception as e:
            return False, f"Không thể kết nối {self._provider_name} tại {self.endpoint}: {e}"

    def upload_file(self, local_path: str, remote_object_name: str) -> bool:
        """Tải một file cục bộ lên Storage bucket."""
        available, _ = self.is_configured_and_available()
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
            print(f"[{self._provider_name}] Lỗi upload {local_path} -> {remote_object_name}: {e}")
            return False

    def download_file(self, remote_object_name: str, local_path: str) -> bool:
        """Tải một đối tượng từ Storage về máy cục bộ."""
        available, _ = self.is_configured_and_available()
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
            print(f"[{self._provider_name}] Lỗi download {remote_object_name} -> {local_path}: {e}")
            return False

    def sync_lake_to_remote(self) -> Dict[str, Any]:
        """
        Đồng bộ toàn bộ dữ liệu Data Lakehouse cục bộ lên Cloudflare R2 / S3:
        - Quét toàn bộ thư mục data_lake/raw/ tìm các file .parquet
        - Quét và tải lên catalog.db
        """
        available, msg = self.is_configured_and_available()
        if not available:
            return {"success": False, "message": msg, "uploaded_count": 0, "provider": self._provider_name}

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
                        print(f"[{self._provider_name}] Lỗi đẩy file {rel_path}: {e}")

        # 2. Quét SQLite catalog.db
        if os.path.exists(self.catalog_db_path):
            remote_catalog = "data_lake/catalog.db"
            try:
                self.client.fput_object(self.bucket_name, remote_catalog, self.catalog_db_path)
                uploaded_files.append(remote_catalog)
            except Exception as e:
                print(f"[{self._provider_name}] Lỗi đẩy catalog.db: {e}")

        return {
            "success": True,
            "message": f"Đã đồng bộ {len(uploaded_files)} tệp lên {self._provider_name} bucket '{self.bucket_name}'.",
            "uploaded_count": len(uploaded_files),
            "files": uploaded_files,
            "provider": self._provider_name
        }

    def sync_remote_to_lake(self) -> Dict[str, Any]:
        """
        Đồng bộ dữ liệu từ Cloudflare R2 / S3 bucket về Data Lakehouse cục bộ của thành viên:
        - Tải các file Parquet còn thiếu về data_lake/raw/
        - Tải catalog.db từ remote nếu local chưa có hoặc cập nhật.
        """
        available, msg = self.is_configured_and_available()
        if not available:
            return {"success": False, "message": msg, "downloaded_count": 0, "provider": self._provider_name}

        downloaded_files = []
        try:
            objects = self.client.list_objects(self.bucket_name, prefix="data_lake/", recursive=True)
            for obj in objects:
                remote_key = obj.object_name
                rel_path = remote_key.replace("data_lake/", "", 1)
                local_path = os.path.join(self.base_lake_dir, rel_path)

                if os.path.exists(local_path):
                    local_size = os.path.getsize(local_path)
                    if local_size == obj.size:
                        continue

                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                self.client.fget_object(self.bucket_name, remote_key, local_path)
                downloaded_files.append(rel_path)

            return {
                "success": True,
                "message": f"Đã tải về {len(downloaded_files)} tệp mới từ {self._provider_name} bucket '{self.bucket_name}'.",
                "downloaded_count": len(downloaded_files),
                "files": downloaded_files,
                "provider": self._provider_name
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Lỗi trong quá trình kéo dữ liệu từ {self._provider_name}: {e}",
                "downloaded_count": 0,
                "provider": self._provider_name
            }


# Tương thích ngược alias
MinIOStorageManager = RemoteStorageManager

# Singleton instance
_storage_manager_instance: Optional[RemoteStorageManager] = None


def get_remote_storage_manager() -> RemoteStorageManager:
    global _storage_manager_instance
    if _storage_manager_instance is None:
        _storage_manager_instance = RemoteStorageManager()
    return _storage_manager_instance


def get_minio_storage_manager() -> RemoteStorageManager:
    return get_remote_storage_manager()
