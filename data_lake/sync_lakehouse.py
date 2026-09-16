#!/usr/bin/env python3
"""
Data Lakehouse MinIO / S3 Remote Sync CLI Tool
==============================================
Công cụ dòng lệnh hỗ trợ đồng bộ kho dữ liệu Data Lakehouse giữa máy cá nhân và máy chủ MinIO / S3:
1. 'push'   : Đẩy toàn bộ các phân vùng Parquet và catalog.db từ local lên MinIO.
2. 'pull'   : Tải các phân vùng Parquet của các thành viên khác từ MinIO về máy để train model.
3. 'status' : Kiểm tra kết nối tới MinIO Server và dung lượng bucket.

Cú pháp:
    python data_lake/sync_lakehouse.py --action status
    python data_lake/sync_lakehouse.py --action push
    python data_lake/sync_lakehouse.py --action pull
"""

import os
import sys
import argparse

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# An toàn mã hóa console Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from data_lake.remote_storage import MinIOStorageManager, get_minio_storage_manager


def main():
    parser = argparse.ArgumentParser(
        description="Data Lakehouse MinIO / S3 Remote Sync CLI Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--action",
        choices=["push", "pull", "status"],
        default="status",
        help="Hành động đồng bộ: 'push' (đẩy lên), 'pull' (tải về), 'status' (kiểm tra kết nối)"
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="MinIO Endpoint (ví dụ: 192.168.1.50:9000 hoặc s3.amazonaws.com)"
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="Tên bucket trên MinIO / S3 (mặc định: edge-lakehouse hoặc từ file .env)"
    )
    parser.add_argument(
        "--access-key",
        default=None,
        help="MinIO Access Key"
    )
    parser.add_argument(
        "--secret-key",
        default=None,
        help="MinIO Secret Key"
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Bật HTTPS (mặc định: HTTP thông thường cho local MinIO)"
    )

    args = parser.parse_args()

    print("=" * 68)
    print("   DATA LAKEHOUSE MINIO / S3 REMOTE STORAGE SYNC TOOL")
    print("=" * 68)

    mgr = MinIOStorageManager(
        endpoint=args.endpoint,
        access_key=args.access_key,
        secret_key=args.secret_key,
        bucket_name=args.bucket,
        secure=args.secure if args.secure else None
    )

    print(f" * Endpoint    : {mgr.endpoint}")
    print(f" * Bucket Name : {mgr.bucket_name}")
    print(f" * SSL/TLS     : {'BẬT (HTTPS)' if mgr.secure else 'TẮT (HTTP)'}")
    print(f" * Local Dir   : {mgr.base_lake_dir}")
    print("-" * 68)

    available, msg = mgr.is_configured_and_available()
    if not available:
        print(f"\n[!] CẢNH BÁO KẾT NỐI MINIO:")
        print(f"    {msg}\n")
        print("  -> Hướng dẫn khởi tạo MinIO cho Team:")
        print("     1. Khởi động MinIO Server (Docker hoặc Binary):")
        print("        docker run -d -p 9000:9000 -p 9001:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data --console-address ':9001'")
        print("     2. Cấu hình file .env tại thư mục gốc dự án:")
        print("        MINIO_ENDPOINT=localhost:9000")
        print("        MINIO_ACCESS_KEY=minioadmin")
        print("        MINIO_SECRET_KEY=minioadmin")
        print("        MINIO_BUCKET=edge-lakehouse")
        print("=" * 68 + "\n")
        sys.exit(1)

    print(f"[OK] {msg}\n")

    if args.action == "status":
        print("-> Trạng thái: MinIO Server sẵn sàng hoạt động.")
        try:
            objects = list(mgr.client.list_objects(mgr.bucket_name, prefix="data_lake/", recursive=True))
            total_size_kb = sum(obj.size for obj in objects) / 1024.0
            print(f"-> Tổng số tệp trên Bucket '{mgr.bucket_name}': {len(objects)} tệp ({total_size_kb:.2f} KB)")
            for obj in objects[:8]:
                print(f"   - {obj.object_name} ({obj.size / 1024.0:.1f} KB)")
            if len(objects) > 8:
                print(f"   ... và {len(objects) - 8} tệp khác.")
        except Exception as e:
            print(f"-> Không thể liệt kê danh sách tệp: {e}")

    elif args.action == "push":
        print("-> Đang đẩy toàn bộ các tệp Parquet và catalog.db từ máy cục bộ lên MinIO...")
        res = mgr.sync_lake_to_remote()
        if res["success"]:
            print(f"[THÀNH CÔNG] {res['message']}")
            for f in res.get("files", [])[:10]:
                print(f"   + Đã upload: {f}")
        else:
            print(f"[THẤT BẠI] {res['message']}")

    elif args.action == "pull":
        print("-> Đang kéo các tệp dữ liệu từ MinIO bucket về máy cục bộ...")
        res = mgr.sync_remote_to_lake()
        if res["success"]:
            print(f"[THÀNH CÔNG] {res['message']}")
            for f in res.get("files", [])[:10]:
                print(f"   + Đã download: {f}")
        else:
            print(f"[THẤT BẠI] {res['message']}")

    print("=" * 68 + "\n")


if __name__ == "__main__":
    main()
