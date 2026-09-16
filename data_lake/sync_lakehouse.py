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

from data_lake.remote_storage import RemoteStorageManager, get_remote_storage_manager


def main():
    parser = argparse.ArgumentParser(
        description="Data Lakehouse Cloudflare R2 / S3 / MinIO Remote Sync CLI Tool",
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
        help="Remote Endpoint (ví dụ: <account_id>.r2.cloudflarestorage.com hoặc 192.168.1.50:9000)"
    )
    parser.add_argument(
        "--bucket",
        default=None,
        help="Tên bucket (mặc định: edge-lakehouse hoặc từ file .env)"
    )
    parser.add_argument(
        "--access-key",
        default=None,
        help="Access Key ID (R2 / S3 / MinIO)"
    )
    parser.add_argument(
        "--secret-key",
        default=None,
        help="Secret Access Key"
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Bật HTTPS (mặc định: tự động bật cho Cloudflare R2)"
    )

    args = parser.parse_args()

    mgr = RemoteStorageManager(
        endpoint=args.endpoint,
        access_key=args.access_key,
        secret_key=args.secret_key,
        bucket_name=args.bucket,
        secure=args.secure if args.secure else None
    )

    print("=" * 68)
    print(f"   DATA LAKEHOUSE REMOTE STORAGE SYNC TOOL ({mgr._provider_name.upper()})")
    print("=" * 68)
    print(f" * Provider    : {mgr._provider_name}")
    print(f" * Endpoint    : {mgr.endpoint}")
    print(f" * Bucket Name : {mgr.bucket_name}")
    print(f" * SSL/TLS     : {'BẬT (HTTPS)' if mgr.secure else 'TẮT (HTTP)'}")
    print(f" * Local Dir   : {mgr.base_lake_dir}")
    print("-" * 68)

    available, msg = mgr.is_configured_and_available()
    if not available:
        print(f"\n[!] CẢNH BÁO KẾT NỐI {mgr._provider_name.upper()}:")
        print(f"    {msg}\n")
        print("  -> Hướng dẫn cấu hình Cloudflare R2 cho Team (Khuyến nghị 0đ phí Egress):")
        print("     1. Tạo bucket 'edge-lakehouse' tại Cloudflare Dashboard: https://dash.cloudflare.com/ -> R2")
        print("     2. Tạo API Token: R2 -> Manage R2 API Tokens -> Create API Token (Quyền: Object Read & Write)")
        print("     3. Cấu hình file .env tại thư mục gốc dự án:")
        print("        R2_ENDPOINT=<account_id>.r2.cloudflarestorage.com")
        print("        R2_ACCESS_KEY_ID=<your_r2_access_key_id>")
        print("        R2_SECRET_ACCESS_KEY=<your_r2_secret_access_key>")
        print("        R2_BUCKET=edge-lakehouse")
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
