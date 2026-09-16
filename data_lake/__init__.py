"""
Data Lakehouse Package for Edge AI Telemetry
=============================================
Cung cấp công cụ lưu trữ dữ liệu mạng hàng ngày theo chuẩn Apache Parquet & SQLite Catalog:
- DataLakeManager: Quản lý phiên ghi, phân vùng dữ liệu theo ngày, nạp dữ liệu huấn luyện.
- DataLakeCollector: Tiến trình thu nhận dữ liệu thời gian thực từ bus MQTT.
"""

from .lakehouse import DataLakeManager, get_lakehouse_manager
from .collector import DataLakeCollector, start_lake_collector

__all__ = [
    "DataLakeManager",
    "get_lakehouse_manager",
    "DataLakeCollector",
    "start_lake_collector"
]
