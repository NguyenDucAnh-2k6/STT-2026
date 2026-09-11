"""
Dashboard Backend In-Memory System State
========================================
Quản lý trạng thái luồng telemetry, cảnh báo, danh sách node kết nối trong bộ nhớ.
"""

from typing import List, Dict, Any


class SystemState:
    """Quản lý trạng thái runtime in-memory của hệ thống giám sát."""

    def __init__(self):
        self.connected_nodes: Dict[str, dict] = {}
        self.telemetry_history: List[dict] = []
        self.alerts_history: List[dict] = []
        self.total_packets_inspected: int = 0
        self.total_threats_detected: int = 0
        self.current_anomaly_score: float = 0.0
        self.current_threat_level: str = "NORMAL"
        self.anomaly_threshold: float = 0.55
        self.broker_connected: bool = False

    def add_telemetry(self, data_point: dict):
        self.telemetry_history.append(data_point)
        if len(self.telemetry_history) > 200:
            self.telemetry_history.pop(0)

    def add_alert(self, alert_entry: dict):
        self.total_threats_detected += 1
        self.alerts_history.append(alert_entry)
        if len(self.alerts_history) > 100:
            self.alerts_history.pop(0)

    def get_initial_payload(self) -> dict:
        return {
            "type": "INITIAL_STATE",
            "connected_nodes": list(self.connected_nodes.values()),
            "history": self.telemetry_history[-30:],
            "alerts": self.alerts_history[-20:],
            "total_packets": self.total_packets_inspected,
            "total_threats": self.total_threats_detected,
            "anomaly_threshold": self.anomaly_threshold,
            "broker_connected": self.broker_connected
        }


# Singleton system state instance
state = SystemState()
