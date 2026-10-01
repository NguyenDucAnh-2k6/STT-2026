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

        # Trạng thái của bộ bắn gói tin mạng thật (Attack Traffic Generator)
        self.attack_status: str = "IDLE"          # IDLE hoặc ATTACKING
        self.attack_scenario: str = "Normal"      # Normal, Port_Scanning, DDoS_UDP, DDoS_TCP, Vulnerability_scanner, Uploading
        self.attack_target_ip: str = "127.0.0.1"
        self.attack_auto_cycle: bool = False

        # Danh sách các mạng WiFi phát hiện được (ESP-32 Sniffer & Host Probe)
        self.detected_wifi_networks: List[dict] = []

        # Thông tin các mô hình Edge AI & Host ML đang chạy
        self.host_classifier: str = "Host ML"
        self.host_anomaly_detector: str = "Anomaly Detector"
        self.edge_model: str = "Edge TinyML"
        self.features_count: int = 56
        self._load_active_models_metadata()

    def _load_active_models_metadata(self):
        try:
            import os, json
            root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            m_dir = os.getenv("MODELS_DIR")
            if not m_dir or not os.path.exists(m_dir):
                m_base = os.path.join(root, "ml_engine", "models")
                if os.path.exists(m_base):
                    subdirs = [os.path.join(m_base, d) for d in os.listdir(m_base) if os.path.isdir(os.path.join(m_base, d))]
                    if subdirs:
                        m_dir = sorted(subdirs, key=os.path.getmtime, reverse=True)[0]
            if m_dir and os.path.exists(os.path.join(m_dir, "model_metadata.json")):
                with open(os.path.join(m_dir, "model_metadata.json"), "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self.host_classifier = meta.get("classifier_type", self.host_classifier)
                self.host_anomaly_detector = meta.get("anomaly_detector_type", self.host_anomaly_detector)
                self.features_count = meta.get("features_count", self.features_count)
                is_dl = self.host_classifier in ("pytorch_deep", "dnn") or self.host_anomaly_detector in ("deep_autoencoder", "autoencoder")
                self.edge_model = "EdgeDeepNet + AutoencoderNet (TFLite)" if is_dl else f"{self.host_classifier} + {self.host_anomaly_detector} (TinyML C)"
        except Exception:
            pass

    def update_wifi_networks(self, networks: list):
        if not networks:
            return
        existing_map = {n.get("ssid"): n for n in self.detected_wifi_networks if n.get("ssid")}
        for net in networks:
            ssid = net.get("ssid")
            if ssid:
                existing_map[ssid] = net
        self.detected_wifi_networks = list(existing_map.values())[-20:]

    def add_telemetry(self, data_point: dict):
        if "host_classifier" in data_point and data_point["host_classifier"] != "Host Classifier":
            self.host_classifier = data_point["host_classifier"]
        if "host_anomaly_detector" in data_point and data_point["host_anomaly_detector"] != "Anomaly Detector":
            self.host_anomaly_detector = data_point["host_anomaly_detector"]
        if "edge_model" in data_point and data_point["edge_model"] != "Edge TinyML":
            self.edge_model = data_point["edge_model"]
        if "host_features_count" in data_point:
            self.features_count = data_point["host_features_count"]

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
            "broker_connected": self.broker_connected,
            "detected_wifi_networks": self.detected_wifi_networks,
            "system_models": {
                "classifier": self.host_classifier,
                "anomaly_detector": self.host_anomaly_detector,
                "edge_model": self.edge_model,
                "features_count": self.features_count
            },
            "attack_status": {
                "status": self.attack_status,
                "scenario": self.attack_scenario,
                "target_ip": self.attack_target_ip,
                "auto_cycle": self.attack_auto_cycle
            }
        }


# Singleton system state instance
state = SystemState()
