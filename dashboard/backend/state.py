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
        self.alert_packet_ids: Dict[str, bool] = {}
        self.total_packets_inspected: int = 0
        self.total_threats_detected: int = 0
        self.current_anomaly_score: float | None = None
        self.latest_traffic_window = None
        self.capture_totals: Dict[tuple, int] = {}
        self.prediction_broadcast_times: Dict[str, float] = {}
        self.current_threat_level: str = "UNKNOWN"
        self.anomaly_threshold: float = 0.55
        self.broker_connected: bool = False

        # Trạng thái của bộ bắn gói tin mạng thật (Attack Traffic Generator)
        self.attack_status: str = "IDLE"          # IDLE hoặc ATTACKING
        self.attack_scenario: str = "Normal"      # Normal, Port_Scanning, DDoS_UDP, DDoS_TCP, Vulnerability_scanner, Uploading
        self.attack_target_ip: str = "127.0.0.1"
        self.attack_auto_cycle: bool = False
        self.attack_details: Dict[str, Any] = {}
        self.experiment_status: Dict[str, Any] = {"phase": "IDLE"}

        # Danh sách các mạng WiFi phát hiện được (ESP-32 Sniffer & Host Probe)
        self.detected_wifi_networks: List[dict] = []

        # Trạng thái Live Digital Twin và các sự kiện phòng thủ RL
        self.digital_twin_state: Dict[str, Any] = {}
        self.defense_actions: List[dict] = []

        # Thông tin các mô hình Edge AI & Host ML đang chạy
        self.host_classifier: str = "Host ML"
        self.host_anomaly_detector: str = "Anomaly Detector"
        self.edge_model: str = "Edge TinyML"
        self.features_count: int = 10
        self.traffic_mode: str = "encrypted"
        self.dataset_name: str = "USTC-TFC2016"
        self.profile: str = "esp32-l234-packet-v1"
        self.model_labels: List[str] = [
            "Normal", "Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Nsis-ay", "Shifu", "Tinba", "Virut", "Zeus"
        ]
        self.features_list: List[str] = [
            "arp.opcode", "arp.hw.size", "icmp.checksum", "tcp.ack_raw", "tcp.checksum",
            "tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.len", "tcp.srcport"
        ]
        self._load_active_models_metadata()

    def _load_active_models_metadata(self):
        try:
            import os, json
            root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            m_dir = os.getenv("MODELS_DIR")
            if not m_dir or not os.path.exists(m_dir) or not os.path.exists(os.path.join(m_dir, "model_metadata.json")):
                m_base = os.path.join(root, "ml_engine", "models")
                if os.path.exists(m_base):
                    candidates = []
                    for entry in os.listdir(m_base):
                        p1 = os.path.join(m_base, entry)
                        if os.path.isdir(p1):
                            if os.path.exists(os.path.join(p1, "model_metadata.json")):
                                candidates.append(p1)
                            for sub in os.listdir(p1):
                                p2 = os.path.join(p1, sub)
                                if os.path.isdir(p2) and os.path.exists(os.path.join(p2, "model_metadata.json")):
                                    candidates.append(p2)
                    if candidates:
                        pref_mode = os.getenv("AERO_TRAFFIC_MODE")
                        if pref_mode:
                            matched = [c for c in candidates if pref_mode in c]
                            if matched:
                                candidates = matched
                        m_dir = sorted(candidates, key=os.path.getmtime, reverse=True)[0]
            if m_dir and os.path.exists(os.path.join(m_dir, "model_metadata.json")):
                with open(os.path.join(m_dir, "model_metadata.json"), "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self.host_classifier = meta.get("classifier_type", self.host_classifier)
                self.host_anomaly_detector = meta.get("anomaly_detector_type", self.host_anomaly_detector)
                self.features_count = meta.get("features_count", self.features_count)
                self.traffic_mode = meta.get("traffic_mode", os.getenv("AERO_TRAFFIC_MODE", "encrypted" if self.features_count == 10 else "decrypted"))
                self.dataset_name = meta.get("dataset_quality", {}).get("dataset_name", meta.get("data_source", "USTC-TFC2016" if self.traffic_mode == "encrypted" else "Edge-IIoTset"))
                self.profile = meta.get("profile", meta.get("feature_semantics", "esp32-l234-packet-v1" if self.traffic_mode == "encrypted" else "edge-iiotset-56"))
                if meta.get("labels"):
                    self.model_labels = meta["labels"]
                if meta.get("features"):
                    self.features_list = meta["features"]
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
        if "traffic_mode" in data_point:
            self.traffic_mode = data_point["traffic_mode"]
        if "dataset_name" in data_point:
            self.dataset_name = data_point["dataset_name"]
        if "profile" in data_point:
            self.profile = data_point["profile"]

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
            "traffic_mode": self.traffic_mode,
            "dataset_name": self.dataset_name,
            "profile": self.profile,
            "experiment_status": self.experiment_status,
            "connected_nodes": list(self.connected_nodes.values()),
            "history": self.telemetry_history[-30:],
            "latest_traffic_window": self.latest_traffic_window,
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
                "features_count": self.features_count,
                "traffic_mode": self.traffic_mode,
                "dataset_name": self.dataset_name,
                "profile": self.profile,
                "labels": self.model_labels,
                "features": self.features_list
            },
            "attack_status": {
                "status": self.attack_status,
                "scenario": self.attack_scenario,
                "target_ip": self.attack_target_ip,
                "auto_cycle": self.attack_auto_cycle,
                **self.attack_details
            }
        }


# Singleton system state instance
state = SystemState()
