"""
Closed-Loop Cyber Defense Service (MQTT-Driven)
================================================
Dịch vụ vận hành khép kín toàn diện theo kiến trúc Triển khai Digital Twin:
    Real Traffic / Telemetry -> Edge ML Detection -> Digital Twin -> RL Policy ->
    Sandbox Dry-Run Simulation -> Safety Controller -> Network Controller ->
    Real Network / Host Firewall -> Feedback Loop (MQTT: edge/defense/action)
"""

import json
import time
import os
import threading
from typing import Dict, Any, Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

import numpy as np

from digital_twin.rl_environment import (
    CyberDefenseRLEnv,
    DefenseAction,
    ThreatType,
    ACTION_NAMES
)
from digital_twin.rl_agent import CyberDefenseRLAgent
from digital_twin.safety_controller import SafetyController, SafetyDecision
from digital_twin.network_controller import NetworkController
from digital_twin.engine import NetworkDigitalTwin


class ClosedLoopDefenseService:
    """
    Dịch vụ điều phối tự động vòng kín (Closed-Loop Autonomous Defense).
    """

    def __init__(
        self,
        broker_host: str = "127.0.0.1",
        broker_port: int = 1883,
        policy_path: str = "digital_twin/models/rl_defense_policy.json",
        enforce_real_firewall: bool = False
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.policy_path = policy_path
        self.enforce_real_firewall = enforce_real_firewall

        # 1. Khởi tạo Digital Twin mô phỏng
        self.twin = NetworkDigitalTwin(name="ClosedLoop-Live-Twin")

        # 2. Khởi tạo RL Agent
        self.agent = CyberDefenseRLAgent()
        if os.path.isfile(self.policy_path):
            self.agent.load_policy(self.policy_path)
            print(f"[RL Defense] Đã nạp thành công policy huấn luyện từ: {self.policy_path}")
        else:
            print(f"[RL Defense] Chưa có policy tại {self.policy_path}. Sử dụng heuristic baseline policy.")

        # 3. Khởi tạo Safety Controller & Network Controller
        self.safety_controller = SafetyController()
        self.network_controller = NetworkController(dry_run=not self.enforce_real_firewall)

        self.running = False
        self.mqtt_client = None

    def start(self):
        """Khởi động dịch vụ lắng nghe MQTT."""
        if mqtt is None:
            print("[RL Defense Error] paho-mqtt chưa được cài đặt!")
            return

        self.running = True
        self.mqtt_client = mqtt.Client(client_id=f"AERO-RL-Defense-{int(time.time())}")
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_message = self._on_message

        try:
            self.mqtt_client.connect(self.broker_host, self.broker_port, keepalive=60)
            self.mqtt_client.loop_start()
            print(f"[RL Defense] Dịch vụ Closed-Loop Defense đã kết nối MQTT tại {self.broker_host}:{self.broker_port}")
            print(f"             Chế độ thực thi: {'MẠNG THẬT (Active Firewall)' if self.enforce_real_firewall else 'DRY-RUN AN TOÀN (Sandbox Simulation)'}")
        except Exception as e:
            print(f"[RL Defense Error] Không thể kết nối MQTT Broker: {e}")

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            # Lắng nghe kết quả suy luận từ ML Engine
            client.subscribe("edge/telemetry/prediction")
            client.subscribe("edge/telemetry/traffic")
            client.subscribe("edge/telemetry/window")
            print("  -> Đã đăng ký lắng nghe topics: edge/telemetry/prediction, edge/telemetry/traffic")

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        if not isinstance(payload, dict):
            return
        if msg.topic == "edge/telemetry/traffic" and payload.get("record_kind") == "packet":
            return
        if msg.topic in ("edge/telemetry/traffic", "edge/telemetry/window"):
            # Hiệu chuẩn Digital Twin theo dữ liệu mạng thật
            self.twin.sync_from_real_telemetry(payload)

        elif msg.topic == "edge/telemetry/prediction":
            # Nhận kết quả phát hiện đe dọa -> Kích hoạt quy trình ra quyết định RL
            self._process_threat_detection(payload)

    def _process_threat_detection(self, prediction_data: Dict[str, Any]):
        """Xử lý phát hiện mối đe dọa và ra quyết định phòng thủ đóng vòng."""
        score = prediction_data.get("anomaly_score")
        if prediction_data.get("inference_status", "ok") != "ok" or not isinstance(score, (int, float)) or not np.isfinite(score):
            return  # Unavailable inference must never drive a defense action.
        is_anomaly = prediction_data.get("is_anomaly", False)
        threat_type_str = prediction_data.get("threat_type", "Normal")
        anomaly_score = float(prediction_data.get("anomaly_score", 0.0))
        confidence = float(prediction_data.get("confidence", 1.0))
        raw_telemetry = prediction_data.get("raw_telemetry", {})

        # Trích xuất IP khả nghi (hoặc từ device_id / IP giả lập tấn công)
        attacker_ip = raw_telemetry.get("src_ip") or prediction_data.get("attacker_ip") or "192.168.1.199"

        # 1. Ánh xạ threat type sang enum
        threat_enum = ThreatType.NORMAL
        threat_lower = threat_type_str.lower()
        if "syn" in threat_lower:
            threat_enum = ThreatType.SYN_FLOOD
        elif "udp" in threat_lower:
            threat_enum = ThreatType.UDP_FLOOD
        elif "scan" in threat_lower or "port" in threat_lower:
            threat_enum = ThreatType.PORT_SCAN
        elif "exfil" in threat_lower or "backdoor" in threat_lower:
            threat_enum = ThreatType.DATA_EXFILTRATION
        elif "adversarial" in threat_lower or "gan" in threat_lower:
            threat_enum = ThreatType.ADVERSARIAL_GAN
        elif is_anomaly:
            threat_enum = ThreatType.SYN_FLOOD

        # 2. Xây dựng vector trạng thái (Observation Vector)
        obs = np.zeros(10, dtype=np.float32)
        obs[0] = float(threat_enum.value) / 5.0
        obs[1] = float(np.clip(anomaly_score, 0.0, 1.0))
        obs[2] = float(np.clip(confidence, 0.0, 1.0))
        obs[3] = float(np.clip(float(raw_telemetry.get("packet_rate", 10.0)) / 5000.0, 0.0, 1.0))
        obs[4] = float(raw_telemetry.get("syn_ratio", 0.02))
        obs[5] = float(raw_telemetry.get("udp_ratio", 0.10))
        obs[6] = float(self.twin.channels[6].airtime_utilization)
        obs[7] = float(self.twin.channels[6].collision_probability)
        obs[8] = 0.02
        obs[9] = float(obs[6] * 1.1)

        # 3. RL Agent suy luận hành động phòng thủ tối ưu
        proposed_action_idx = self.agent.select_action(obs, evaluate=True)
        proposed_action = DefenseAction(proposed_action_idx)
        xai_info = self.agent.explain_decision(obs)

        # 4. Thẩm định qua Safety Controller (Digital Twin Dry-Run Sandbox)
        decision, final_action, safety_reason = self.safety_controller.validate_action(
            proposed_action=proposed_action,
            target_ip=attacker_ip,
            twin_engine=self.twin,
            metadata=prediction_data
        )

        # 5. Thực thi qua Network Controller nếu được phê duyệt
        enacted = False
        if decision in (SafetyDecision.APPROVED, SafetyDecision.DOWNGRADED):
            if final_action != DefenseAction.NO_ACTION:
                enacted = self.network_controller.enforce_action(
                    action=final_action,
                    target_ip=attacker_ip,
                    reason=f"RL Autonomous Decision: {safety_reason}"
                )

        # 6. Phát bản tin phản hồi (Closed-Loop Feedback) lên MQTT
        defense_event = {
            "timestamp": time.time(),
            "target_ip": attacker_ip,
            "detected_threat": threat_type_str,
            "anomaly_score": round(anomaly_score, 4),
            "proposed_action": ACTION_NAMES[proposed_action],
            "safety_decision": decision.value,
            "final_action": ACTION_NAMES[final_action],
            "enacted": enacted,
            "dry_run": not self.enforce_real_firewall,
            "reason": safety_reason,
            "xai_explanation": xai_info.get("rational_explanation", "")
        }

        if self.mqtt_client and self.mqtt_client.is_connected():
            self.mqtt_client.publish(
                "edge/defense/action",
                json.dumps(defense_event),
                qos=1
            )

    def stop(self):
        """Dừng an toàn dịch vụ và dọn dẹp các rule tường lửa."""
        self.running = False
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        self.network_controller.stop()
        print("[RL Defense] Đã dừng dịch vụ Closed-Loop Defense và hoàn nguyên Firewall.")
