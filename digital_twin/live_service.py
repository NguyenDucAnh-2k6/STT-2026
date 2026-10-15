"""
Live Network Digital Twin Daemon (Real-Time Service)
====================================================
Tiến trình Bản sao số thời gian thực (Live Digital Twin) vận hành song song cùng hệ thống mạng thật:
1. Nhận luồng Telemetry thời gian thực từ MQTT (`edge/telemetry/traffic`).
2. Đồng bộ hóa và hiệu chuẩn mô hình vật lý mạng ảo (Airtime, CSMA/CA Contention, Queuing Delay).
3. Phát định kỳ trạng thái bản sao số lên topic `edge/digital_twin/state` (chu kỳ 1s)
   để Web Dashboard trực quan hóa topology và thông số vô tuyến.
4. Tích hợp sẵn Closed-Loop RL Incident Response & Safety Sandbox khi được kích hoạt.
"""

import sys
import os
import time
import json
import threading
from typing import Dict, Any, Optional

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from digital_twin.engine import NetworkDigitalTwin
from digital_twin.models import MitigationPolicy, MitigationAction, DryRunReport
from digital_twin.rl_environment import DefenseAction, ThreatType, ACTION_NAMES
from digital_twin.rl_agent import CyberDefenseRLAgent
from digital_twin.safety_controller import SafetyController, SafetyDecision
from digital_twin.network_controller import NetworkController


class LiveDigitalTwinDaemon:
    """
    Tiến trình daemon Bản sao số mạng biên thời gian thực.
    """

    def __init__(
        self,
        broker_host: str = "127.0.0.1",
        broker_port: int = 1883,
        enable_rl_defense: bool = False,
        enforce_real_firewall: bool = False
    ):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.enable_rl_defense = enable_rl_defense
        self.enforce_real_firewall = enforce_real_firewall

        # Khởi tạo Digital Twin cốt lõi
        self.twin = NetworkDigitalTwin(name="Live-Edge-Twin")
        self.running = False
        self.mqtt_client = None
        self.experiment_state: Dict[str, Any] = {}

        # Khởi tạo RL Agent & Controllers nếu kích hoạt RL Defense
        if self.enable_rl_defense:
            self.rl_agent = CyberDefenseRLAgent()
            policy_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "models",
                "rl_defense_policy.json"
            )
            if os.path.isfile(policy_path):
                self.rl_agent.load_policy(policy_path)
            self.safety_controller = SafetyController()
            self.network_controller = NetworkController(dry_run=not self.enforce_real_firewall)
        else:
            self.rl_agent = None
            self.safety_controller = None
            self.network_controller = None

    def start(self):
        """Khởi động daemon kết nối MQTT và luồng mô phỏng vật lý."""
        self.running = True

        # 1. Luồng mô phỏng nhịp vật lý 1 Hz
        self.physics_thread = threading.Thread(target=self._physics_loop, daemon=True)
        self.physics_thread.start()

        # 2. Khởi tạo MQTT Client
        if mqtt is not None:
            self.mqtt_client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2 if hasattr(mqtt, "CallbackAPIVersion") else 1,
                client_id=f"AERO-Live-Digital-Twin-{int(time.time())}"
            )
            self.mqtt_client.on_connect = self._on_connect
            self.mqtt_client.on_message = self._on_message

            try:
                self.mqtt_client.connect(self.broker_host, self.broker_port, keepalive=60)
                self.mqtt_client.loop_start()
                print(f"[Digital Twin] Đã kích hoạt Live Network Digital Twin song song với mạng thật!")
                print(f"               Lắng nghe MQTT tại {self.broker_host}:{self.broker_port} -> Publish: edge/digital_twin/state")
                if self.enable_rl_defense:
                    print(f"               [RL Defense] Tích hợp Autonomous Incident Response (Chế độ: {'Active Firewall' if self.enforce_real_firewall else 'Dry-run Sandbox'})")
            except Exception as e:
                print(f"[Digital Twin Error] Không thể kết nối MQTT: {e}")

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            client.subscribe("edge/telemetry/traffic")
            client.subscribe("edge/telemetry/window")
            client.subscribe("edge/telemetry/prediction")
            client.subscribe("edge/digital_twin/dry_run_req")
            client.subscribe("edge/experiments/status", qos=1)

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        if not isinstance(payload, dict):
            return
        if topic == "edge/experiments/status":
            self.experiment_state = dict(payload)
            return
        if topic == "edge/telemetry/traffic" and payload.get("record_kind") == "packet":
            return
        if topic in ("edge/telemetry/traffic", "edge/telemetry/window"):
            # Hiệu chuẩn động lực học của Digital Twin theo lưu lượng thật
            self.twin.sync_from_real_telemetry(payload)

        elif topic == "edge/telemetry/prediction":
            # Cập nhật trạng thái tấn công và kích hoạt RL Defense nếu có
            if self.enable_rl_defense:
                self._handle_rl_defense_step(payload)

        elif topic == "edge/digital_twin/dry_run_req":
            # Nhận yêu cầu chạy Sandbox Dry-Run on-demand từ Dashboard
            self._handle_dry_run_request(payload)

    def _physics_loop(self):
        """Vòng lặp tính toán vật lý không gian vô tuyến và xuất trạng thái mỗi giây."""
        while self.running:
            try:
                # Tiến 1 nhịp thời gian mô phỏng
                self.twin.step(dt_sec=1.0)

                # Xuất bản tin tổng quan Digital Twin lên MQTT
                if self.mqtt_client and self.mqtt_client.is_connected():
                    summary = self.twin.get_summary_state()
                    summary["timestamp"] = time.time()
                    summary["rl_defense_enabled"] = self.enable_rl_defense
                    summary["experiment"] = dict(self.experiment_state)
                    self.mqtt_client.publish(
                        "edge/digital_twin/state",
                        json.dumps(summary),
                        qos=0
                    )
            except Exception:
                pass
            time.sleep(1.0)

    def _handle_rl_defense_step(self, prediction_data: Dict[str, Any]):
        """Xử lý suy luận RL và kiểm định an toàn qua Digital Twin."""
        score = prediction_data.get("anomaly_score")
        if prediction_data.get("inference_status", "ok") != "ok" or not isinstance(score, (int, float)) or not np.isfinite(score):
            return  # Unavailable inference must never drive a defense action.
        threat_type_str = prediction_data.get("threat_type", "Normal")
        anomaly_score = float(prediction_data.get("anomaly_score", 0.0))
        confidence = float(prediction_data.get("confidence", 1.0))
        raw_telemetry = prediction_data.get("raw_telemetry", {})
        attacker_ip = raw_telemetry.get("src_ip") or prediction_data.get("attacker_ip") or "192.168.1.199"

        # Ánh xạ enum
        threat_enum = ThreatType.NORMAL
        tl = threat_type_str.lower()
        if "syn" in tl:
            threat_enum = ThreatType.SYN_FLOOD
        elif "udp" in tl:
            threat_enum = ThreatType.UDP_FLOOD
        elif "scan" in tl or "port" in tl:
            threat_enum = ThreatType.PORT_SCAN
        elif "exfil" in tl or "backdoor" in tl:
            threat_enum = ThreatType.DATA_EXFILTRATION
        elif "gan" in tl or "adversarial" in tl:
            threat_enum = ThreatType.ADVERSARIAL_GAN
        elif prediction_data.get("is_anomaly", False):
            threat_enum = ThreatType.SYN_FLOOD

        # Vector trạng thái 10 chiều
        import numpy as np
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

        # Chọn hành động
        act_idx = self.rl_agent.select_action(obs, evaluate=True)
        act = DefenseAction(act_idx)
        xai = self.rl_agent.explain_decision(obs)

        # Thẩm định Sandbox
        decision, final_action, reason = self.safety_controller.validate_action(
            proposed_action=act,
            target_ip=attacker_ip,
            twin_engine=self.twin,
            metadata=prediction_data
        )

        enacted = False
        if decision in (SafetyDecision.APPROVED, SafetyDecision.DOWNGRADED):
            if final_action != DefenseAction.NO_ACTION:
                enacted = self.network_controller.enforce_action(
                    action=final_action,
                    target_ip=attacker_ip,
                    reason=f"RL Defense: {reason}"
                )

        event = {
            "timestamp": time.time(),
            "target_ip": attacker_ip,
            "detected_threat": threat_type_str,
            "anomaly_score": round(anomaly_score, 4),
            "proposed_action": ACTION_NAMES[act],
            "safety_decision": decision.value,
            "final_action": ACTION_NAMES[final_action],
            "enacted": enacted,
            "dry_run": not self.enforce_real_firewall,
            "reason": reason,
            "xai_explanation": xai.get("rational_explanation", "")
        }
        if self.mqtt_client and self.mqtt_client.is_connected():
            self.mqtt_client.publish("edge/defense/action", json.dumps(event), qos=1)

    def _handle_dry_run_request(self, payload: Dict[str, Any]):
        """Xử lý yêu cầu Dry-Run Sandbox theo lệnh của Dashboard."""
        action_str = payload.get("action", "BLOCK_MAC")
        target_id = payload.get("target", "192.168.1.199")
        param_val = payload.get("parameter_value", None)

        act_enum = MitigationAction.BLOCK_MAC
        if action_str == "RATE_LIMIT_IP":
            act_enum = MitigationAction.RATE_LIMIT_IP
        elif action_str == "SWITCH_CHANNEL":
            act_enum = MitigationAction.SWITCH_CHANNEL

        policy = MitigationPolicy(action=act_enum, target_identifier=target_id, parameter_value=param_val)
        report: DryRunReport = self.twin.evaluate_mitigation_policy_dry_run(policy, duration_sec=3.0)

        response = {
            "req_id": payload.get("req_id", "req_01"),
            "policy": action_str,
            "target": target_id,
            "verdict": report.verdict.value,
            "attack_suppressed": report.attack_suppressed_pct,
            "collateral_damage": report.collateral_damage_pct,
            "health_score": report.network_health_score,
            "recommended": report.recommended_to_apply
        }
        if self.mqtt_client and self.mqtt_client.is_connected():
            self.mqtt_client.publish("edge/digital_twin/dry_run_res", json.dumps(response), qos=1)

    def stop(self):
        """Dừng daemon an toàn."""
        self.running = False
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        if self.network_controller:
            self.network_controller.stop()


def start_live_digital_twin_worker(
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    enable_rl_defense: bool = False,
    enforce_real: bool = False
):
    """Entrypoint khởi chạy worker cho multiprocessing."""
    daemon = LiveDigitalTwinDaemon(
        broker_host=broker_host,
        broker_port=broker_port,
        enable_rl_defense=enable_rl_defense,
        enforce_real_firewall=enforce_real
    )
    daemon.start()
    while daemon.running:
        time.sleep(1.0)
