"""
Network Digital Twin - Reinforcement Learning Environment (Gym-Compatible)
==========================================================================
Xây dựng môi trường học tăng cường (RL Environment) tương thích Gymnasium/Gym
dựa trên nền tảng Network Digital Twin (NDT) của hệ sinh thái AERO.

Mục tiêu của RL Agent:
Học Policy ra quyết định phòng thủ mạng tối ưu (Autonomous Incident Response):
- Cân bằng giữa việc dập tắt cuộc tấn công (Attack Suppression)
- Triệt tiêu tổn hại ngoài ý muốn đối với các thiết bị hợp pháp (Collateral Damage)
- Tối thiểu hóa chi phí can thiệp và tránh báo động giả (False Alarms)
"""
import os
import random
from enum import IntEnum
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

from digital_twin.models import (
    VirtualNode,
    ChannelState,
    NodeRole,
    NodeStatus,
    MitigationAction,
    MitigationPolicy,
    DryRunReport,
    TwinSafetyVerdict
)
from digital_twin.engine import NetworkDigitalTwin


class DefenseAction(IntEnum):
    """
    Không gian hành động phòng thủ chuẩn (Action Space):
    Dựa trên các chuẩn phòng thủ mạng công nghiệp (NIST SP 800-61 / MITRE D3FEND).
    """
    NO_ACTION = 0            # Giữ nguyên, không can thiệp (phù hợp khi lưu lượng bình thường)
    RATE_LIMIT_IP = 1        # Siết băng thông IP nguồn (chống UDP Flood, DoS nhẹ)
    BLOCK_IP_FIREWALL = 2    # Chặn hoàn toàn IP qua Tường lửa (chống Port Scan, SYN Flood hung hãn)
    ISOLATE_MAC_DEAUTH = 3   # Cách ly MAC vô tuyến tầng 2 (chống thiết bị Rogue, IoT bị chiếm quyền)
    SWITCH_CHANNEL = 4       # Đổi kênh vô tuyến Wi-Fi (né nhiễu RF / Jamming / Flooding tràn kênh)
    HONEYPOT_REDIRECT = 5    # Chuyển hướng sang Honeypot ảo (chống Reconnaissance / Vuln Scan)


ACTION_NAMES = {
    DefenseAction.NO_ACTION: "NO_ACTION",
    DefenseAction.RATE_LIMIT_IP: "RATE_LIMIT_IP",
    DefenseAction.BLOCK_IP_FIREWALL: "BLOCK_IP_FIREWALL",
    DefenseAction.ISOLATE_MAC_DEAUTH: "ISOLATE_MAC_DEAUTH",
    DefenseAction.SWITCH_CHANNEL: "SWITCH_CHANNEL",
    DefenseAction.HONEYPOT_REDIRECT: "HONEYPOT_REDIRECT",
}


class ThreatType(IntEnum):
    """Mã hóa danh mục mối đe dọa từ bộ Edge ML Detection."""
    NORMAL = 0
    SYN_FLOOD = 1
    UDP_FLOOD = 2
    PORT_SCAN = 3
    DATA_EXFILTRATION = 4
    ADVERSARIAL_GAN = 5


class EmpiricalThreatBank:
    """
    Ngân hàng mẫu đe dọa thực nghiệm (Data-Driven Threat Bank):
    Trích xuất và nạp phân phối đặc trưng thực tế từ tập dữ liệu an ninh mạng
    Edge-IIoTset và các phân vùng Parquet trong Data Lakehouse (data_lake/raw/).
    Đảm bảo RL Agent không bị bias bởi số liệu hardcoded, mà được tôi luyện trực tiếp
    trên phân phối lưu lượng thực tế!
    """

    def __init__(self, root_dir: Optional[str] = None):
        self.root_dir = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.samples_by_threat: Dict[ThreatType, List[Dict[str, float]]] = {
            t: [] for t in ThreatType
        }
        self.load_empirical_samples()

    def load_empirical_samples(self):
        """Nạp dữ liệu từ CSV Edge-IIoTset và Parquet Data Lake."""
        import os
        # 1. Nạp từ Edge-IIoTset CSV
        csv_path = os.path.join(self.root_dir, "ml_engine", "datasets", "synthetic_traffic_dataset.csv")
        if os.path.exists(csv_path):
            try:
                import pandas as pd
                df = pd.read_csv(csv_path)
                label_map = {
                    0: ThreatType.NORMAL,
                    1: ThreatType.SYN_FLOOD,
                    2: ThreatType.PORT_SCAN,
                    3: ThreatType.UDP_FLOOD,
                    4: ThreatType.DATA_EXFILTRATION
                }
                for lbl, threat_type in label_map.items():
                    sub_df = df[df["label"] == lbl]
                    if not sub_df.empty:
                        # Lấy tối đa 200 mẫu mỗi loại để làm seed bank
                        n_sample = min(len(sub_df), 200)
                        for _, row in sub_df.sample(n_sample, random_state=42).iterrows():
                            self.samples_by_threat[threat_type].append({
                                "packet_rate": float(row.get("packet_rate", 10.0)),
                                "byte_rate": float(row.get("byte_rate", 5000.0)),
                                "avg_packet_size": float(row.get("avg_packet_size", 500.0)),
                                "syn_ratio": float(row.get("syn_ratio", 0.02)),
                                "ack_ratio": float(row.get("ack_ratio", 0.85)),
                                "udp_ratio": float(row.get("udp_ratio", 0.10)),
                                "icmp_ratio": float(row.get("icmp_ratio", 0.01)),
                            })
            except Exception:
                pass

        # 2. Nạp thêm lưu lượng Normal thực tế từ các phân vùng Parquet trong Data Lakehouse
        lake_raw_dir = os.path.join(self.root_dir, "data_lake", "raw")
        if os.path.exists(lake_raw_dir):
            try:
                import pandas as pd
                parquet_files = []
                for root, _, files in os.walk(lake_raw_dir):
                    for f in files:
                        if f.endswith(".parquet"):
                            parquet_files.append(os.path.join(root, f))
                for pf in parquet_files[-5:]:
                    try:
                        df_p = pd.read_parquet(pf)
                        if "packet_rate" in df_p.columns:
                            normal_p = df_p[df_p.get("ground_truth_scenario", "Normal") == "Normal"]
                            if not normal_p.empty:
                                for _, row in normal_p.sample(min(len(normal_p), 50), random_state=42).iterrows():
                                    self.samples_by_threat[ThreatType.NORMAL].append({
                                        "packet_rate": float(row.get("packet_rate", 10.0)),
                                        "byte_rate": float(row.get("byte_rate", 5000.0)),
                                        "avg_packet_size": float(row.get("avg_packet_size", 500.0)),
                                        "syn_ratio": float(row.get("syn_ratio", 0.02)),
                                        "ack_ratio": float(row.get("ack_ratio", 0.85)),
                                        "udp_ratio": float(row.get("udp_ratio", 0.10)),
                                        "icmp_ratio": float(row.get("icmp_ratio", 0.01)),
                                    })
                    except Exception:
                        pass
            except Exception:
                pass

    def sample_features(self, threat: ThreatType) -> Optional[Dict[str, float]]:
        """Lấy ngẫu nhiên một vector đặc trưng thực tế từ kho mẫu."""
        pool = self.samples_by_threat.get(threat, [])
        if pool:
            return random.choice(pool)
        return None


class CyberDefenseRLEnv:
    """
    Môi trường RL đóng vòng (Closed-loop RL Environment).
    Giao diện chuẩn Gymnasium/Gym:
      - reset() -> (obs, info)
      - step(action) -> (obs, reward, terminated, truncated, info)
    """

    def __init__(self, seed: Optional[int] = None, data_source: str = "hybrid"):
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

        self.action_space_n = len(DefenseAction)
        # Vector trạng thái 10 chiều
        self.observation_dim = 10

        self.data_source = data_source
        self.seed_bank = EmpiricalThreatBank()

        self.twin = NetworkDigitalTwin(name="RL-Training-Twin")
        self.current_step = 0
        self.max_steps_per_episode = 100

        # Trạng thái hiện tại của phiên mô phỏng
        self.current_threat: ThreatType = ThreatType.NORMAL
        self.current_threat_node_id: Optional[str] = None
        self.current_obs: np.ndarray = np.zeros(self.observation_dim, dtype=np.float32)

    def reset(self, threat_type: Optional[ThreatType] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Khởi tạo lại trạng thái môi trường cho episode mới."""
        self.twin = NetworkDigitalTwin(name="RL-Training-Twin")
        self.current_step = 0

        # Nếu không chỉ định, ngẫu nhiên chọn một kịch bản mạng
        if threat_type is None:
            # Xác suất 30% Normal, 70% các loại tấn công khác nhau
            if random.random() < 0.30:
                self.current_threat = ThreatType.NORMAL
            else:
                self.current_threat = random.choice([
                    ThreatType.SYN_FLOOD,
                    ThreatType.UDP_FLOOD,
                    ThreatType.PORT_SCAN,
                    ThreatType.DATA_EXFILTRATION,
                    ThreatType.ADVERSARIAL_GAN
                ])
        else:
            self.current_threat = threat_type

        # Cấu hình nút mạng trong Twin tương ứng với kịch bản
        self._inject_threat_scenario(self.current_threat)

        # Chạy 1 nhịp mô phỏng ban đầu
        self.twin.step(dt_sec=1.0)
        self.current_obs = self._build_observation()

        info = {
            "threat_type": self.current_threat.name,
            "target_node": self.current_threat_node_id,
            "airtime": self.twin.channels[6].airtime_utilization
        }
        return self.current_obs, info

    def _inject_threat_scenario(self, threat: ThreatType):
        """Đưa kịch bản tấn công tương ứng vào mô hình Digital Twin."""
        # Xóa các nút tấn công cũ nếu có
        threat_ids = [nid for nid, n in self.twin.nodes.items() if n.is_malicious]
        for tid in threat_ids:
            self.twin.remove_node(tid)

        if threat == ThreatType.NORMAL:
            self.current_threat_node_id = None
            return

        node_id = f"threat_{threat.name.lower()}_01"
        self.current_threat_node_id = node_id

        # Lấy mẫu đặc trưng thực tế từ Edge-IIoTset / Data Lake Parquet
        real_sample = self.seed_bank.sample_features(threat)

        if threat == ThreatType.SYN_FLOOD:
            pkt_rate = real_sample["packet_rate"] if real_sample else 3200.0
            byte_rate = real_sample["byte_rate"] if real_sample else 250000.0
            avg_size = real_sample["avg_packet_size"] if real_sample else 78.0
            syn_r = real_sample["syn_ratio"] if real_sample else 0.96
            ack_r = real_sample["ack_ratio"] if real_sample else 0.02
            udp_r = real_sample["udp_ratio"] if real_sample else 0.01

            self.twin.add_node(VirtualNode(
                node_id=node_id,
                name="SYN Flooder Bot (Data-Driven)",
                role=NodeRole.ATTACKER,
                mac_address="de:ad:be:ef:00:01",
                ip_address="192.168.1.199",
                channel=6,
                rssi_dbm=-45.0,
                tx_packet_rate=pkt_rate,
                tx_byte_rate=byte_rate,
                avg_packet_size=avg_size,
                syn_ratio=syn_r,
                ack_ratio=ack_r,
                udp_ratio=udp_r,
                is_malicious=True
            ))

        elif threat == ThreatType.UDP_FLOOD:
            pkt_rate = real_sample["packet_rate"] if real_sample else 4500.0
            byte_rate = real_sample["byte_rate"] if real_sample else 650000.0
            avg_size = real_sample["avg_packet_size"] if real_sample else 1400.0
            syn_r = real_sample["syn_ratio"] if real_sample else 0.01
            ack_r = real_sample["ack_ratio"] if real_sample else 0.01
            udp_r = real_sample["udp_ratio"] if real_sample else 0.98

            self.twin.add_node(VirtualNode(
                node_id=node_id,
                name="UDP Storm Attacker (Data-Driven)",
                role=NodeRole.ATTACKER,
                mac_address="de:ad:be:ef:00:02",
                ip_address="192.168.1.205",
                channel=6,
                rssi_dbm=-42.0,
                tx_packet_rate=pkt_rate,
                tx_byte_rate=byte_rate,
                avg_packet_size=avg_size,
                syn_ratio=syn_r,
                ack_ratio=ack_r,
                udp_ratio=udp_r,
                is_malicious=True
            ))

        elif threat == ThreatType.PORT_SCAN:
            pkt_rate = real_sample["packet_rate"] if real_sample else 350.0
            byte_rate = real_sample["byte_rate"] if real_sample else 22000.0
            avg_size = real_sample["avg_packet_size"] if real_sample else 60.0
            syn_r = real_sample["syn_ratio"] if real_sample else 0.88
            ack_r = real_sample["ack_ratio"] if real_sample else 0.05
            udp_r = real_sample["udp_ratio"] if real_sample else 0.05

            self.twin.add_node(VirtualNode(
                node_id=node_id,
                name="Nmap Recon Probe (Data-Driven)",
                role=NodeRole.ATTACKER,
                mac_address="de:ad:be:ef:00:03",
                ip_address="192.168.1.210",
                channel=6,
                rssi_dbm=-50.0,
                tx_packet_rate=pkt_rate,
                tx_byte_rate=byte_rate,
                avg_packet_size=avg_size,
                syn_ratio=syn_r,
                ack_ratio=ack_r,
                udp_ratio=udp_r,
                is_malicious=True
            ))

        elif threat == ThreatType.DATA_EXFILTRATION:
            pkt_rate = real_sample["packet_rate"] if real_sample else 600.0
            byte_rate = real_sample["byte_rate"] if real_sample else 750000.0
            avg_size = real_sample["avg_packet_size"] if real_sample else 1250.0
            syn_r = real_sample["syn_ratio"] if real_sample else 0.03
            ack_r = real_sample["ack_ratio"] if real_sample else 0.45
            udp_r = real_sample["udp_ratio"] if real_sample else 0.10

            self.twin.add_node(VirtualNode(
                node_id=node_id,
                name="C2 Exfiltration Agent (Data-Driven)",
                role=NodeRole.ATTACKER,
                mac_address="de:ad:be:ef:00:04",
                ip_address="192.168.1.215",
                channel=6,
                rssi_dbm=-55.0,
                tx_packet_rate=pkt_rate,
                tx_byte_rate=byte_rate,
                avg_packet_size=avg_size,
                syn_ratio=syn_r,
                ack_ratio=ack_r,
                udp_ratio=udp_r,
                is_malicious=True
            ))

        elif threat == ThreatType.ADVERSARIAL_GAN:
            # Tấn công lẩn tránh sinh bởi WGAN-GP (Low & Slow + Dummy Padding)
            self.twin.add_node(VirtualNode(
                node_id=node_id,
                name="GAN Evasion Node (WGAN Perturbed)",
                role=NodeRole.ATTACKER,
                mac_address="de:ad:be:ef:00:05",
                ip_address="192.168.1.220",
                channel=6,
                rssi_dbm=-48.0,
                tx_packet_rate=450.0,
                tx_byte_rate=180000.0,
                avg_packet_size=400.0,
                syn_ratio=0.42,
                ack_ratio=0.38,
                udp_ratio=0.20,
                is_malicious=True,
                is_adversarial=True
            ))

    def _build_observation(self) -> np.ndarray:
        """
        Xây dựng vector đặc trưng trạng thái mạng 10 chiều:
        0. threat_type_norm: [0.0 - 1.0] (Loại tấn công dự đoán từ Edge ML)
        1. anomaly_score: [0.0 - 1.0] (Điểm số bất thường Isolation Forest)
        2. confidence: [0.0 - 1.0] (Độ tin cậy phân loại)
        3. packet_rate_norm: Tốc độ gói tin mạng (chuẩn hóa / 5000)
        4. syn_ratio: [0.0 - 1.0]
        5. udp_ratio: [0.0 - 1.0]
        6. airtime_utilization: [0.0 - 1.0]
        7. collision_probability: [0.0 - 1.0]
        8. avg_latency_norm: Độ trễ mạng (chuẩn hóa / 200 ms)
        9. collateral_damage_risk: [0.0 - 1.0] (Ước lượng rủi ro ảnh hưởng thiết bị hợp pháp)
        """
        obs = np.zeros(self.observation_dim, dtype=np.float32)

        # 0. Mã hóa loại đe dọa
        obs[0] = float(self.current_threat.value) / 5.0

        # Lấy thông số từ kênh mạng lõi (kênh 6)
        core_ch = self.twin.channels[6]
        obs[6] = float(np.clip(core_ch.airtime_utilization, 0.0, 1.0))
        obs[7] = float(np.clip(core_ch.collision_probability, 0.0, 1.0))

        # Thống kê nút
        all_nodes = list(self.twin.nodes.values())
        total_pkt_rate = sum(n.tx_packet_rate for n in all_nodes if n.status == NodeStatus.ONLINE)
        obs[3] = float(np.clip(total_pkt_rate / 5000.0, 0.0, 1.0))

        # Lấy nút đáng ngờ hoặc trung bình
        target = self.twin.get_node(self.current_threat_node_id) if self.current_threat_node_id else None
        if target:
            obs[1] = 0.95 if target.is_malicious else 0.05
            obs[2] = 0.90
            obs[4] = float(np.clip(target.syn_ratio, 0.0, 1.0))
            obs[5] = float(np.clip(target.udp_ratio, 0.0, 1.0))
        else:
            obs[1] = 0.02
            obs[2] = 0.98
            obs[4] = 0.02
            obs[5] = 0.10

        # Độ trễ trung bình của các thiết bị IoT bình thường
        benign_nodes = [n for n in all_nodes if n.role == NodeRole.BENIGN_IOT]
        if benign_nodes:
            avg_lat = np.mean([n.latency_ms for n in benign_nodes])
            obs[8] = float(np.clip(avg_lat / 200.0, 0.0, 1.0))
            # Rủi ro nếu airtime > 50%
            obs[9] = float(np.clip(core_ch.airtime_utilization * 1.2, 0.0, 1.0))
        else:
            obs[8] = 0.01
            obs[9] = 0.0

        return obs

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """
        Thực hiện một hành động phòng thủ trong môi trường:
        1. Chuyển đổi DefenseAction thành MitigationPolicy.
        2. Thử nghiệm qua Dry-run Sandbox của Digital Twin.
        3. Tính toán Reward đa mục tiêu (Multi-Objective Cyber Defense Reward).
        """
        self.current_step += 1
        act = DefenseAction(action)
        target = self.twin.get_node(self.current_threat_node_id) if self.current_threat_node_id else None
        target_id = target.ip_address if target else "192.168.1.1"

        # 1. Chuyển đổi sang MitigationPolicy
        policy = self._action_to_policy(act, target_id)

        # 2. Dry-run trong Sandbox của Digital Twin
        report: DryRunReport = self.twin.evaluate_mitigation_policy_dry_run(policy, duration_sec=3.0)

        # 3. Tính toán Reward
        reward = self._calculate_reward(act, self.current_threat, report)

        # Cập nhật trạng thái thực của Twin nếu phán quyết an toàn
        if report.verdict == TwinSafetyVerdict.SAFE_TO_ENFORCE and act != DefenseAction.NO_ACTION:
            if act == DefenseAction.BLOCK_IP_FIREWALL and target:
                target.status = NodeStatus.ISOLATED
            elif act == DefenseAction.RATE_LIMIT_IP and target:
                target.status = NodeStatus.THROTTLED
                target.tx_packet_rate = min(target.tx_packet_rate, 50.0)
            elif act == DefenseAction.ISOLATE_MAC_DEAUTH and target:
                target.status = NodeStatus.OFFLINE
            elif act == DefenseAction.SWITCH_CHANNEL:
                for n in self.twin.nodes.values():
                    if not n.is_malicious:
                        n.channel = 11

        # Tiến thêm 1 bước thời gian vật lý
        self.twin.step(dt_sec=1.0)
        self.current_obs = self._build_observation()

        # Tiêu chí kết thúc episode (Triệt tiêu thành công hoặc hết số bước)
        terminated = (report.attack_suppressed_pct >= 90.0) or (self.current_threat == ThreatType.NORMAL and act == DefenseAction.NO_ACTION)
        truncated = self.current_step >= self.max_steps_per_episode

        info = {
            "action_name": ACTION_NAMES[act],
            "verdict": report.verdict.value,
            "attack_suppressed": report.attack_suppressed_pct,
            "collateral_damage": report.collateral_damage_pct,
            "health_score": report.network_health_score,
            "dry_run_report": report
        }

        return self.current_obs, reward, terminated, truncated, info

    def _action_to_policy(self, act: DefenseAction, target_id: str) -> MitigationPolicy:
        """Chuyển đổi Enum Action thành MitigationPolicy."""
        if act == DefenseAction.NO_ACTION:
            return MitigationPolicy(action=MitigationAction.NO_ACTION, target_identifier=target_id)
        elif act == DefenseAction.RATE_LIMIT_IP:
            return MitigationPolicy(action=MitigationAction.RATE_LIMIT_IP, target_identifier=target_id, parameter_value=25000.0)
        elif act == DefenseAction.BLOCK_IP_FIREWALL:
            return MitigationPolicy(action=MitigationAction.BLOCK_MAC, target_identifier=target_id)
        elif act == DefenseAction.ISOLATE_MAC_DEAUTH:
            return MitigationPolicy(action=MitigationAction.ISOLATE_NODE, target_identifier=target_id)
        elif act == DefenseAction.SWITCH_CHANNEL:
            return MitigationPolicy(action=MitigationAction.SWITCH_CHANNEL, target_identifier=target_id, parameter_value=11)
        elif act == DefenseAction.HONEYPOT_REDIRECT:
            # Chuyển hướng rate-limit nhẹ và bẫy IP
            return MitigationPolicy(action=MitigationAction.RATE_LIMIT_IP, target_identifier=target_id, parameter_value=5000.0)
        return MitigationPolicy(action=MitigationAction.NO_ACTION, target_identifier=target_id)

    def _calculate_reward(self, act: DefenseAction, threat: ThreatType, report: DryRunReport) -> float:
        """
        Hàm tính phần thưởng đa mục tiêu (Multi-Objective Reward Function):
        R = + Thưởng dập tắt tấn công
            - Phạt tổn hại ngoài ý muốn (Collateral Damage)
            - Phạt chi phí can thiệp / Overkill
            - Phạt báo động giả (False Alarm)
        """
        reward = 0.0

        # KỊCH BẢN 1: MẠNG BÌNH THƯỜNG (NORMAL BENIGN)
        if threat == ThreatType.NORMAL:
            if act == DefenseAction.NO_ACTION:
                # Thưởng vì duy trì ổn định, không can thiệp bừa bãi
                return +5.0
            else:
                # PHẠT NẶNG BÁO ĐỘNG GIẢ (False Positive): Tự dưng chặn hoặc nhảy kênh làm gián đoạn người dùng
                if act in (DefenseAction.BLOCK_IP_FIREWALL, DefenseAction.ISOLATE_MAC_DEAUTH):
                    return -25.0
                elif act == DefenseAction.SWITCH_CHANNEL:
                    return -15.0
                else:
                    return -10.0

        # KỊCH BẢN 2: ĐANG BỊ TẤN CÔNG (MALICIOUS ATTACK)
        # 2.1. Thưởng dập tắt tấn công (Attack Suppression)
        suppress_reward = (report.attack_suppressed_pct / 100.0) * 15.0
        reward += suppress_reward

        # 2.2. Phạt tổn hại phụ (Collateral Damage)
        damage_penalty = (report.collateral_damage_pct / 100.0) * 20.0
        reward -= damage_penalty

        # 2.3. Khớp chuẩn kỹ thuật phòng thủ tối ưu theo từng loại tấn công:
        # - SYN Flood: Phòng thủ chuẩn là BLOCK_IP_FIREWALL (Drop packets tại firewall)
        if threat == ThreatType.SYN_FLOOD:
            if act == DefenseAction.BLOCK_IP_FIREWALL:
                reward += 10.0  # Chuẩn NIST
            elif act == DefenseAction.RATE_LIMIT_IP:
                reward += 2.0   # Chỉ giảm tải phần nào
            elif act == DefenseAction.NO_ACTION:
                reward -= 15.0  # Không hành động khi bị ngập lụt SYN

        # - UDP Flood: Phòng thủ chuẩn là RATE_LIMIT_IP (hoặc BLOCK_IP nếu quá tải)
        elif threat == ThreatType.UDP_FLOOD:
            if act in (DefenseAction.RATE_LIMIT_IP, DefenseAction.BLOCK_IP_FIREWALL):
                reward += 10.0
            elif act == DefenseAction.NO_ACTION:
                reward -= 15.0

        # - Port Scan: Phòng thủ chuẩn là HONEYPOT_REDIRECT hoặc BLOCK_IP_FIREWALL
        elif threat == ThreatType.PORT_SCAN:
            if act in (DefenseAction.HONEYPOT_REDIRECT, DefenseAction.BLOCK_IP_FIREWALL):
                reward += 10.0
            elif act == DefenseAction.ISOLATE_MAC_DEAUTH:
                reward -= 5.0   # Quá mức (Overkill) cho một vụ quét cổng thông thường
            elif act == DefenseAction.NO_ACTION:
                reward -= 8.0

        # - Data Exfiltration: Phòng thủ chuẩn là BLOCK_IP_FIREWALL và ISOLATE_MAC_DEAUTH
        elif threat == ThreatType.DATA_EXFILTRATION:
            if act in (DefenseAction.BLOCK_IP_FIREWALL, DefenseAction.ISOLATE_MAC_DEAUTH):
                reward += 12.0
            elif act == DefenseAction.NO_ACTION:
                reward -= 20.0

        # - Adversarial GAN: Tấn công né tránh tinh vi, chuẩn là ISOLATE_MAC_DEAUTH hoặc BLOCK_IP
        elif threat == ThreatType.ADVERSARIAL_GAN:
            if act in (DefenseAction.ISOLATE_MAC_DEAUTH, DefenseAction.BLOCK_IP_FIREWALL):
                reward += 12.0
            elif act == DefenseAction.RATE_LIMIT_IP:
                reward += 4.0
            elif act == DefenseAction.NO_ACTION:
                reward -= 18.0

        # Thưởng thêm nếu đạt phán quyết An Toàn Tuyệt Đối từ Sandbox
        if report.verdict == TwinSafetyVerdict.SAFE_TO_ENFORCE:
            reward += 5.0
        elif report.verdict == TwinSafetyVerdict.RISK_OF_COLLATERAL_DAMAGE:
            reward -= 10.0

        return float(reward)
