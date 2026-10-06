"""
Network Digital Twin (NDT) Engine
=================================
Mô phỏng bản sao số thời gian thực cho hệ sinh thái mạng biên AERO:
1. Mô phỏng Topology & Vật lý không gian vô tuyến (802.11 CSMA/CA, Airtime, Queuing delay).
2. Đồng bộ hóa trạng thái thực từ luồng Telemetry (Real-to-Twin Calibration).
3. Đón nhận lưu lượng tấn công chuẩn hoặc lưu lượng đối kháng sinh bởi GAN (Adversarial Traffic).
4. Thực hiện thử nghiệm an toàn chính sách phòng thủ trong Sandbox (Dry-run Sandbox),
   tính toán Blast Radius và mức độ tổn hại ngoài ý muốn (Collateral Damage) trước khi ban hành.
"""

import copy
import time
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

from digital_twin.models import (
    VirtualNode,
    ChannelState,
    NodeRole,
    NodeStatus,
    MitigationPolicy,
    MitigationAction,
    DryRunReport,
    TwinSafetyVerdict
)


class NetworkDigitalTwin:
    """
    Động cơ Bản sao số (Digital Twin) cho mạng biên AERO.
    """

    def __init__(self, name: str = "AERO-Edge-Twin"):
        self.name = name
        self.current_time: float = 0.0

        # Danh mục các nút mạng ảo (Virtual Nodes)
        self.nodes: Dict[str, VirtualNode] = {}

        # Trạng thái 13 kênh vô tuyến Wi-Fi 2.4GHz
        self.channels: Dict[int, ChannelState] = {
            ch: ChannelState(channel_id=ch) for ch in range(1, 14)
        }

        # Lịch sử telemetry và báo cáo dry-run
        self.telemetry_history: List[Dict[str, Any]] = []
        self.dry_run_history: List[DryRunReport] = []

        # Khởi tạo topology mạng mặc định
        self._initialize_default_topology()

    def _initialize_default_topology(self):
        """Khởi tạo một mạng văn phòng/phòng lab điển hình."""
        # 1. Gateway (Access Point Core)
        self.add_node(VirtualNode(
            node_id="gw_ap_01",
            name="Core AP (AERO-Lab)",
            role=NodeRole.GATEWAY,
            mac_address="00:11:22:33:44:01",
            ip_address="192.168.1.1",
            channel=6,
            rssi_dbm=-30.0,
            tx_packet_rate=150.0,
            tx_byte_rate=120000.0,
            avg_packet_size=800.0
        ))

        # 2. Cảm biến biên ESP32 Sniffer (Promiscuous Mode)
        self.add_node(VirtualNode(
            node_id="esp32_sniffer_01",
            name="ESP32 Edge Probe (Ch 6)",
            role=NodeRole.PROBE_ESP32,
            mac_address="24:6f:28:aa:bb:01",
            ip_address="192.168.1.101",
            channel=6,
            rssi_dbm=-48.0,
            tx_packet_rate=5.0,  # Chỉ gửi telemetry MQTT
            tx_byte_rate=2500.0
        ))

        # 3. Các thiết bị IoT bình thường (Benign Clients)
        self.add_node(VirtualNode(
            node_id="iot_cam_01",
            name="IoT Security Camera",
            role=NodeRole.BENIGN_IOT,
            mac_address="a4:cf:12:34:56:02",
            ip_address="192.168.1.50",
            channel=6,
            rssi_dbm=-52.0,
            tx_packet_rate=80.0,  # Luồng RTSP video nhẹ
            tx_byte_rate=80000.0,
            avg_packet_size=1000.0,
            udp_ratio=0.80,
            syn_ratio=0.01,
            ack_ratio=0.18
        ))

        self.add_node(VirtualNode(
            node_id="iot_sensor_01",
            name="IoT Environmental Sensor",
            role=NodeRole.BENIGN_IOT,
            mac_address="b8:27:eb:78:9a:03",
            ip_address="192.168.1.51",
            channel=6,
            rssi_dbm=-65.0,
            tx_packet_rate=5.0,  # Bắn MQTT mỗi vài trăm ms
            tx_byte_rate=1200.0,
            avg_packet_size=240.0,
            syn_ratio=0.02,
            ack_ratio=0.90
        ))

        # 4. Nút tiềm ẩn tấn công (Threat / Attacker Node)
        self.add_node(VirtualNode(
            node_id="node_threat_01",
            name="Untrusted Host / Threat Node",
            role=NodeRole.ATTACKER,
            mac_address="de:ad:be:ef:aa:99",
            ip_address="192.168.1.199",
            channel=6,
            rssi_dbm=-58.0,
            tx_packet_rate=20.0,
            tx_byte_rate=15000.0,
            is_malicious=False  # Ban đầu ở trạng thái yên lặng (Dormant)
        ))

    def add_node(self, node: VirtualNode):
        """Thêm một nút vào bản sao số."""
        self.nodes[node.node_id] = node

    def get_node(self, node_id: str) -> Optional[VirtualNode]:
        """Truy vấn nút theo ID."""
        return self.nodes.get(node_id)

    def find_node_by_ip_or_mac(self, identifier: str) -> Optional[VirtualNode]:
        """Tìm nút theo địa chỉ IP hoặc MAC."""
        for node in self.nodes.values():
            if node.ip_address == identifier or node.mac_address.lower() == identifier.lower():
                return node
        return None

    def inject_attack(
        self,
        attack_type: str = "SYN_Flood",
        packet_rate: float = 3500.0,
        target_node_id: str = "node_threat_01"
    ):
        """Phát động tấn công tiêu chuẩn trên nút chỉ định trong Digital Twin."""
        attacker = self.nodes.get(target_node_id)
        if not attacker:
            return

        attacker.is_malicious = True
        attacker.is_adversarial = False
        attacker.tx_packet_rate = packet_rate

        if attack_type in ("SYN_Flood", "DDoS_TCP"):
            attacker.avg_packet_size = 64.0
            attacker.tx_byte_rate = packet_rate * 64.0
            attacker.syn_ratio = 0.95
            attacker.ack_ratio = 0.02
            attacker.udp_ratio = 0.01

        elif attack_type in ("Volumetric_DDoS", "DDoS_UDP"):
            attacker.avg_packet_size = 1200.0
            attacker.tx_byte_rate = packet_rate * 1200.0
            attacker.udp_ratio = 0.96
            attacker.syn_ratio = 0.01

        elif attack_type in ("Port_Scan", "Port_Scanning"):
            attacker.avg_packet_size = 60.0
            attacker.tx_byte_rate = packet_rate * 60.0
            attacker.syn_ratio = 0.80

    def inject_adversarial_attack(
        self,
        adversarial_vector: np.ndarray,
        feature_names: List[str],
        target_node_id: str = "node_threat_01"
    ):
        """
        Nạp vector tấn công đối kháng (sinh bởi WGAN) vào nút tấn công trong Digital Twin.
        Vector này đã được tinh chỉnh để lẩn tránh IDS.
        """
        attacker = self.nodes.get(target_node_id)
        if not attacker:
            return

        attacker.is_malicious = True
        attacker.is_adversarial = True

        name_to_idx = {name: i for i, name in enumerate(feature_names)}

        if "packet_rate" in name_to_idx:
            attacker.tx_packet_rate = float(adversarial_vector[name_to_idx["packet_rate"]])
        if "byte_rate" in name_to_idx:
            attacker.tx_byte_rate = float(adversarial_vector[name_to_idx["byte_rate"]])
        if "avg_packet_size" in name_to_idx:
            attacker.avg_packet_size = float(adversarial_vector[name_to_idx["avg_packet_size"]])
        if "syn_ratio" in name_to_idx:
            attacker.syn_ratio = float(adversarial_vector[name_to_idx["syn_ratio"]])
        if "ack_ratio" in name_to_idx:
            attacker.ack_ratio = float(adversarial_vector[name_to_idx["ack_ratio"]])
        if "udp_ratio" in name_to_idx:
            attacker.udp_ratio = float(adversarial_vector[name_to_idx["udp_ratio"]])

    def step(self, dt_sec: float = 1.0):
        """
        Thực hiện một bước mô phỏng vật lý mạng (CSMA/CA channel physics & queuing):
        1. Tính toán Airtime Utilization trên từng kênh.
        2. Mô phỏng va chạm gói tin (Collisions) khi kênh bị nghẽn do tấn công.
        3. Cập nhật độ trễ (Latency), tỷ lệ rớt gói (Packet Loss), và tải bộ đệm ESP32.
        """
        self.current_time += dt_sec

        # 1. Đặt lại thống kê kênh
        for ch in self.channels.values():
            ch.airtime_utilization = 0.01
            ch.active_nodes_count = 0

        # Băng thông kênh Wi-Fi thực tế (giả định 20MHz ~ 54Mbps lý thuyết, hiệu dụng ~25Mbps = 3.125 MB/s)
        CHANNEL_CAPACITY_BYTES_SEC = 3125000.0

        # 2. Tính tổng tải trên từng kênh
        for node in self.nodes.values():
            if node.status in (NodeStatus.ISOLATED, NodeStatus.OFFLINE):
                continue

            ch = self.channels.get(node.channel)
            if ch:
                ch.active_nodes_count += 1
                effective_bytes = node.tx_byte_rate
                if node.rate_limit_bps is not None:
                    effective_bytes = min(effective_bytes, node.rate_limit_bps / 8.0)

                ch.airtime_utilization += (effective_bytes / CHANNEL_CAPACITY_BYTES_SEC)

        # 3. Cập nhật hiện tượng vật lý: Nghẽn kênh, va chạm, suy giảm QoS
        for ch_id, ch in self.channels.items():
            # Giới hạn airtime tối đa là 1.0
            ch.airtime_utilization = min(1.0, ch.airtime_utilization)

            # Mô phỏng xác suất va chạm CSMA/CA khi tải cao (> 0.6)
            if ch.airtime_utilization > 0.60:
                excess = ch.airtime_utilization - 0.60
                ch.collision_probability = min(0.95, 0.02 + 2.5 * (excess ** 1.8))
                ch.noise_floor_dbm = -92.0 + 20.0 * excess
            else:
                ch.collision_probability = 0.01 + 0.03 * ch.airtime_utilization
                ch.noise_floor_dbm = -92.0

        # 4. Phản ánh QoS ngược lại từng nút mạng
        for node in self.nodes.values():
            if node.status in (NodeStatus.ISOLATED, NodeStatus.OFFLINE):
                node.packet_loss_rate = 1.0
                node.latency_ms = 9999.0
                continue

            ch = self.channels[node.channel]

            # Rớt gói do va chạm không dây
            node.packet_loss_rate = ch.collision_probability

            # Độ trễ tăng theo hàng đợi M/M/1
            base_latency = 2.5
            if ch.airtime_utilization < 0.95:
                queue_factor = 1.0 / max(0.05, (1.0 - ch.airtime_utilization))
            else:
                queue_factor = 25.0

            node.latency_ms = min(2000.0, base_latency * queue_factor)

            # ESP32 Sniffer Buffer: nếu tổng gói tin trên kênh > 5000 pkts/s -> Buffer ESP32 đầy
            if node.role == NodeRole.PROBE_ESP32:
                total_channel_pkts = sum(
                    n.tx_packet_rate for n in self.nodes.values()
                    if n.channel == node.channel and n.status == NodeStatus.ONLINE
                )
                node.buffer_occupancy = min(1.0, total_channel_pkts / 5000.0)

    def evaluate_policy_dry_run(
        self,
        policy: MitigationPolicy,
        duration_sec: float = 8.0
    ) -> DryRunReport:
        """
        Chế độ Sandbox Thử nghiệm Khép kín (Closed-Loop Dry-run):
        1. Tạo bản sao tạm thời của Digital Twin (Sandbox Clone).
        2. Áp dụng chính sách phòng thủ đề xuất (ví dụ: Chặn MAC, Siết băng thông, Nhảy kênh).
        3. Chạy mô phỏng trong duration_sec giây ảo.
        4. Đo lường:
           - Attack Suppressed (%): Lưu lượng tấn công bị dập tắt bao nhiêu?
           - Collateral Damage (%): Thiết bị IoT hợp pháp có bị rớt gói/trễ quá mức không?
           - Network Health Score (0.0 -> 1.0).
        5. Đưa ra phán quyết (Verdict) trước khi cho phép áp dụng ra mạng thật!
        """
        # Tạo bản sao sâu độc lập để không ảnh hưởng trạng thái hiện tại
        sandbox = copy.deepcopy(self)

        # Đo đạc trước khi áp dụng
        benign_nodes_before = [n for n in sandbox.nodes.values() if n.role == NodeRole.BENIGN_IOT]
        initial_benign_throughput = sum(n.tx_byte_rate for n in benign_nodes_before)
        initial_attack_rate = sum(n.tx_packet_rate for n in sandbox.nodes.values() if n.is_malicious)

        # Áp dụng chính sách lên Sandbox
        target_node = sandbox.find_node_by_ip_or_mac(policy.target_identifier)

        if policy.action == MitigationAction.BLOCK_MAC:
            if target_node:
                target_node.status = NodeStatus.ISOLATED
        elif policy.action == MitigationAction.RATE_LIMIT_IP:
            if target_node:
                limit = policy.parameter_value or 10000.0  # Mặc định siết xuống 10 kbps
                target_node.rate_limit_bps = limit
                target_node.status = NodeStatus.THROTTLED
        elif policy.action == MitigationAction.SWITCH_CHANNEL:
            new_channel = int(policy.parameter_value or 11)
            # Chuyển AP và các node hợp pháp sang kênh mới để né kênh bị tấn công
            for n in sandbox.nodes.values():
                if n.role in (NodeRole.GATEWAY, NodeRole.BENIGN_IOT, NodeRole.PROBE_ESP32):
                    n.channel = new_channel

        # Chạy mô phỏng sandbox
        sim_steps = int(duration_sec)
        for _ in range(sim_steps):
            sandbox.step(dt_sec=1.0)

        # Đo đạc sau khi áp dụng chính sách
        benign_nodes_after = [n for n in sandbox.nodes.values() if n.role == NodeRole.BENIGN_IOT]
        final_benign_throughput = sum(
            n.tx_byte_rate * (1.0 - n.packet_loss_rate) for n in benign_nodes_after
        )
        final_attack_rate = sum(
            n.tx_packet_rate for n in sandbox.nodes.values()
            if n.is_malicious and n.status == NodeStatus.ONLINE
        )

        # 1. Tính tỷ lệ triệt tiêu tấn công
        if initial_attack_rate > 0:
            attack_suppressed_pct = max(0.0, (1.0 - final_attack_rate / initial_attack_rate)) * 100.0
        else:
            attack_suppressed_pct = 100.0

        # 2. Tính tổn hại ngoài ý muốn (Collateral Damage)
        # Nếu thiết bị bình thường bị giảm băng thông hoặc tăng độ trễ > 150ms
        avg_benign_loss = float(np.mean([n.packet_loss_rate for n in benign_nodes_after]))
        avg_benign_latency = float(np.mean([n.latency_ms for n in benign_nodes_after]))

        collateral_damage_pct = max(0.0, avg_benign_loss * 100.0)
        if avg_benign_latency > 150.0:
            collateral_damage_pct += min(50.0, (avg_benign_latency - 150.0) / 10.0)

        collateral_damage_pct = min(100.0, collateral_damage_pct)

        # 3. Tính điểm sức khỏe mạng (Network Health Score: 0.0 -> 1.0)
        health_score = (
            0.5 * (attack_suppressed_pct / 100.0) +
            0.5 * (1.0 - collateral_damage_pct / 100.0)
        )
        health_score = max(0.0, min(1.0, health_score))

        # 4. Xác định phán quyết an toàn (Safety Verdict)
        if attack_suppressed_pct >= 80.0 and collateral_damage_pct < 15.0:
            verdict = TwinSafetyVerdict.SAFE_TO_ENFORCE
            recommended = True
        elif collateral_damage_pct >= 25.0:
            verdict = TwinSafetyVerdict.RISK_OF_COLLATERAL_DAMAGE
            recommended = False
        else:
            verdict = TwinSafetyVerdict.INEFFECTIVE
            recommended = False

        report = DryRunReport(
            policy=policy,
            simulated_duration_sec=duration_sec,
            attack_suppressed_pct=round(attack_suppressed_pct, 2),
            collateral_damage_pct=round(collateral_damage_pct, 2),
            network_health_score=round(health_score, 3),
            verdict=verdict,
            recommended_to_apply=recommended,
            details={
                "target_identified": target_node.node_id if target_node else "UNKNOWN",
                "final_channel_airtime": round(sandbox.channels[sandbox.get_node("gw_ap_01").channel].airtime_utilization, 3),
                "avg_benign_latency_ms": round(avg_benign_latency, 2),
                "avg_benign_loss_pct": round(avg_benign_loss * 100.0, 2)
            }
        )

        self.dry_run_history.append(report)
        return report

    def sync_from_real_telemetry(self, telemetry_data: Dict[str, Any]):
        """
        Đồng bộ tham số thực tế từ MQTT Telemetry (ESP32/Host Sniffer) vào Digital Twin:
        - Điều chỉnh tốc độ nền (packet_rate).
        - Hiệu chỉnh độ nhiễu kênh (noise floor).
        """
        channel = telemetry_data.get("channel", 1)
        pkt_rate = telemetry_data.get("packet_rate", 10.0)
        avg_size = telemetry_data.get("avg_packet_size", 500.0)

        # Cập nhật nút ESP32 tương ứng
        for node in self.nodes.values():
            if node.role == NodeRole.PROBE_ESP32 and node.channel == channel:
                node.tx_packet_rate = float(pkt_rate)
                node.avg_packet_size = float(avg_size)

        self.telemetry_history.append({
            "timestamp": time.time(),
            "channel": channel,
            "packet_rate": pkt_rate
        })
        if len(self.telemetry_history) > 1000:
            self.telemetry_history.pop(0)

    def get_summary_state(self) -> Dict[str, Any]:
        """Xuất tổng quan trạng thái phục vụ API / Dashboard."""
        active_nodes = [n for n in self.nodes.values() if n.status == NodeStatus.ONLINE]
        malicious_nodes = [n for n in self.nodes.values() if n.is_malicious]

        # Kênh của Gateway chính
        gw = self.get_node("gw_ap_01")
        core_ch = self.channels[gw.channel] if gw else self.channels[1]

        return {
            "name": self.name,
            "sim_time": round(self.current_time, 1),
            "total_nodes": len(self.nodes),
            "active_nodes": len(active_nodes),
            "malicious_nodes": len(malicious_nodes),
            "core_channel": {
                "id": core_ch.channel_id,
                "airtime_utilization": round(core_ch.airtime_utilization * 100.0, 1),
                "collision_prob": round(core_ch.collision_probability * 100.0, 1),
                "noise_dbm": round(core_ch.noise_floor_dbm, 1)
            },
            "nodes": [
                {
                    "id": n.node_id,
                    "name": n.name,
                    "role": n.role.value,
                    "status": n.status.value,
                    "ip": n.ip_address,
                    "mac": n.mac_address,
                    "rate_pkts_s": round(n.tx_packet_rate, 1),
                    "loss_pct": round(n.packet_loss_rate * 100.0, 1),
                    "latency_ms": round(n.latency_ms, 1),
                    "is_adversarial": n.is_adversarial
                }
                for n in self.nodes.values()
            ]
        }
