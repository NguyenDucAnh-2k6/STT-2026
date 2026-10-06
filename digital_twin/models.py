"""
Network Digital Twin - Data Models & Schema
===========================================
Định nghĩa các cấu trúc dữ liệu mô phỏng trạng thái vật lý của mạng biên (Edge Network):
1. VirtualNode: Đại diện cho Access Point, ESP32 Probe, Thiết bị IoT, và Nút tấn công.
2. ChannelMetrics: Trạng thái không gian vô tuyến (Airtime, Interference, Collision Rate).
3. MitigationPolicy: Chính sách can thiệp mạng đề xuất (Chặn MAC, Siết băng thông, Nhảy kênh).
4. DryRunReport: Báo cáo kết quả thử nghiệm chính sách trong sandbox sinh thái số.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class NodeRole(str, Enum):
    GATEWAY = "GATEWAY"
    PROBE_ESP32 = "PROBE_ESP32"
    BENIGN_IOT = "BENIGN_IOT"
    ATTACKER = "ATTACKER"


class NodeStatus(str, Enum):
    ONLINE = "ONLINE"
    ISOLATED = "ISOLATED"
    THROTTLED = "THROTTLED"
    OFFLINE = "OFFLINE"


class VirtualNode(BaseModel):
    """Mô hình nút mạng ảo trong Digital Twin."""
    node_id: str
    name: str
    role: NodeRole
    mac_address: str
    ip_address: str
    channel: int = 1
    rssi_dbm: float = -55.0
    status: NodeStatus = NodeStatus.ONLINE

    # Thống kê lưu lượng thời gian thực
    tx_packet_rate: float = 10.0      # pkts/s
    tx_byte_rate: float = 5000.0      # bytes/s
    avg_packet_size: float = 500.0    # bytes
    buffer_occupancy: float = 0.05    # [0.0 - 1.0]
    packet_loss_rate: float = 0.0     # [0.0 - 1.0]
    latency_ms: float = 2.5           # ms

    # Phân phối cờ/giao thức
    syn_ratio: float = 0.02
    ack_ratio: float = 0.85
    udp_ratio: float = 0.10
    icmp_ratio: float = 0.01

    # Cấu hình can thiệp
    rate_limit_bps: Optional[float] = None
    is_malicious: bool = False
    is_adversarial: bool = False


class ChannelState(BaseModel):
    """Trạng thái kênh vô tuyến 802.11 (Channel Physics)."""
    channel_id: int
    airtime_utilization: float = 0.05  # [0.0 - 1.0]
    collision_probability: float = 0.01 # [0.0 - 1.0]
    noise_floor_dbm: float = -92.0
    active_nodes_count: int = 0


class MitigationAction(str, Enum):
    BLOCK_MAC = "BLOCK_MAC"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    ISOLATE_NODE = "ISOLATE_NODE"
    SWITCH_CHANNEL = "SWITCH_CHANNEL"
    NO_ACTION = "NO_ACTION"


class MitigationPolicy(BaseModel):
    """Chính sách can thiệp phòng thủ đề xuất để kiểm thử trong Digital Twin."""
    action: MitigationAction
    target_identifier: str            # MAC hoặc IP
    parameter_value: Optional[float] = None # Giá trị (ví dụ: limit 50000 bps, hoặc channel 6)
    reason: str = "Tự động đề xuất bởi Security Engine"


class TwinSafetyVerdict(str, Enum):
    SAFE_TO_ENFORCE = "SAFE_TO_ENFORCE"                     # An toàn tuyệt đối, triệt tiêu tấn công, không ảnh hưởng IoT
    RISK_OF_COLLATERAL_DAMAGE = "RISK_OF_COLLATERAL_DAMAGE" # Nguy cơ chặn nhầm thiết bị hợp pháp / nghẽn mạng phụ
    INEFFECTIVE = "INEFFECTIVE"                             # Không đủ dập tắt tấn công


class DryRunReport(BaseModel):
    """Báo cáo đánh giá thử nghiệm an toàn chính sách trước khi áp dụng mạng thật."""
    policy: MitigationPolicy
    simulated_duration_sec: float
    attack_suppressed_pct: float
    collateral_damage_pct: float
    network_health_score: float   # 0.0 -> 1.0
    verdict: TwinSafetyVerdict
    recommended_to_apply: bool
    details: Dict[str, Any] = Field(default_factory=dict)
