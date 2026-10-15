"""
Traffic Data Schema & Operational Constants
============================================
Chỉ dẫn module:
- Module này định nghĩa các chuẩn dữ liệu mạng phục vụ trích xuất đặc trưng và suy luận biên.
- Bất kỳ thay đổi nào về thứ tự các đặc trưng trong FEATURE_NAMES đều ảnh hưởng trực tiếp đến:
  1. Đầu vào huấn luyện (train.py)
  2. Bộ trích xuất thời gian thực (inference_service.py)
  3. Mã nguồn C sinh ra cho vi điều khiển ESP32 (tinyml_model.h)
- Khuyến nghị: Giữ nguyên thứ tự danh sách đặc trưng nếu muốn duy trì tương thích firmware.
"""

from typing import List, Dict, Any, TypedDict

# ==============================================================================
# 1. ĐẶC TRƯNG MẠNG ĐẦY ĐỦ EDGE-IIOTSET (56 ĐẶC TRƯNG HÀNH VI MẠNG THỰC SỰ - ĐÃ LOẠI BỎ TOÀN BỘ IP & METADATA RÒ RỈ)
# ==============================================================================
EDGE_IIOTSET_FEATURES: List[str] = [
    "arp.opcode",
    "arp.hw.size",
    "icmp.checksum",
    "icmp.seq_le",
    "icmp.transmit_timestamp",
    "icmp.unused",
    "http.file_data",
    "http.content_length",
    "http.request.uri.query",
    "http.request.method",
    "http.referer",
    "http.request.full_uri",
    "http.request.version",
    "http.response",
    "http.tls_port",
    "tcp.ack",
    "tcp.ack_raw",
    "tcp.checksum",
    "tcp.connection.fin",
    "tcp.connection.rst",
    "tcp.connection.syn",
    "tcp.connection.synack",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.options",
    "tcp.payload",
    "tcp.seq",
    "tcp.srcport",
    "udp.port",
    "udp.stream",
    "udp.time_delta",
    "dns.qry.name",
    "dns.qry.name.len",
    "dns.qry.qu",
    "dns.qry.type",
    "dns.retransmission",
    "dns.retransmit_request",
    "dns.retransmit_request_in",
    "mqtt.conack.flags",
    "mqtt.conflag.cleansess",
    "mqtt.conflags",
    "mqtt.hdrflags",
    "mqtt.len",
    "mqtt.msg_decoded_as",
    "mqtt.msg",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.protoname",
    "mqtt.topic",
    "mqtt.topic_len",
    "mqtt.ver",
    "mbtcp.len",
    "mbtcp.trans_id",
    "mbtcp.unit_id"
]

# 8 chỉ số thống kê rút gọn cơ sở từ luồng gói tin trong cửa sổ thời gian (sliding window):
SLIDING_WINDOW_FEATURES: List[str] = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "syn_ratio",
    "ack_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_dst_ports"
]

# Tập đặc trưng mở rộng toàn diện (L3/L4 Extended Features Pool - Theo khuyến nghị GPT):
# Khắc phục thiếu sót về: endpoint diversity, TCP flags, semantic state, packet distribution, IAT và entropy
SLIDING_WINDOW_EXTENDED_FEATURES: List[str] = [
    # 1. Thể tích & Lưu lượng cơ sở (Traffic Volume)
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "packet_size_std",
    # 2. Phân bố giao thức tầng mạng (Protocol Distribution)
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    # 3. Trạng thái và cờ TCP chi tiết (Detailed TCP Flags & Connection State)
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "syn_completion_ratio",
    # 4. Độ đa dạng địa chỉ và cổng (Endpoint Diversity - Phản ánh "D" trong DDoS & Quét mạng)
    "unique_src_ports",
    "unique_dst_ports",
    "unique_src_ips",
    "unique_dst_ips",
    "src_dst_pair_count",
    # 5. Động lực học thời gian & Khoảng cách giữa các gói (Temporal Dynamics & IAT - Bắt Low & Slow)
    "mean_iat",
    "std_iat",
    # 6. Entropy cổng dịch vụ (Port Scanning & Vulnerability Recognition)
    "dst_port_entropy"
]

# ==============================================================================
# DANH MỤC CỘT METADATA & NHÃN CẤM RÒ RỈ VÀO TẬP ĐẶC TRƯNG HUẤN LUYỆN (DATA LEAKAGE PREVENTION)
# ==============================================================================
DATA_LEAKAGE_METADATA_COLUMNS: List[str] = [
    "session_id",
    "timestamp",
    "datetime_iso",
    "probe_type",
    "sniffer_mode",
    "channel",
    "ground_truth_scenario",
    "is_attack",
    "label",
    "Attack_label",
    "Attack_type",
    "predicted_threat",
    "anomaly_score",
    "confidence",
    "edge_prediction",
    "edge_flag",
    "attack_scenario",
    "attack_status"
]

# Mặc định sử dụng bộ đặc trưng đầy đủ 56 đặc trưng đầu vào của Edge-IIoTset
FEATURE_NAMES: List[str] = EDGE_IIOTSET_FEATURES

# ==============================================================================
# 2. DANH MỤC NHÃN TẤN CÔNG (LABELS: 15 LỚP TRONG EDGE-IIOTSET)
# ==============================================================================
EDGE_IIOTSET_LABELS: List[str] = [
    "Normal",
    "DDoS_UDP",
    "DDoS_ICMP",
    "Ransomware",
    "DDoS_HTTP",
    "SQL_injection",
    "Uploading",
    "DDoS_TCP",
    "Backdoor",
    "Vulnerability_scanner",
    "Port_Scanning",
    "XSS",
    "Password",
    "MITM",
    "Fingerprinting"
]

# Danh mục nhãn thu gọn 5 lớp (cho Sliding Window / Simulator cũ)
SLIDING_WINDOW_LABELS: List[str] = [
    "Normal",
    "SYN_Flood",
    "Port_Scan",
    "Volumetric_DDoS",
    "Data_Exfiltration"
]

# Mặc định sử dụng 15 nhãn của Edge-IIoTset
LABEL_NAMES: List[str] = EDGE_IIOTSET_LABELS

LABEL_MAP: Dict[str, int] = {name: idx for idx, name in enumerate(LABEL_NAMES)}
LABEL_NAME_TO_ID: Dict[str, int] = LABEL_MAP
INDEX_TO_LABEL: Dict[int, str] = {idx: name for idx, name in enumerate(LABEL_NAMES)}

# ==============================================================================
# 3. CÁC HẰNG SỐ CẤU HÌNH VẬN HÀNH (OPERATIONAL DEFAULTS)
# ==============================================================================
DEFAULT_ANOMALY_THRESHOLD: float = 0.55   # Điểm số bất thường vượt ngưỡng này sẽ phát cảnh báo
DEFAULT_CONTAMINATION_RATE: float = 0.03  # Tỷ lệ ngoại lai giả định trong tập dữ liệu bình thường
DEFAULT_DATASET_SAMPLES: int = 15000      # Số lượng mẫu mặc định khi huấn luyện / lấy mẫu



class FeatureVector(TypedDict):
    """Cấu trúc dữ liệu 8 đặc trưng tiêu chuẩn."""
    packet_rate: float
    byte_rate: float
    avg_packet_size: float
    syn_ratio: float
    ack_ratio: float
    udp_ratio: float
    icmp_ratio: float
    unique_dst_ports: float


class ExtendedFeatureVector(TypedDict, total=False):
    """Cấu trúc dữ liệu đặc trưng mở rộng (L3/L4 Extended Feature Set)."""
    packet_rate: float
    byte_rate: float
    avg_packet_size: float
    packet_size_std: float
    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float
    syn_ratio: float
    ack_ratio: float
    rst_ratio: float
    fin_ratio: float
    syn_completion_ratio: float
    unique_src_ports: int
    unique_dst_ports: int
    unique_src_ips: int
    unique_dst_ips: int
    src_dst_pair_count: int
    mean_iat: float
    std_iat: float
    dst_port_entropy: float


class TelemetryPayload(TypedDict, total=False):
    """Cấu trúc gói tin Telemetry gửi từ cảm biến/Simulator qua MQTT."""
    device_id: str
    timestamp: int
    packet_rate: float
    byte_rate: float
    avg_packet_size: float
    packet_size_std: float
    syn_ratio: float
    ack_ratio: float
    rst_ratio: float
    fin_ratio: float
    syn_completion_ratio: float
    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float
    unique_src_ports: int
    unique_dst_ports: int
    unique_src_ips: int
    unique_dst_ips: int
    src_dst_pair_count: int
    mean_iat: float
    std_iat: float
    dst_port_entropy: float
    tcp_packets: int
    udp_packets: int
    icmp_packets: int

