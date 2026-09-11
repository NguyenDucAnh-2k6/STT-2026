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
# 1. ĐẶC TRƯNG MẠNG ĐẦY ĐỦ EDGE-IIOTSET (FULL 63-COLUMN SCHEMA: 61 FEATURES + 2 LABELS)
# ==============================================================================
EDGE_IIOTSET_FEATURES: List[str] = [
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
    "arp.dst.proto_ipv4",
    "arp.opcode",
    "arp.hw.size",
    "arp.src.proto_ipv4",
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

# 8 chỉ số thống kê rút gọn từ luồng gói tin trong cửa sổ thời gian (sliding window):
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

# Mặc định sử dụng bộ đặc trưng đầy đủ 61 đặc trưng đầu vào
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


class TelemetryPayload(TypedDict, total=False):
    """Cấu trúc gói tin Telemetry gửi từ cảm biến/Simulator qua MQTT."""
    device_id: str
    timestamp: int
    packet_rate: float
    byte_rate: float
    avg_packet_size: float
    syn_ratio: float
    ack_ratio: float
    udp_ratio: float
    icmp_ratio: float
    unique_dst_ports: float
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
