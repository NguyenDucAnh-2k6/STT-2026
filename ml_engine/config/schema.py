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
# 1. ĐẶC TRƯNG MẠNG (FEATURES) TỐI ƯU CHO THIẾT BỊ BIÊN (EDGE IOT)
# ==============================================================================
# 8 chỉ số thống kê rút gọn từ luồng gói tin trong cửa sổ thời gian (sliding window):
#  - packet_rate:      Tần suất gói (pkts/s) -> Nhận diện tấn công dồn dập (DDoS, Flood).
#  - byte_rate:        Băng thông tiêu thụ (bytes/s) -> Nhận diện rò rỉ dữ liệu hoặc cạn kiệt tài nguyên.
#  - avg_packet_size:  Kích thước gói trung bình -> Nhận diện gói TCP SYN nhỏ hay data chunk lớn.
#  - syn_ratio:        Tỷ lệ cờ SYN / tổng TCP -> Dấu hiệu kinh điển của SYN Flood scan/attack.
#  - ack_ratio:        Tỷ lệ cờ ACK / tổng TCP -> Dấu hiệu luồng kết nối ổn định hay bất thường.
#  - udp_ratio:        Tỷ lệ lưu lượng UDP -> Dấu hiệu UDP Flood / DNS amplification.
#  - icmp_ratio:       Tỷ lệ gói tin ICMP -> Dấu hiệu Ping Flood / Smurf attack.
#  - unique_dst_ports: Số lượng cổng đích -> Dấu hiệu quét cổng (Port Scan / Network Recon).

FEATURE_NAMES: List[str] = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "syn_ratio",
    "ack_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_dst_ports"
]

# ==============================================================================
# 2. DANH MỤC NHÃN TẤN CÔNG (LABELS)
# ==============================================================================
LABEL_NAMES: List[str] = [
    "Normal",               # 0: Lưu lượng truy cập mạng an toàn, bình thường
    "SYN_Flood",            # 1: Tấn công dồn dập cờ TCP SYN gây cạn kiệt hàng đợi kết nối
    "Port_Scan",            # 2: Quét dò cổng phân tán nhằm thu thập thông tin lỗ hổng
    "Volumetric_DDoS",      # 3: Tấn công từ chối dịch vụ băng thông cực lớn
    "Data_Exfiltration"     # 4: Hành vi đánh cắp, trích xuất dữ liệu dung lượng lớn ra ngoài
]

LABEL_MAP: Dict[str, int] = {name: idx for idx, name in enumerate(LABEL_NAMES)}
INDEX_TO_LABEL: Dict[int, str] = {idx: name for idx, name in enumerate(LABEL_NAMES)}

# ==============================================================================
# 3. CÁC HẰNG SỐ CẤU HÌNH VẬN HÀNH (OPERATIONAL DEFAULTS)
# ==============================================================================
DEFAULT_ANOMALY_THRESHOLD: float = 0.55   # Điểm số bất thường vượt ngưỡng này sẽ phát cảnh báo
DEFAULT_CONTAMINATION_RATE: float = 0.03  # Tỷ lệ ngoại lai giả định trong tập dữ liệu bình thường
DEFAULT_DATASET_SAMPLES: int = 10000      # Số lượng mẫu mặc định khi sinh dữ liệu huấn luyện


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
