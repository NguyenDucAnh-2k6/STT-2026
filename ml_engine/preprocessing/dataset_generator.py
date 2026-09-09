"""
Network Traffic Synthetic Dataset Generator
============================================
Chỉ dẫn module:
- Module này chịu trách nhiệm khởi tạo tập dữ liệu lưu lượng mạng mô phỏng
  dựa trên phân phối thống kê từ các bộ dữ liệu tiêu chuẩn (CIC-IDS2017 & NSL-KDD).
- Phân bổ mẫu mặc định:
  + Normal Traffic:         60% (nền tảng mạng văn phòng, IoT ổn định)
  + SYN Flood Attack:       10% (tần suất gói cao, kích thước gói nhỏ, tỷ lệ SYN áp đảo)
  + Port Scan Attack:       10% (tần suất quét trung bình, số lượng cổng đích biến thiên lớn)
  + Volumetric DDoS:        10% (tần suất gói cực lớn, băng thông nghẽn, UDP bão hòa)
  + Data Exfiltration:      10% (băng thông tải ra lớn liên tục, kích thước gói đạt MTU)
- Để bổ sung dạng tấn công mới:
  1. Thêm nhãn vào `ml_engine.config.schema.LABEL_NAMES`
  2. Bổ sung hàm sinh phân phối tương ứng trong `generate_synthetic_dataset`
"""

import os
from typing import Tuple, Optional
import numpy as np
import pandas as pd

from ..config.schema import FEATURE_NAMES, LABEL_MAP, DEFAULT_DATASET_SAMPLES


def generate_synthetic_dataset(
    n_samples: int = DEFAULT_DATASET_SAMPLES,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Sinh tập dữ liệu lưu lượng mạng mô phỏng phục vụ huấn luyện và đánh giá mô hình.

    Parameters:
    -----------
    n_samples : int
        Tổng số lượng mẫu cần sinh (mặc định: 10,000).
    random_state : int
        Seed cho bộ sinh số ngẫu nhiên để đảm bảo khả năng tái lặp (reproducibility).

    Returns:
    --------
    pd.DataFrame:
        DataFrame chứa 8 cột đặc trưng và 1 cột nhãn 'label' (được xáo trộn ngẫu nhiên).
    """
    np.random.seed(random_state)
    data = []

    # 1. NORMAL TRAFFIC (60% dữ liệu)
    n_normal = int(n_samples * 0.60)
    for _ in range(n_normal):
        packet_rate = np.random.uniform(30.0, 220.0)
        avg_pkt_size = np.random.uniform(280.0, 850.0)
        byte_rate = packet_rate * avg_pkt_size * np.random.uniform(0.95, 1.05)
        syn_ratio = np.random.uniform(0.01, 0.08)
        ack_ratio = np.random.uniform(0.60, 0.88)
        udp_ratio = np.random.uniform(0.08, 0.32)
        icmp_ratio = np.random.uniform(0.00, 0.02)
        unique_ports = np.random.randint(3, 20)
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, LABEL_MAP["Normal"]])

    # 2. SYN FLOOD ATTACK (10% dữ liệu)
    n_syn = int(n_samples * 0.10)
    for _ in range(n_syn):
        packet_rate = np.random.uniform(1200.0, 4500.0)
        avg_pkt_size = np.random.uniform(54.0, 78.0)
        byte_rate = packet_rate * avg_pkt_size
        syn_ratio = np.random.uniform(0.85, 0.99)
        ack_ratio = np.random.uniform(0.00, 0.05)
        udp_ratio = np.random.uniform(0.00, 0.05)
        icmp_ratio = 0.0
        unique_ports = np.random.randint(1, 6)
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, LABEL_MAP["SYN_Flood"]])

    # 3. PORT SCAN ATTACK (10% dữ liệu)
    n_scan = int(n_samples * 0.10)
    for _ in range(n_scan):
        packet_rate = np.random.uniform(300.0, 950.0)
        avg_pkt_size = np.random.uniform(54.0, 95.0)
        byte_rate = packet_rate * avg_pkt_size
        syn_ratio = np.random.uniform(0.55, 0.88)
        ack_ratio = np.random.uniform(0.02, 0.15)
        udp_ratio = np.random.uniform(0.10, 0.35)
        icmp_ratio = np.random.uniform(0.01, 0.08)
        unique_ports = np.random.randint(60, 400)
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, LABEL_MAP["Port_Scan"]])

    # 4. VOLUMETRIC DDOS (10% dữ liệu)
    n_ddos = int(n_samples * 0.10)
    for _ in range(n_ddos):
        packet_rate = np.random.uniform(3500.0, 9000.0)
        avg_pkt_size = np.random.uniform(900.0, 1480.0)
        byte_rate = packet_rate * avg_pkt_size
        syn_ratio = np.random.uniform(0.02, 0.20)
        ack_ratio = np.random.uniform(0.05, 0.25)
        udp_ratio = np.random.uniform(0.70, 0.95)
        icmp_ratio = np.random.uniform(0.02, 0.15)
        unique_ports = np.random.randint(4, 25)
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, LABEL_MAP["Volumetric_DDoS"]])

    # 5. DATA EXFILTRATION (10% dữ liệu)
    n_exfil = int(n_samples * 0.10)
    for _ in range(n_exfil):
        packet_rate = np.random.uniform(100.0, 320.0)
        avg_pkt_size = np.random.uniform(1400.0, 1496.0)
        byte_rate = packet_rate * avg_pkt_size
        syn_ratio = np.random.uniform(0.01, 0.03)
        ack_ratio = np.random.uniform(0.92, 0.99)
        udp_ratio = np.random.uniform(0.00, 0.04)
        icmp_ratio = 0.0
        unique_ports = np.random.randint(1, 3)
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, LABEL_MAP["Data_Exfiltration"]])

    # Đóng gói DataFrame và xáo trộn ngẫu nhiên
    columns = FEATURE_NAMES + ["label"]
    df = pd.DataFrame(data, columns=columns)
    return df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def save_synthetic_dataset(output_path: str, n_samples: int = DEFAULT_DATASET_SAMPLES, random_state: int = 42) -> str:
    """
    Sinh và lưu dataset ra tệp CSV.

    Parameters:
    -----------
    output_path : str
        Đường dẫn tệp CSV đầu ra.
    n_samples : int
        Số lượng mẫu cần sinh.
    random_state : int
        Hạt giống sinh ngẫu nhiên.

    Returns:
    --------
    str:
        Đường dẫn tuyệt đối đến tệp dataset vừa lưu.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df = generate_synthetic_dataset(n_samples=n_samples, random_state=random_state)
    df.to_csv(output_path, index=False)
    return os.path.abspath(output_path)
