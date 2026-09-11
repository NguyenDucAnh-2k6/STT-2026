#!/usr/bin/env python3
"""
Edge-IIoTset Comprehensive Exploratory Data Analysis (EDA) & Feature Extraction
================================================================================
Mục đích:
1. Phân tích chi tiết tập dữ liệu Edge-IIoTset (Selected dataset for ML and DL).
2. Kiểm tra schema 63 đặc trưng, độ cân bằng các lớp tấn công (14 loại tấn công + Normal).
3. Vẽ các đồ thị trực quan hóa chất lượng cao (Dark Cyber SOC Aesthetic) lưu tại ml_engine/notebooks/eda_charts/.
4. Trích xuất mối tương quan và kiểm chứng chiến lược thu gọn về 8 đặc trưng cho vi điều khiển ESP32.
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Đảm bảo UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Thư mục làm việc
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_PATH = os.path.join(
    BASE_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
    "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv"
)
OUTPUT_CHARTS_DIR = os.path.join(BASE_DIR, "ml_engine", "notebooks", "eda_charts")
os.makedirs(OUTPUT_CHARTS_DIR, exist_ok=True)

# Thiết lập phong cách đồ họa Cyber SOC hiện đại
plt.style.use('dark_background')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#1f3344'
plt.rcParams['axes.linewidth'] = 1.0
plt.rcParams['grid.color'] = '#162330'
plt.rcParams['grid.linestyle'] = '--'
plt.rcParams['grid.alpha'] = 0.6


def run_eda():
    print("=" * 75)
    print("      EDGE-IIOTSET DATASET - COMPREHENSIVE EXPLORATORY DATA ANALYSIS")
    print("=" * 75)

    if not os.path.exists(DATASET_PATH):
        print(f"[LỖI] Không tìm thấy file: {DATASET_PATH}")
        return

    print(f"\n[1/6] Đang nạp dataset từ: {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    n_rows, n_cols = df.shape
    print(f"  -> Tổng số dòng (Records)  : {n_rows:,}")
    print(f"  -> Tổng số cột (Features)  : {n_cols}")

    # 1. Phân tích nhãn
    print("\n[2/6] Phân tích phân phối nhãn tấn công...")
    attack_counts = df["Attack_type"].value_counts()
    binary_counts = df["Attack_label"].value_counts()

    print(f"  -> Nhị phân (Binary): Normal = {binary_counts.get(0, 0):,} ({binary_counts.get(0, 0)/n_rows*100:.1f}%), Attack = {binary_counts.get(1, 0):,} ({binary_counts.get(1, 0)/n_rows*100:.1f}%)")
    print("\n  -> Chi tiết 14 loại tấn công:")
    for atk, cnt in attack_counts.items():
        print(f"     * {atk:<25}: {cnt:>6,} ({cnt/n_rows*100:>5.2f}%)")

    # 2. Xử lý dữ liệu khuyết & kiểu dữ liệu
    print("\n[3/6] Kiểm tra kiểu dữ liệu và giá trị khuyết...")
    null_counts = df.isnull().sum()
    cols_with_null = null_counts[null_counts > 0]
    if len(cols_with_null) == 0:
        print("  -> Không có giá trị NULL/Khuyết trong toàn bộ 157,800 dòng!")
    else:
        print(f"  -> Có {len(cols_with_null)} cột chứa giá trị khuyết: {dict(cols_with_null)}")

    # 3. Phân loại nhóm đặc trưng theo tầng mạng
    transport_cols = [c for c in df.columns if c.startswith("tcp.") or c.startswith("udp.")]
    iot_app_cols = [c for c in df.columns if c.startswith("mqtt.") or c.startswith("mbtcp.") or c.startswith("http.")]
    net_cols = [c for c in df.columns if c.startswith("ip.") or c.startswith("arp.") or c.startswith("icmp.") or c.startswith("dns.")]

    print(f"\n  -> Phân loại 63 đặc trưng:")
    print(f"     * Giao vận (Transport - TCP/UDP) : {len(transport_cols)} đặc trưng")
    print(f"     * Ứng dụng IoT (MQTT/Modbus/HTTP): {len(iot_app_cols)} đặc trưng")
    print(f"     * Mạng & Dò quét (IP/ARP/ICMP/DNS) : {len(net_cols)} đặc trưng")

    # =========================================================================
    # VẼ BIỂU ĐỒ 1: PHÂN BỐ CÁC LỚP TẤN CÔNG (ATTACK TYPE DISTRIBUTION)
    # =========================================================================
    print("\n[4/6] Đang vẽ Biểu đồ 1: Phân bố các loại tấn công (Attack Types)...")
    fig, ax = plt.subplots(figsize=(12, 7), facecolor='#091017')
    ax.set_facecolor('#0d1722')

    palette = ['#10b981' if x == 'Normal' else '#ef4444' if 'DDoS' in x else '#f59e0b' if 'Scan' in x else '#a855f7' for x in attack_counts.index]
    y_pos = np.arange(len(attack_counts))
    bars = ax.barh(y_pos, attack_counts.values, color=palette, edgecolor='#ffffff', alpha=0.85, height=0.7)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(attack_counts.index, fontsize=11, fontweight='semibold')
    ax.invert_yaxis()
    ax.set_xlabel('Số lượng gói tin / mẫu (Packet Records)', fontsize=12, color='#94a3b8', labelpad=10)
    ax.set_title('Edge-IIoTset: Phân Phối 14 Loại Tấn Công & Lưu Lượng Bình Thường (Normal)', fontsize=14, fontweight='bold', color='#38bdf8', pad=15)
    ax.grid(axis='x', alpha=0.3)

    # Ghi số lượng và phần trăm trên từng thanh
    for bar in bars:
        width = bar.get_width()
        pct = width / n_rows * 100
        ax.text(width + 800, bar.get_y() + bar.get_height()/2, f"{int(width):,} ({pct:.1f}%)",
                va='center', ha='left', fontsize=9.5, color='#e2e8f0', fontweight='bold')

    plt.tight_layout()
    chart1_path = os.path.join(OUTPUT_CHARTS_DIR, "01_attack_types_distribution.png")
    plt.savefig(chart1_path, dpi=300, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  -> Đã lưu: {chart1_path}")

    # =========================================================================
    # VẼ BIỂU ĐỒ 2: PHÂN BỐ CÁC GIAO THỨC TRUYỀN THÔNG IOT / MẠNG
    # =========================================================================
    print("[5/6] Đang vẽ Biểu đồ 2: Phân bố giao thức mạng (Protocols)...")
    # Đếm tỷ lệ gói theo giao thức
    tcp_pkts = (df["tcp.connection.syn"] > 0) | (df["tcp.flags.ack"] > 0) | (df["tcp.len"] > 0)
    udp_pkts = (df["udp.stream"] > 0) | (df["udp.port"] > 0)
    icmp_pkts = (df["icmp.checksum"] > 0) | (df["icmp.seq_le"] > 0)
    mqtt_pkts = (df["mqtt.len"] > 0) | (df["mqtt.topic_len"] > 0)
    http_pkts = (df["http.content_length"] > 0) | (df["http.tls_port"] > 0)
    modbus_pkts = (df["mbtcp.len"] > 0) | (df["mbtcp.trans_id"] > 0)

    protocol_counts = pd.Series({
        "TCP Core": tcp_pkts.sum(),
        "UDP Datagram": udp_pkts.sum(),
        "ICMP Control": icmp_pkts.sum(),
        "MQTT (IoT Telemetry)": mqtt_pkts.sum(),
        "HTTP / Web Services": http_pkts.sum(),
        "Modbus TCP (Industrial)": modbus_pkts.sum()
    }).sort_values(ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6), facecolor='#091017')
    ax.set_facecolor('#0d1722')
    colors = ['#06b6d4', '#f59e0b', '#14b8a6', '#a855f7', '#3b82f6', '#ec4899']

    wedges, texts, autotexts = ax.pie(  # type: ignore
        protocol_counts.values,
        labels=protocol_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=colors,
        wedgeprops=dict(width=0.45, edgecolor='#091017', linewidth=2),
        pctdistance=0.75
    )
    for text in texts:
        text.set_color('#cbd5e1')
        text.set_fontsize(10)
    for autotext in autotexts:
        autotext.set_color('#ffffff')
        autotext.set_fontsize(10)
        autotext.set_weight('bold')

    ax.set_title('Edge-IIoTset: Phân Tách Lưu Lượng Theo Giao Thức Mạng & IoT', fontsize=14, fontweight='bold', color='#38bdf8', pad=15)
    plt.tight_layout()
    chart2_path = os.path.join(OUTPUT_CHARTS_DIR, "02_iot_protocols_breakdown.png")
    plt.savefig(chart2_path, dpi=300, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  -> Đã lưu: {chart2_path}")

    # =========================================================================
    # VẼ BIỂU ĐỒ 3: MA TRẬN TƯƠNG QUAN (CORRELATION HEATMAP) CÁC ĐẶC TRƯNG CHÍNH
    # =========================================================================
    print("[6/6] Đang vẽ Biểu đồ 3: Ma trận tương quan đặc trưng (Feature Correlation)...")
    key_features = [
        "tcp.connection.syn",
        "tcp.flags.ack",
        "tcp.len",
        "tcp.dstport",
        "udp.stream",
        "icmp.transmit_timestamp",
        "mqtt.len",
        "mbtcp.len",
        "http.content_length",
        "Attack_label"
    ]
    # Lấy mẫu ngẫu nhiên 30,000 dòng để tính tương quan nhanh và chính xác
    sub_df = df[key_features].dropna().sample(30000, random_state=42).astype(float)
    corr = sub_df.corr()

    fig, ax = plt.subplots(figsize=(11, 9), facecolor='#091017')
    ax.set_facecolor('#0d1722')

    sns.heatmap(
        corr,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        vmin=-0.4,
        vmax=1.0,
        linewidths=0.5,
        linecolor='#091017',
        cbar_kws={"shrink": 0.8},
        ax=ax
    )
    ax.set_title('Ma Trận Tương Quan (Pearson Correlation) Giữa Các Đặc Trưng & Nhãn Tấn Công', fontsize=13, fontweight='bold', color='#38bdf8', pad=15)
    plt.xticks(rotation=45, ha='right', color='#cbd5e1', fontsize=9.5)
    plt.yticks(color='#cbd5e1', fontsize=9.5)

    plt.tight_layout()
    chart3_path = os.path.join(OUTPUT_CHARTS_DIR, "03_feature_correlation_heatmap.png")
    plt.savefig(chart3_path, dpi=300, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  -> Đã lưu: {chart3_path}")

    print("\n" + "=" * 75)
    print(" [THÀNH CÔNG] BÁO CÁO EDA ĐÃ ĐƯỢC TẠO HOÀN TẤT!")
    print(f"  * Thư mục biểu đồ: {OUTPUT_CHARTS_DIR}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_eda()
