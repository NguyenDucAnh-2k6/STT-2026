#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Model Training Pipeline
============================================================
Huấn luyện mô hình học máy phát hiện bất thường và phân loại tấn công lưu lượng mạng:
 1. Isolation Forest (Unsupervised Anomaly Detection): Nhận diện độ lệch khỏi baseline mạng bình thường.
 2. Decision Tree / Light Classifier (Supervised): Phân loại chính xác dạng tấn công (SYN Flood, Port Scan, DDoS, Exfiltration).
 3. Xuất model weights và scaler sang thư mục ml_engine/models/.
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
import joblib

# Danh sách đặc trưng (Features) tối ưu cho thiết bị biên Edge
FEATURE_NAMES = [
    "packet_rate",       # Tốc độ gói tin/giây
    "byte_rate",         # Tốc độ byte/giây
    "avg_packet_size",   # Kích thước gói tin trung bình (bytes)
    "syn_ratio",         # Tỷ lệ cờ SYN trong TCP (0.0 -> 1.0)
    "ack_ratio",         # Tỷ lệ cờ ACK trong TCP (0.0 -> 1.0)
    "udp_ratio",         # Tỷ lệ gói UDP (0.0 -> 1.0)
    "icmp_ratio",        # Tỷ lệ gói ICMP (0.0 -> 1.0)
    "unique_dst_ports"   # Số lượng port đích trong cửa sổ lấy mẫu
]

LABEL_NAMES = ["Normal", "SYN_Flood", "Port_Scan", "Volumetric_DDoS", "Data_Exfiltration"]
LABEL_MAP = {name: idx for idx, name in enumerate(LABEL_NAMES)}

def generate_synthetic_dataset(n_samples: int = 10000, random_state: int = 42) -> pd.DataFrame:
    """
    Sinh tập dữ liệu lưu lượng mạng mô phỏng chuẩn CIC-IDS2017 / NSL-KDD
    được gom cụm phù hợp với bộ trích xuất đặc trưng của ESP32.
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
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, 0])

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
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, 1])

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
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, 2])

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
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, 3])

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
        data.append([packet_rate, byte_rate, avg_pkt_size, syn_ratio, ack_ratio, udp_ratio, icmp_ratio, unique_ports, 4])

    df = pd.DataFrame(data, columns=FEATURE_NAMES + ["label"])
    return df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

def train_pipeline():
    output_dir = os.path.join(os.path.dirname(__file__), "models")
    dataset_dir = os.path.join(os.path.dirname(__file__), "datasets")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(dataset_dir, exist_ok=True)

    print("=" * 65)
    print("  EDGE AI NETWORK ANOMALY DETECTION - TRAINING PIPELINE")
    print("=" * 65)

    # 1. Sinh tập dữ liệu huấn luyện
    print("\n[1/4] Sinh tap du lieu luu luong mang mau (10,000 mau)...")
    df = generate_synthetic_dataset(n_samples=10000)
    csv_path = os.path.join(dataset_dir, "synthetic_traffic_dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"  -> Da luu dataset tai: {csv_path}")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # 2. Chuẩn hóa đặc trưng
    print("\n[2/4] Chuan hoa dac trung (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 3. Huấn luyện mô hình không giám sát (Isolation Forest)
    # Lấy dữ liệu Normal để mô hình học phân bố bình thường
    print("\n[3/4] Huan luyen mo hinh Isolation Forest (Unsupervised Anomaly Detector)...")
    X_normal_train = X_train_scaled[y_train == 0]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.03,  # Tỷ lệ ngoại lai ước lượng trong tập normal
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_normal_train)

    # Đánh giá Isolation Forest trên toàn bộ tập test
    # Điểm anomaly_score càng âm -> càng bất thường
    test_scores = iso_forest.score_samples(X_test_scaled)
    # Chuyển đổi thành xác suất bất thường trong khoảng [0, 1]
    norm_scores = 1.0 - (test_scores - test_scores.min()) / (test_scores.max() - test_scores.min() + 1e-8)
    preds_binary = (iso_forest.predict(X_test_scaled) == -1).astype(int)
    actual_binary = (y_test != 0).astype(int)
    iso_f1 = f1_score(actual_binary, preds_binary)
    print(f"  -> Isolation Forest Binary F1-Score: {iso_f1:.4f}")

    # 4. Huấn luyện bộ phân loại dạng tấn công (Lightweight Multi-class Decision Tree)
    # Cây quyết định cực nhẹ, tối ưu để convert sang C-code chạy trên Edge
    print("\n[4/4] Huan luyen bo phan loai tan cong (Decision Tree / Edge Optimized)...")
    clf = DecisionTreeClassifier(
        max_depth=6,
        min_samples_split=5,
        min_samples_leaf=3,
        random_state=42
    )
    clf.fit(X_train, y_train)  # Train trực tiếp trên raw features để dễ convert C code
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  -> Decision Tree Accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES))

    # 5. Lưu models và metadata
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(scaler, scaler_path)
    joblib.dump(iso_forest, iso_path)
    joblib.dump(clf, clf_path)

    metadata = {
        "features": FEATURE_NAMES,
        "labels": LABEL_NAMES,
        "decision_tree_accuracy": float(acc),
        "isolation_forest_f1": float(iso_f1),
        "isolation_score_min": float(test_scores.min()),
        "isolation_score_max": float(test_scores.max())
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print("=" * 65)
    print(f" [OK] Huan luyen thanh cong! Cac file mo hinh da san sang tai: {output_dir}")
    print("=" * 65)

if __name__ == "__main__":
    train_pipeline()
