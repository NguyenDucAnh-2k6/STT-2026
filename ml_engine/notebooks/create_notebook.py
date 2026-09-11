import json
import os

notebook = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Khám Phá & Phân Tích Chuyên Sâu Bộ Dữ Liệu An Ninh Mạng IoT/IIoT (Edge-IIoTset)\n",
                "## Nghiên cứu đặc trưng lưu lượng mạng, phân phối tấn công và chiến lược thu gọn đặc trưng cho thiết bị biên (ESP32 TinyML)\n",
                "\n",
                "---\n",
                "\n",
                "### 1. Giới Thiệu Bộ Dữ Liệu Edge-IIoTset\n",
                "**Edge-IIoTset** là bộ dữ liệu an ninh mạng chuẩn quốc tế (IEEE Access 2022) được thiết kế đặc thù cho môi trường mạng Internet vạn vật (IoT) và IoT công nghiệp (IIoT). Bộ dữ liệu được thu thập trên mô hình mạng thực nghiệm Testbed đa tầng bao gồm:\n",
                "- **Thiết bị cảm biến IoT**: ESP32, Raspberry Pi, cảm biến ngọn lửa, độ ẩm đất, nồng độ pH, nhịp tim, siêu âm khoảng cách, nhiệt độ & độ ẩm.\n",
                "- **Giao thức công nghiệp & IoT**: Modbus TCP/IP, MQTT, CoAP, HTTP, DNS, ARP.\n",
                "- **14 Kịch bản tấn công thực tế**: DDoS (TCP SYN, UDP, ICMP, HTTP), Port Scanning, Backdoor, Password Brute-force, Ransomware, SQL Injection, XSS, MITM (ARP spoofing + DNS), Uploading, OS Fingerprinting, Vulnerability Scanning.\n",
                "\n",
                "### 2. Vấn Đề Lựa Chọn Tệp Dữ Liệu (Dataset File Selection)\n",
                "> **Câu hỏi:** Trong thư mục `datasets/Edge-IIoTset dataset`, chúng ta nên dùng các file như thế nào? Dùng file trong `Selected dataset for ML and DL` có bị mất thông tin hữu ích so với các file `.csv` thô trong `Attack traffic` và `Normal traffic` không?\n",
                ">\n",
                "> **Kết luận khoa học:**\n",
                "> 1. **Schema 100% Đồng nhất (63 Features):** Cả tệp `ML-EdgeIIoT-dataset.csv` lẫn từng tệp CSV thô trong `Attack traffic` đều sở hữu cùng một tập 63 cột đặc trưng từ tầng Network, Transport đến IoT Application (TCP flags, MQTT, Modbus, HTTP, ICMP...). **Không hề có bất kỳ đặc trưng nào bị mất.**\n",
                "> 2. **Giải quyết vấn đề Class Imbalance cực đoan:** Các tệp thô trong `Attack traffic` nặng tới hàng chục Gigabytes (ví dụ riêng file ICMP Flood là 892 MB chứa hàng chục triệu gói tin ICMP trùng lặp). Nếu gộp thô, mô hình sẽ bị thiên lệch (bias) 95% vào DDoS và mất hoàn toàn khả năng nhận diện các cuộc tấn công tinh vi (Port Scan, Backdoor, MITM).\n",
                "> 3. **Tệp được chuẩn hóa chính thức (Gold Standard):** `ML-EdgeIIoT-dataset.csv` (157,800 dòng, ~82 MB) là bộ mẫu phân tầng (stratified sample) được chính các tác giả bài báo khoa học xây dựng để phục vụ huấn luyện và kiểm thử các giải thuật Machine Learning đạt hiệu năng cao nhất."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 1. Khai báo thư viện và thiết lập giao diện\n",
                "import os\n",
                "import sys\n",
                "import numpy as np\n",
                "import pandas as pd\n",
                "import matplotlib.pyplot as plt\n",
                "import seaborn as sns\n",
                "\n",
                "# Cấu hình giao diện Dark Theme Cyber SOC hiện đại\n",
                "plt.style.use('dark_background')\n",
                "plt.rcParams['font.sans-serif'] = 'DejaVu Sans'\n",
                "plt.rcParams['axes.edgecolor'] = '#1f3344'\n",
                "plt.rcParams['axes.linewidth'] = 1.0\n",
                "plt.rcParams['grid.color'] = '#162330'\n",
                "plt.rcParams['grid.linestyle'] = '--'\n",
                "plt.rcParams['grid.alpha'] = 0.6\n",
                "\n",
                "# Đường dẫn tệp dữ liệu chuẩn\n",
                "DATASET_PATH = os.path.join(\n",
                "    \"..\", \"datasets\", \"Edge-IIoTset dataset\",\n",
                "    \"Selected dataset for ML and DL\", \"ML-EdgeIIoT-dataset.csv\"\n",
                ")\n",
                "\n",
                "print(f\"Đường dẫn dataset: {os.path.abspath(DATASET_PATH)}\")\n",
                "print(f\"Tệp tồn tại: {os.path.exists(DATASET_PATH)}\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 3. Tải Dữ Liệu & Kiểm Tra Cấu Trúc Tổng Quan (Schema Inspection)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 2. Tải 157,800 dòng dữ liệu\n",
                "df = pd.read_csv(DATASET_PATH, low_memory=False)\n",
                "\n",
                "print(f\"Số lượng dòng (Records)  : {df.shape[0]:,}\")\n",
                "print(f\"Số lượng cột (Features)  : {df.shape[1]}\")\n",
                "print(f\"Dung lượng bộ nhớ (RAM)  : {df.memory_usage().sum() / (1024**2):.2f} MB\\n\")\n",
                "\n",
                "# Kiểm tra 5 dòng đầu tiên\n",
                "df[['ip.src_host', 'tcp.dstport', 'tcp.flags.ack', 'tcp.connection.syn', 'Attack_type', 'Attack_label']].head()"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 3. Kiểm tra kiểu dữ liệu và kiểm tra giá trị khuyết (Missing Values)\n",
                "print(\"Phân bố kiểu dữ liệu:\")\n",
                "print(df.dtypes.value_counts())\n",
                "\n",
                "null_total = df.isnull().sum().sum()\n",
                "print(f\"\\nTổng số giá trị khuyết (Missing/Null values): {null_total}\")\n",
                "if null_total == 0:\n",
                "    print(\"-> [HOÀN HẢO] Dữ liệu đã được tiền xử lý sạch sẽ, không có bất kỳ ô trống nào!\")"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 4. Phân Tích Phân Phối Nhãn Tấn Công (Label & Threat Class Distribution)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 4. Thống kê phân bố nhị phân (Binary) và đa lớp (Multi-class)\n",
                "attack_counts = df['Attack_type'].value_counts()\n",
                "binary_counts = df['Attack_label'].value_counts()\n",
                "\n",
                "print(\"=== PHÂN BỐ NHỊ PHÂN (ATTACK LABEL) ===\")\n",
                "print(f\"- 0 (Normal) : {binary_counts.get(0, 0):>7,} ({binary_counts.get(0, 0)/len(df)*100:.2f}%)\")\n",
                "print(f\"- 1 (Attack) : {binary_counts.get(1, 0):>7,} ({binary_counts.get(1, 0)/len(df)*100:.2f}%)\")\n",
                "\n",
                "print(\"\\n=== PHÂN BỐ CHI TIẾT 14 LOẠI TẤN CÔNG (ATTACK TYPE) ===\")\n",
                "for atk, cnt in attack_counts.items():\n",
                "    print(f\"- {atk:<25}: {cnt:>6,} mẫu ({cnt/len(df)*100:>5.2f}%)\")"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 5. Trực quan hóa phân bố các loại tấn công bằng Horizontal Bar Chart\n",
                "fig, ax = plt.subplots(figsize=(12, 7), facecolor='#091017')\n",
                "ax.set_facecolor('#0d1722')\n",
                "\n",
                "colors = [\n",
                "    '#10b981' if x == 'Normal' \n",
                "    else '#ef4444' if 'DDoS' in x \n",
                "    else '#f59e0b' if 'Scan' in x \n",
                "    else '#a855f7' for x in attack_counts.index\n",
                "]\n",
                "\n",
                "y_pos = np.arange(len(attack_counts))\n",
                "bars = ax.barh(y_pos, attack_counts.values, color=colors, edgecolor='#ffffff', alpha=0.85, height=0.7)\n",
                "\n",
                "ax.set_yticks(y_pos)\n",
                "ax.set_yticklabels(attack_counts.index, fontsize=11, fontweight='semibold')\n",
                "ax.invert_yaxis()\n",
                "ax.set_xlabel('Số lượng gói tin / mẫu (Packet Records)', fontsize=12, color='#94a3b8', labelpad=10)\n",
                "ax.set_title('Edge-IIoTset: Phân Phối 14 Loại Tấn Công & Lưu Lượng Bình Thường (Normal)', fontsize=14, fontweight='bold', color='#38bdf8', pad=15)\n",
                "ax.grid(axis='x', alpha=0.3)\n",
                "\n",
                "for bar in bars:\n",
                "    width = bar.get_width()\n",
                "    pct = width / len(df) * 100\n",
                "    ax.text(width + 600, bar.get_y() + bar.get_height()/2, f\"{int(width):,} ({pct:.1f}%)\",\n",
                "            va='center', ha='left', fontsize=9.5, color='#e2e8f0', fontweight='bold')\n",
                "\n",
                "plt.tight_layout()\n",
                "plt.show()"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 5. Phân Tách Theo Tầng Giao Thức (Protocol Layer Breakdown)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 6. Đánh giá tỷ lệ lưu lượng giữa các giao thức mạng và giao thức IoT công nghiệp\n",
                "tcp_pkts = (df[\"tcp.connection.syn\"] > 0) | (df[\"tcp.flags.ack\"] > 0) | (df[\"tcp.len\"] > 0)\n",
                "udp_pkts = (df[\"udp.stream\"] > 0) | (df[\"udp.port\"] > 0)\n",
                "icmp_pkts = (df[\"icmp.checksum\"] > 0) | (df[\"icmp.seq_le\"] > 0)\n",
                "mqtt_pkts = (df[\"mqtt.len\"] > 0) | (df[\"mqtt.topic_len\"] > 0)\n",
                "http_pkts = (df[\"http.content_length\"] > 0) | (df[\"http.tls_port\"] > 0)\n",
                "modbus_pkts = (df[\"mbtcp.len\"] > 0) | (df[\"mbtcp.trans_id\"] > 0)\n",
                "\n",
                "protocol_counts = pd.Series({\n",
                "    \"TCP Core\": tcp_pkts.sum(),\n",
                "    \"UDP Datagram\": udp_pkts.sum(),\n",
                "    \"ICMP Control\": icmp_pkts.sum(),\n",
                "    \"MQTT (IoT Telemetry)\": mqtt_pkts.sum(),\n",
                "    \"HTTP / Web Services\": http_pkts.sum(),\n",
                "    \"Modbus TCP (Industrial)\": modbus_pkts.sum()\n",
                "}).sort_values(ascending=False)\n",
                "\n",
                "# Vẽ Donut Chart\n",
                "fig, ax = plt.subplots(figsize=(8, 8), facecolor='#091017')\n",
                "ax.set_facecolor('#0d1722')\n",
                "proto_colors = ['#06b6d4', '#f59e0b', '#14b8a6', '#a855f7', '#3b82f6', '#ec4899']\n",
                "\n",
                "wedges, texts, autotexts = ax.pie(  # type: ignore\n",
                "    protocol_counts.values,\n",
                "    labels=protocol_counts.index,\n",
                "    autopct='%1.1f%%',\n",
                "    startangle=140,\n",
                "    colors=proto_colors,\n",
                "    wedgeprops=dict(width=0.45, edgecolor='#091017', linewidth=2),\n",
                "    pctdistance=0.75\n",
                ")\n",
                "for text in texts:\n",
                "    text.set_color('#cbd5e1')\n",
                "    text.set_fontsize(11)\n",
                "for autotext in autotexts:\n",
                "    autotext.set_color('#ffffff')\n",
                "    autotext.set_fontsize(10.5)\n",
                "    autotext.set_weight('bold')\n",
                "\n",
                "ax.set_title('Edge-IIoTset: Tỷ Lệ Giao Thức Mạng & Giao Thức IoT Ứng Dụng', fontsize=14, fontweight='bold', color='#38bdf8', pad=15)\n",
                "plt.tight_layout()\n",
                "plt.show()"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 6. Ma Trận Tương Quan Đặc Trưng & Phân Tích Dấu Hiệu Tấn Công"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 7. Trích xuất ma trận tương quan giữa các đặc trưng giao vận cốt lõi và nhãn tấn công\n",
                "key_features = [\n",
                "    \"tcp.connection.syn\",\n",
                "    \"tcp.flags.ack\",\n",
                "    \"tcp.len\",\n",
                "    \"tcp.dstport\",\n",
                "    \"udp.stream\",\n",
                "    \"icmp.transmit_timestamp\",\n",
                "    \"mqtt.len\",\n",
                "    \"mbtcp.len\",\n",
                "    \"http.content_length\",\n",
                "    \"Attack_label\"\n",
                "]\n",
                "\n",
                "sub_df = df[key_features].dropna().sample(30000, random_state=42).astype(float)\n",
                "corr = sub_df.corr()\n",
                "\n",
                "fig, ax = plt.subplots(figsize=(10, 8), facecolor='#091017')\n",
                "ax.set_facecolor('#0d1722')\n",
                "\n",
                "sns.heatmap(\n",
                "    corr,\n",
                "    annot=True,\n",
                "    fmt=\".2f\",\n",
                "    cmap=\"coolwarm\",\n",
                "    vmin=-0.4,\n",
                "    vmax=1.0,\n",
                "    linewidths=0.5,\n",
                "    linecolor='#091017',\n",
                "    cbar_kws={\"shrink\": 0.8},\n",
                "    ax=ax\n",
                ")\n",
                "ax.set_title('Ma Trận Tương Quan (Pearson Correlation) Các Đặc Trưng Mạng', fontsize=13, fontweight='bold', color='#38bdf8', pad=15)\n",
                "plt.xticks(rotation=45, ha='right', color='#cbd5e1', fontsize=9.5)\n",
                "plt.yticks(color='#cbd5e1', fontsize=9.5)\n",
                "plt.tight_layout()\n",
                "plt.show()"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 7. Chiến Lược Ánh Xạ Về 8 Đặc Trưng Cốt Lõi Cho EdgeGuard (TinyML ESP32)\n",
                "\n",
                "Vi điều khiển ESP32 và máy tính Host Sniffer không thể tính toán toàn bộ 63 đặc trưng cồng kềnh trong thời gian thực (< 15ms). Vì vậy, hệ thống **EdgeGuard AI** rút gọn thành **8 đặc trưng thống kê cửa sổ thời gian (Sliding Window)**:\n",
                "\n",
                "| STT | Đặc Trưng EdgeGuard | Nguồn tương đương trong Edge-IIoTset | Ý nghĩa An ninh mạng |\n",
                "| :--- | :--- | :--- | :--- |\n",
                "| 1 | `packet_rate` | Tần suất gói tin trên cửa sổ thời gian | Nhận diện DDoS, Flood dồn dập |\n",
                "| 2 | `byte_rate` | `tcp.len` + header / time delta | Phát hiện truyền tải dữ liệu lớn, exfiltration |\n",
                "| 3 | `avg_packet_size` | `tcp.len` trung bình | Phân biệt gói SYN nhỏ (60B) vs gói tin dữ liệu |\n",
                "| 4 | `syn_ratio` | `tcp.connection.syn` | Nhận diện SYN Flood, Port Scanning |\n",
                "| 5 | `ack_ratio` | `tcp.flags.ack` | Đo lường độ ổn định của các luồng TCP thiết lập |\n",
                "| 6 | `udp_ratio` | `udp.stream` > 0 | Phát hiện UDP Flood, DNS Amplification |\n",
                "| 7 | `icmp_ratio` | `icmp.checksum` > 0 | Phát hiện Ping of Death, ICMP Flood |\n",
                "| 8 | `unique_dst_ports`| Số cổng duy nhất `tcp.dstport` | Nhận diện quét cổng (Port Scan / Network Recon) |\n",
                "\n",
                "Hãy cùng kiểm tra phân phối của các đặc trưng cốt lõi này:"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# 8. So sánh đặc trưng cờ SYN và cổng đích giữa Normal, SYN Flood, và Port Scan\n",
                "sample_types = ['Normal', 'DDoS_TCP', 'Port_Scanning', 'DDoS_UDP']\n",
                "sample_df = df[df['Attack_type'].isin(sample_types)].copy()\n",
                "\n",
                "fig, axes = plt.subplots(1, 2, figsize=(14, 5), facecolor='#091017')\n",
                "\n",
                "# Biểu đồ 1: Cờ SYN theo từng loại tấn công\n",
                "sns.barplot(data=sample_df, x='Attack_type', y='tcp.connection.syn', ax=axes[0], palette=['#10b981', '#ef4444', '#f59e0b', '#06b6d4'])\n",
                "axes[0].set_title('Tỷ Lệ Kích Hoạt Cờ TCP SYN', fontsize=12, color='#38bdf8', fontweight='bold')\n",
                "axes[0].set_ylabel('SYN Activation (Mean)', color='#94a3b8')\n",
                "axes[0].set_facecolor('#0d1722')\n",
                "\n",
                "# Biểu đồ 2: Kích thước gói tin (tcp.len)\n",
                "sns.barplot(data=sample_df, x='Attack_type', y='tcp.len', ax=axes[1], palette=['#10b981', '#ef4444', '#f59e0b', '#06b6d4'])\n",
                "axes[1].set_title('Độ Dài Gói Tin TCP (tcp.len)', fontsize=12, color='#38bdf8', fontweight='bold')\n",
                "axes[1].set_ylabel('Payload Length (Bytes)', color='#94a3b8')\n",
                "axes[1].set_facecolor('#0d1722')\n",
                "\n",
                "plt.tight_layout()\n",
                "plt.show()"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "--- \n",
                "### 8. Hướng Dẫn Tích Hợp Vào Optuna HPO & Huấn Luyện Final Model\n",
                "\n",
                "Bộ dữ liệu `ML-EdgeIIoT-dataset.csv` đã sẵn sàng và được tích hợp trực tiếp vào pipeline huấn luyện của hệ thống. Bạn có thể kích hoạt quá trình tối ưu hóa siêu tham số (Optuna HPO 5-Fold Stratified Cross-Validation) bằng các câu lệnh dòng lệnh sau:\n",
                "\n",
                "```bash\n",
                "# 1. Tối ưu hóa Random Forest với 20 trials trên dataset Edge-IIoTset:\n",
                "python ml_engine/tuning/optuna_tuner.py --model random_forest --n-trials 20 --dataset \"ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv\"\n",
                "\n",
                "# 2. Tối ưu hóa Decision Tree và tự động xuất C Header TinyML cho ESP32:\n",
                "python ml_engine/tuning/optuna_tuner.py --model decision_tree --n-trials 25 --export-tinyml --dataset \"ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv\"\n",
                "\n",
                "# 3. Huấn luyện mô hình kết hợp Ensemble Voting (RandomForest + ExtraTrees + GradientBoosting):\n",
                "python ml_engine/tuning/optuna_tuner.py --model ensemble_voting --n-trials 15 --dataset \"ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL/ML-EdgeIIoT-dataset.csv\"\n",
                "\n",
                "# 4. Khởi động Master Launcher chạy toàn bộ hệ thống kèm Dashboard và mô hình đã tối ưu:\n",
                "python run_system.py --classifier ensemble_voting\n",
                "```"
            ]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.12.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 5
}

output_path = os.path.join("ml_engine", "notebooks", "EDA_Edge_IIoTset.ipynb")
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=2, ensure_ascii=False)

print(f"Created Jupyter Notebook EDA successfully at: {output_path}")
