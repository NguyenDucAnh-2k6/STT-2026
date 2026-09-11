# AERO - Hệ Thống Edge AI Phát Hiện Bất Thường Lưu Lượng Mạng

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![ESP32 Compatible](https://img.shields.io/badge/Hardware-ESP32%20%7C%20ESP32--S3-brightgreen.svg)](https://www.espressif.com/)
[![MQTT Mosquitto](https://img.shields.io/badge/MQTT-Mosquitto%203.1.1-orange.svg)](https://mosquitto.org/)

Hệ thống giám sát và phát hiện bất thường an ninh mạng thời gian thực dựa trên kiến trúc **Edge AI**. Dự án kết hợp thiết bị biên vi điều khiển (ESP32) hoạt động ở chế độ Promiscuous Mode, giao thức truyền tải siêu nhẹ MQTT (Mosquitto), mô hình học máy phát hiện dị biệt (Isolation Forest) kết hợp TinyML nhúng trực tiếp on-device, cùng giao diện giám sát SOC (Security Operations Center) hiện đại thời gian thực.

Hệ thống sử dụng bộ dữ liệu an ninh mạng công nghiệp chuẩn **Edge-IIoTset** với cấu trúc trọn vẹn **63 đặc trưng** (61 đặc trưng mạng đầu vào từ tầng Network, Transport đến IoT Application và 15 lớp nhãn tấn công). Kiến trúc dự án được phân tách triệt để giữa **Quy trình Huấn luyện & HPO Offline** và **Phiên Vận hành Suy luận Thời gian thực (Runtime Inference)**.

---

## 🌟 Tính Năng Nổi Bật

- **Bắt gói tin biên (Edge Promiscuous Sniffing)**: ESP32 bắt trực tiếp các khung WiFi 802.11, trích xuất đặc trưng lưu lượng mạng thời gian thực mà không cần can thiệp hạ tầng mạng phức tạp.
- **Dữ liệu chuẩn Edge-IIoTset (Full 63 Features)**: Mô hình hỗ trợ học trên toàn bộ 61 đặc trưng lưu lượng mạng và phân loại chính xác 15 nhãn tấn công (DDoS UDP/TCP/HTTP/ICMP, SQL Injection, Ransomware, Port Scanning, Backdoor, Vulnerability Scanner, MITM, XSS...).
- **Tối ưu hóa siêu tham số tự động (Optuna HPO)**:
  - Tích hợp Stratified $K$-Fold Cross-Validation (`--cv [N]`).
  - Giao diện log chuẩn Optuna trực quan (`[I ...]`).
  - Tự động sao lưu và duy trì toàn bộ lịch sử thử nghiệm vào SQLite database (`optuna_study.db`).
- **Mô hình học máy kép (Dual AI Pipeline)**:
  - **Isolation Forest (Unsupervised)**: Học trên lưu lượng bình thường để phát hiện các bất thường Zero-day chưa từng biết trước.
  - **Attack Classifier (Supervised & TinyML)**: Phân loại cụ thể danh mục cuộc tấn công với độ chính xác vượt trội.
- **TinyML On-Device Ready**: Công cụ chuyển đổi tự động xuất mã nguồn C Header (`tinyml_model.h`), cho phép nhúng trực tiếp cây quyết định vào ESP32 để suy luận 100% on-chip với thời gian thực thi $< 50\,\mu s$.
- **Kiến trúc tách bạch (Zero-Training in Runtime)**: Phiên vận hành `run_system.py` thuần túy nạp các Artifacts đã được huấn luyện sẵn, khởi động tức thì, có cơ chế cảnh báo và hướng dẫn nếu thiếu Artifacts.
- **SOC Web Dashboard Real-time**: Giao diện Cyberpunk Glassmorphism Dark Mode tuyệt đẹp, biểu đồ Chart.js cập nhật trực tiếp qua WebSocket.
- **Đa dạng nguồn Telemetry (Multi-Probe)**: Hỗ trợ linh hoạt 3 nguồn dữ liệu: Bộ giả lập ESP32 Simulator, Host PC Sniffer (bắt card mạng thật của máy tính) hoặc phần cứng ESP32 thật qua WiFi/MQTT.

---

## 🏗️ Kiến Trúc Hệ Thống

```
┌───────────────────────────────────────────────────────────────┐
│                    NGUỒN DỮ LIỆU TELEMETRY                    │
│  [ESP32 WiFi Sniffer]  │  [Host PC Sniffer]  │  [Simulator]  │
└───────────────────────────────┬───────────────────────────────┘
                                │ MQTT: edge/telemetry/traffic
                                ▼
               ┌─────────────────────────────────┐
               │ Mosquitto MQTT Broker (Port 1883)│
               └────────────────┬────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
┌───────────────────────────────┐       ┌───────────────────────────────┐
│   ML REAL-TIME INFERENCE      │       │   FASTAPI & WEBSOCKET BACKEND │
│  (Loads Pre-trained Artifacts)│       │          (Port 8000)          │
│ ┌───────────────────────────┐ │       └───────────────┬───────────────┘
│ │ Preprocessor (Standardize)│ │                       │
│ └─────────────┬─────────────┘ │                       │
│ ┌─────────────▼─────────────┐ │                       │
│ │ Tier 1: Isolation Forest  │ │                       │
│ └─────────────┬─────────────┘ │                       │
│ ┌─────────────▼─────────────┐ │                       │
│ │ Tier 2: Attack Classifier │ │                       │
│ └───────────────────────────┘ │                       │
└───────────────┬───────────────┘                       │
                │ MQTT: edge/telemetry/prediction       │
                └───────────────────────────────────────┘
                                │ WebSocket: /ws/telemetry
                                ▼
               ┌─────────────────────────────────┐
               │ SOC Web Dashboard (Cyberpunk UI)│
               └─────────────────────────────────┘
```

---

## 🚀 Khởi Động Nhanh (Quick Start)

### 1. Cài đặt môi trường Python
```bash
pip install -r requirements.txt
```

### 2. Huấn luyện mô hình và xuất Artifacts (Thực hiện lần đầu)
Trước khi khởi chạy hệ thống lần đầu, bạn cần huấn luyện mô hình để sinh các file trọng số (Artifacts):
```bash
# Huấn luyện Decision Tree với toàn bộ 61 đặc trưng Edge-IIoTset:
python ml_engine/train.py --classifier decision_tree
```
*(Hoặc tối ưu siêu tham số chuyên sâu với Optuna: xem chi tiết tại [Phần 1](#-phần-1-tối-ưu-siêu-tham-số-hpo--huấn-luyện-offline)).*

### 3. Khởi chạy toàn bộ hệ sinh thái chỉ bằng 1 lệnh duy nhất!

Hệ thống hỗ trợ Entry Points trên mọi hệ điều hành:

- **Trên Windows (Command Prompt / PowerShell)**:
  ```cmd
  run_system.bat
  ```
- **Trên Linux / macOS / WSL**:
  ```bash
  chmod +x run_system.sh
  ./run_system.sh
  ```
- **Hoặc chạy trực tiếp qua Python**:
  ```bash
  python run_system.py
  ```

Trình duyệt sẽ tự động mở trang SOC Dashboard tại: **`http://localhost:8000`**

---

## 🔬 PHẦN 1: Tối Ưu Siêu Tham Số (HPO) & Huấn Luyện Offline

Module huấn luyện được tách biệt hoàn toàn khỏi phiên vận hành, chịu trách nhiệm nạp dữ liệu chuẩn hóa, tìm kiếm siêu tham số tốt nhất, huấn luyện mô hình cuối cùng và xuất toàn bộ artifacts vào thư mục `ml_engine/models/`.

### Cách 1: Tối ưu siêu tham số bằng Optuna (`optuna_tuner.py`)

Module `optuna_tuner.py` sử dụng thuật toán Bayesian Optimization (TPE Sampler) để tối đa hóa chỉ số Macro F1-Score trên toàn bộ các lớp tấn công.

#### Điểm đặc biệt:
1. **Log chuẩn Optuna**: Hiển thị log chi tiết `[I ...]` trực tiếp trên terminal với thông tin từng trial và tham số tốt nhất.
2. **Stratified K-Fold CV qua cờ `--cv [N]`**: Đánh giá khách quan qua phân tầng $K$-Fold (mặc định: 5) mà không cần chia tách riêng một tập holdout test.
3. **Sao lưu SQLite (`optuna_study.db`)**: Toàn bộ lịch sử các trial được lưu tự động vào database SQLite tại `ml_engine/models/optuna_study.db`, cho phép dừng, tiếp tục hoặc sao lưu kết quả dễ dàng.
4. **Tự động huấn luyện Final Model & Xuất Artifacts**: Sau khi hoàn thành các trial, Optuna tự động lấy `best_params` để huấn luyện Final Model trên **toàn bộ dữ liệu**, fit mô hình Isolation Forest trên các mẫu `Normal` và xuất trọn bộ artifacts cho `run_system.py`.

#### Cú pháp sử dụng:
```bash
# Tối ưu Decision Tree với 15 trials và 5-Fold CV:
python ml_engine/tuning/optuna_tuner.py --model decision_tree --n-trials 15 --cv 5

# Tối ưu Random Forest trên toàn bộ 157,800 mẫu:
python ml_engine/tuning/optuna_tuner.py --model random_forest --n-trials 20 --cv 5

# Tối ưu nhanh với mẫu 30,000 dòng dữ liệu:
python ml_engine/tuning/optuna_tuner.py --model decision_tree --sample-size 30000 --cv 5

# Tối ưu mô hình mạng nơ-ron đa tầng MLP hoặc Gradient Boosting:
python ml_engine/tuning/optuna_tuner.py --model mlp --n-trials 10 --cv 3
python ml_engine/tuning/optuna_tuner.py --model gradient_boosting --n-trials 15 --cv 5
```

---

### Cách 2: Huấn luyện offline trực tiếp qua `train.py`

Script `train.py` là pipeline huấn luyện chính, hỗ trợ cả huấn luyện nhanh với tham số mặc định hoặc kích hoạt Optuna HPO.

#### Cú pháp sử dụng:
```bash
# Xem danh sách tất cả các thuật toán Classifier và Anomaly Detector hỗ trợ:
python ml_engine/train.py --list-models

# Huấn luyện Decision Tree trên toàn bộ dataset và xuất mã nguồn C TinyML cho ESP32:
python ml_engine/train.py --classifier decision_tree

# Huấn luyện Random Forest với kích thước mẫu 25,000 dòng:
python ml_engine/train.py --classifier random_forest --samples 25000

# Tích hợp chạy Optuna HPO 5-Fold Stratified CV ngay trong train.py:
python ml_engine/train.py --classifier decision_tree --optuna --n-trials 15 --cv 5

# Huấn luyện mô hình Anomaly Detector khác (One-Class SVM, LOF, Elliptic Envelope):
python ml_engine/train.py --classifier decision_tree --anomaly-model one_class_svm
```

#### Các Artifacts sinh ra trong `ml_engine/models/`:
- `attack_classifier.joblib`: Trọng số mô hình phân loại tấn công đã huấn luyện.
- `isolation_forest.joblib`: Trọng số mô hình phát hiện bất thường Unsupervised.
- `preprocessor.joblib` / `scaler.joblib`: Bộ tiền xử lý (OrdinalEncoder + StandardScaler cho 61 đặc trưng).
- `model_metadata.json`: Metadata cấu hình (danh sách 61 đặc trưng, 15 nhãn, siêu tham số, độ chính xác F1).
- `optuna_study.db`: Cơ sở dữ liệu SQLite lưu trữ toàn bộ lịch sử thử nghiệm HPO.
- `tinyml_model.h`: Tệp mã nguồn C Header chứa cấu trúc cây quyết định nhúng cho firmware ESP32.

---

## ⚡ PHẦN 2: Khởi Chạy Toàn Bộ Hệ Thống (Artifact Loading & Live Inference)

Phiên chạy `run_system.py` là trung tâm vận hành runtime của hệ sinh thái.

### Cơ chế hoạt động:
1. **Hoàn toàn KHÔNG huấn luyện trong runtime (Zero Training Overhead)**: `run_system.py` hoạt động ở chế độ suy luận thuần túy, đảm bảo khởi động siêu tốc và ổn định.
2. **Tự động nạp Artifacts đã có**: Hệ thống kiểm tra các tệp `attack_classifier.joblib`, `scaler.joblib` và `model_metadata.json` trong `ml_engine/models/`.
3. **Cơ chế nhắc nhở thông minh (Smart Reminder)**: Nếu chưa tìm thấy artifacts (chưa chạy Phần 1), hệ thống sẽ hiển thị bảng thông báo nổi bật hướng dẫn chi tiết lệnh cần chạy và dừng tiến trình an toàn:
   ```text
   ============================================================================
     [NHAC NHO QUAN TRONG] CHUA TIM THAY ARTIFACTS MO HINH MACHINE LEARNING!
   ============================================================================
     He thong van hanh (run_system.py) hoat dong o che do suy luan thuan tuy,
     khong con tu dong huan luyen de dam bao tinh on dinh va toc do khoi dong.

     Vui long chay quy trinh huan luyen offline truoc de tao artifacts:
         python ml_engine/train.py --classifier decision_tree

     Hoac toi uu hoa sieu tham so (HPO) voi Optuna:
         python ml_engine/tuning/optuna_tuner.py --model decision_tree --cv 5

     Sau khi huan luyen thanh cong va xuat artifacts, hay chay lai:
         python run_system.py
   ============================================================================
   ```
4. **Khởi động đồng bộ 4 tiến trình nền**:
   - MQTT Broker (Port 1883).
   - Real-time Inference Engine (`inference_service.py`): Nhận telemetry, chuẩn hóa qua 61 đặc trưng, suy luận kép 2 tầng với độ trễ $< 1.5\,\text{ms}$.
   - FastAPI Backend & WebSocket Broadcaster (Port 8000).
   - Telemetry Probe (mặc định: Simulator tự động phát luồng dữ liệu).

#### Cú pháp khởi chạy:
```bash
# 1. Khởi chạy tiêu chuẩn (Mặc định dùng ESP32 Simulator tự đổi kịch bản demo):
python run_system.py

# 2. Khởi chạy bắt luồng mạng thật của máy tính (Live PC Network Sniffer):
python run_system.py --probe host

# 3. Khởi chạy đón dữ liệu từ bo mạch ESP32 thật qua WiFi/MQTT:
python run_system.py --probe esp32

# 4. Tùy chỉnh ngưỡng cảnh báo Anomaly Score (mặc định 0.55):
python run_system.py --threshold 0.65

# 5. Khởi chạy không tự động bật trình duyệt:
python run_system.py --no-browser
```

---

## 🛠️ Vận Hành Thủ Công Từng Thành Phần (Manual Execution)

Nếu bạn muốn mở từng terminal riêng biệt để quan sát log chi tiết từng tầng:

### Bước 1: Khởi động MQTT Broker
- **Sử dụng Embedded Python Broker (Không cần cài đặt thêm)**:
  ```bash
  python broker/embedded_broker.py
  ```
- **Hoặc sử dụng Docker Mosquitto**:
  ```bash
  cd broker && docker-compose up -d
  ```

### Bước 2: Chạy Service suy luận thời gian thực
```bash
python ml_engine/inference_service.py --threshold 0.55
```

### Bước 3: Khởi động Web Dashboard Server
```bash
python dashboard/backend/app.py
```
Truy cập giao diện: `http://localhost:8000`

### Bước 4: Chạy nguồn phát Telemetry
- **Bộ giả lập ESP32 Simulator (Auto-cycle mode)**:
  ```bash
  python firmware/simulator/esp32_simulator.py --auto-cycle
  ```
- **Hoặc bắt lưu lượng thật từ card mạng máy tính (Host Sniffer)**:
  ```bash
  python firmware/host_probe/host_sniffer.py
  ```
- **Hoặc bo mạch ESP32 vật lý**:
  Xem hướng dẫn nạp code tại: [docs/ESP32_FLASHING_GUIDE.md](file:///d:/STT%202026/docs/ESP32_FLASHING_GUIDE.md)

---

## 📂 Cấu Trúc Thư Mục Dự Án (Modular Architecture)

```
d:\STT 2026\
├── firmware\
│   ├── esp32_probe\
│   │   ├── esp32_probe.ino            # Mã nguồn Arduino C++ cho ESP32 bắt gói tin & TinyML
│   │   ├── config.h                   # Cấu hình WiFi SSID, Pass, MQTT Broker IP
│   │   └── tinyml_model.h             # Mô hình TinyML C Header được cập nhật tự động
│   ├── host_probe\
│   │   └── host_sniffer.py            # Bắt lưu lượng mạng thật từ card mạng máy tính (Scapy)
│   └── simulator\
│       └── esp32_simulator.py         # Giả lập ESP32 phát traffic đa kịch bản
├── broker\
│   ├── mosquitto.conf                 # Cấu hình chuẩn Eclipse Mosquitto
│   ├── docker-compose.yml             # Chạy Mosquitto nhanh bằng Docker
│   └── embedded_broker.py             # Embedded pure Python MQTT broker dự phòng
├── ml_engine\
│   ├── config\
│   │   ├── __init__.py
│   │   └── schema.py                  # Khai báo FULL 61 Features, 15 Labels Edge-IIoTset & Defaults
│   ├── preprocessing\
│   │   ├── __init__.py
│   │   ├── edge_iiotset_preprocessor.py # Xử lý dữ liệu full 63 cột, OrdinalEncoder, StandardScaler
│   │   ├── feature_preprocessor.py    # Wrapper tương thích ngược và trích xuất vector
│   │   └── dataset_generator.py       # Bộ sinh dữ liệu synthetic traffic đa kịch bản
│   ├── tuning\
│   │   ├── __init__.py
│   │   └── optuna_tuner.py            # Optuna HPO với Stratified K-Fold CV & SQLite backup
│   ├── algorithms\
│   │   ├── base.py                    # Base protocol cho Classifier & Anomaly Detector
│   │   ├── classifiers.py             # DecisionTree, RandomForest, ExtraTrees, GradientBoosting, MLP...
│   │   └── anomaly_detectors.py       # IsolationForest, OneClassSVM, EllipticEnvelope, LOF
│   ├── exporter\
│   │   └── tinyml_exporter.py         # Chuyển đổi mô hình sang C Header (ESP32 TinyML)
│   ├── notebooks\
│   │   ├── EDA_Edge_IIoTset.ipynb     # Jupyter Notebook phân tích chuyên sâu Edge-IIoTset
│   │   ├── generate_eda_report.py     # Script xuất biểu đồ EDA SOC Aesthetic
│   │   └── eda_charts\                # Thư mục chứa các biểu đồ phân tích dữ liệu
│   ├── datasets\                      # Thư mục chứa dataset Edge-IIoTset CSV
│   ├── models\                        # Thư mục chứa Artifacts đã huấn luyện
│   │   ├── attack_classifier.joblib   # Trọng số mô hình phân loại tấn công
│   │   ├── isolation_forest.joblib    # Trọng số mô hình phát hiện bất thường
│   │   ├── preprocessor.joblib        # Bộ tiền xử lý (Encoders + Scaler)
│   │   ├── scaler.joblib              # Weights của StandardScaler
│   │   ├── model_metadata.json        # Thông số cấu hình & kết quả đánh giá mô hình
│   │   ├── optuna_study.db            # Cơ sở dữ liệu SQLite lưu trữ lịch sử trials Optuna
│   │   └── tinyml_model.h             # Tệp header C sinh ra cho vi điều khiển
│   ├── train.py                       # CLI huấn luyện offline độc lập & xuất artifacts
│   └── inference_service.py           # Service suy luận thời gian thực 2 tầng qua MQTT
├── dashboard\
│   ├── backend\
│   │   └── app.py                     # FastAPI server, WebSocket broadcaster & REST APIs
│   └── frontend\
│       ├── index.html                 # Giao diện SOC Dashboard Cyberpunk Dark Mode
│       ├── css\style.css              # Glassmorphism styling, animations & theme
│       └── js\app.js                  # WebSocket client, Chart.js visualizations
├── docs\                              # Tài liệu kỹ thuật kiến trúc, API và ESP32
├── run_system.py                      # Runtime Master Launcher (Inference Only, loads artifacts)
├── run_system.bat                     # Entry point Windows Command Prompt / Batch
├── run_system.sh                      # Entry point Linux / macOS / WSL Shell Script
├── test_pipeline.py                   # Automated Integration Pipeline Test
├── requirements.txt                   # Danh sách thư viện Python
└── README.md                          # Tài liệu hướng dẫn toàn diện dự án
```

---

## 📊 Danh Mục 15 Lớp Tấn Công Chuẩn Edge-IIoTset

| Nhãn Tấn Công (Label) | Danh Mục Mạng / Tầng Giao Thức | Hành Vi & Dấu Hiệu Đặc Trưng |
|---|---|---|
| **Normal** | Toàn bộ các tầng mạng | Lưu lượng truy cập an toàn, bình thường, Anomaly Score $< 0.35$ |
| **DDoS_UDP** | Transport Layer (UDP) | Bão gói tin UDP áp đảo làm cạn kiệt băng thông đường truyền |
| **DDoS_ICMP** | Network Layer (ICMP) | Ping flood / Smurf attack gửi dồn dập gói tin ICMP Echo Request |
| **DDoS_TCP** | Transport Layer (TCP) | SYN Flood / Connection Flood làm tràn hàng đợi backlog |
| **DDoS_HTTP** | Application Layer (HTTP) | Tấn công dồn dập HTTP GET/POST làm tê liệt Web Server |
| **Port_Scanning** | Network Reconnaissance | Quét dò các cổng mở phân tán trên thiết bị IoT / Industrial Gateway |
| **Vulnerability_scanner**| Reconnaissance & Audit | Quét tìm các lỗ hổng dịch vụ mạng và phần mềm lỗi thời |
| **SQL_injection** | Application Layer (Database) | Chèn câu lệnh SQL độc hại qua HTTP request params nhằm đọc/ghi DB |
| **XSS** | Application Layer (Web) | Tiêm mã kịch bản độc hại (Cross-site Scripting) vào ứng dụng web |
| **Ransomware** | Host & File System | Mã độc tống tiền mã hóa dữ liệu máy trạm / SCADA |
| **Backdoor** | Command & Control (C2) | Thiết lập cổng sau ngầm để kiểm soát thiết bị từ xa |
| **Uploading** | Application Layer (Web/FTP) | Tải tệp tin thực thi độc hại (Web Shell, Malware) lên máy chủ |
| **Password** | Authentication Brute-force | Tấn công vét cạn mật khẩu SSH, Telnet, HTTP Basic Auth |
| **MITM** | Data Link / ARP Spoofing | Tấn công nhiễm độc ARP (ARP Poisoning) chặn bắt dữ liệu giữa chừng |
| **Fingerprinting** | Reconnaissance (OS/Service) | Dò quét chữ ký hệ điều hành và phiên bản dịch vụ mạng đang chạy |

---

## 🧪 Kiểm Thử Tích Hợp Tự Động (Integration Test)

Để kiểm tra tính toàn vẹn của toàn bộ luồng kết nối Broker $\rightarrow$ Inference $\rightarrow$ Prediction $\rightarrow$ Alert:
```bash
python test_pipeline.py
```
Kết quả kiểm thử thành công sẽ in thông báo:
```text
Testing end-to-end pipeline...
[InferenceEngine] Da load thanh cong: [decision_tree] + [isolation_forest]!
Direct inference assertion passed: Anomaly detected, threat = Port_Scanning, latency = 59.51 ms
MQTT End-to-end verified! Received 2 messages on subscribed topics.
[ALL TESTS PASSED SUCCESSFULLY!]
```

---

## 📜 Giấy Phép (License)
Dự án được phát hành theo giấy phép [MIT License](LICENSE).
