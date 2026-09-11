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
┌─────────────────────────────────────────────────────────────────────────────┐
│                       NGUỒN DỮ LIỆU TELEMETRY (PROBES)                      │
│   [ESP32 WiFi Sniffer]   │   [Host PC Sniffer]   │   [ESP32 Simulator]      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ MQTT: edge/telemetry/traffic
                                       ▼
                      ┌─────────────────────────────────┐
                      │ Mosquitto MQTT Broker (Port 1883)│
                      └────────────────┬────────────────┘
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
┌───────────────────────────────┐       ┌────────────────────────────────────────────────┐
│   ML REAL-TIME INFERENCE      │       │   MODULAR FASTAPI & WEBSOCKET BACKEND (8000)   │
│  (Loads Pre-trained Artifacts)│       │ ┌────────────────────────────────────────────┐ │
│ ┌───────────────────────────┐ │       │ │ MQTT Bridge -> WebSocket ConnectionManager │ │ │
│ │ Preprocessor (Standardize)│ │       │ └─────────────────────┬──────────────────────┘ │
│ └─────────────┬─────────────┘ │       │ ┌─────────────────────▼──────────────────────┐ │
│ ┌─────────────▼─────────────┐ │       │ │ Routers: REST APIs (/api/*) & WS (/ws/*)   │ │
│ │ Tier 1: Isolation Forest  │ │       │ └────────────────────────────────────────────┘ │
│ └─────────────┬─────────────┘ │       └───────────────────────┬────────────────────────┘
│ ┌─────────────▼─────────────┐ │                               │
│ │ Tier 2: Attack Classifier │ │                               │
│ └───────────────────────────┘ │                               │
└───────────────┬───────────────┘                               │
                │ MQTT: edge/telemetry/prediction               │
                └───────────────────────────────────────────────┘
                                │ WebSocket: /ws/telemetry
                                ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│            SOC WEB DASHBOARD (MODULAR COMPONENT-BASED FRONTEND)                │
│ ┌───────────────────┐ ┌───────────────────┐ ┌────────────────────────────────┐ │
│ │ Header & Audio    │ │ KPI Grid Cards    │ │ Interactive Control Bar        │ │
│ └───────────────────┘ └───────────────────┘ └────────────────────────────────┘ │
│ ┌───────────────────┐ ┌───────────────────┐ ┌────────────────────────────────┐ │
│ │ Chart.js Analytics│ │ Dual AI Assessment│ │ Live Wireshark Flow Inspector  │ │
│ └───────────────────┘ └───────────────────┘ └────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 🧩 Phân Tầng Kiến Trúc Decoupled (Decoupled Layering):
1. **Telemetry Probes**: Tách biệt hoàn toàn phần cứng/giả lập khỏi hệ thống phân tích. Tất cả các probe (`esp32_simulator.py`, `host_sniffer.py`) là các module độc lập, được nạp trực tiếp qua `run_system.py`.
2. **AI Inference & Offline Training**:
   - `ml_engine/train.py` là **Entrypoint Offline duy nhất**: Tiền xử lý full 61 features, Optuna HPO, fit 100% dữ liệu và xuất TinyML C Header (`--export-tinyml-only`).
   - `ml_engine/inference_service.py` là **Runtime Daemon**: Tự động nhận biến môi trường, suy luận 2 tầng trong $< 1.5\,\text{ms}$.
3. **Modular Backend**:
   - `dashboard/backend/`: Không còn file monolithic. Được module hóa thành `config.py`, `models.py`, `state.py`, `websocket_manager.py`, `mqtt_bridge.py` và `routers/` (`api.py`, `ws.py`).
4. **Component-Based Frontend**:
   - `dashboard/frontend/js/`: Sử dụng kiến trúc **Native ES Modules** (không cần bundle/build step). State được quản lý tập trung qua `state.js` (Event Bus), tách bạch các `services/` (WebSocket, Audio API, REST API) và 6 `components/` UI độc lập.

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

## 🔬 PHẦN 1: Tối Ưu Siêu Tham Số (HPO) & Huấn Luyện Offline (`train.py`)

Kể từ phiên bản này, **`ml_engine/train.py` là Entrypoint Duy Nhất** cho toàn bộ quy trình thí nghiệm, tối ưu hóa siêu tham số (HPO) và huấn luyện mô hình offline. 

Module **`ml_engine/tuning/optuna_tuner.py`** thuần túy đóng vai trò là **thư viện thuật toán** (định nghĩa Search Space, cấu hình Pruners, hàm mục tiêu Stratified $K$-Fold CV và quản lý lưu trữ SQLite), được `train.py` import tự động khi kích hoạt cờ `--optuna`.

### Kiến trúc Pipeline Huấn luyện End-to-End (`train.py`):
1. **Nạp & Chuẩn hóa Toàn bộ Dữ liệu**: Nạp trọn vẹn 61 đặc trưng lưu lượng mạng Edge-IIoTset từ `ml_engine/preprocessing/`. Không chia tách riêng tập test split: toàn bộ dữ liệu được tận dụng tối đa cho Cross-Validation và huấn luyện mô hình biên.
2. **Tối ưu hóa Siêu Tham số (Optuna HPO)** *(tùy chọn với `--optuna`)*:
   - Thuật toán Bayesian Optimization (TPE Sampler) tìm kiếm bộ tham số tối đa hóa Macro F1-Score.
   - Đánh giá khách quan qua Stratified $K$-Fold Cross-Validation (`--cv [N]`, mặc định: 5).
   - Log chuẩn Optuna trực quan (`[I 2026-...] Trial {n} finished with value...`) hiển thị trực tiếp trên console.
   - Tự động sao lưu persistent state vào SQLite database (`ml_engine/models/optuna_study.db`).
   - Tùy biến thuật toán cắt tỉa sớm (`--pruner median|percentile|hyperband|none`).
3. **Huấn luyện Final Model**: Fit lại mô hình Classifier trên **100% dữ liệu** với bộ tham số tốt nhất (Best Hyperparameters) vừa tìm được.
4. **Huấn luyện Anomaly Detector**: Fit mô hình Unsupervised (Isolation Forest) trên toàn bộ mẫu lưu lượng an toàn (`Normal`).
5. **Xuất Trọn Bộ Artifacts & TinyML Header**: Tự động lưu các file joblib, metadata JSON, và sinh mã nguồn C Header (`tinyml_model.h`) cho firmware ESP32.

---

### Các Kịch Bản Sử Dụng `train.py`:

#### 1. Huấn luyện nhanh với siêu tham số mặc định:
```bash
# Huấn luyện Decision Tree trên toàn bộ dữ liệu và xuất C Header TinyML cho ESP32:
python ml_engine/train.py --classifier decision_tree

# Huấn luyện Random Forest với kích thước mẫu 30,000 dòng:
python ml_engine/train.py --classifier random_forest --samples 30000
```

#### 2. Huấn luyện End-to-End kết hợp Optuna HPO:
```bash
# Tối ưu Decision Tree với 20 trials và 5-Fold Stratified CV:
python ml_engine/train.py --classifier decision_tree --optuna --n-trials 20 --cv 5

# Tối ưu Random Forest trên toàn bộ dữ liệu Edge-IIoTset:
python ml_engine/train.py --classifier random_forest --optuna --n-trials 15 --cv 5

# Tối ưu kết hợp thuật toán cắt tỉa sớm Hyperband:
python ml_engine/train.py --classifier decision_tree --optuna --n-trials 30 --pruner hyperband
```

#### 3. Thử nghiệm các kiến trúc học máy khác:
```bash
# Mạng nơ-ron đa tầng MLP:
python ml_engine/train.py --classifier mlp --optuna --n-trials 10 --cv 3

# Gradient Boosting:
python ml_engine/train.py --classifier gradient_boosting --samples 30000 --optuna --n-trials 15

# Mô hình kết hợp Ensemble Voting (RandomForest + ExtraTrees + GradientBoosting):
python ml_engine/train.py --classifier ensemble_voting --optuna --n-trials 10

# Thay đổi mô hình Anomaly Detector (One-Class SVM, LOF, Elliptic Envelope):
python ml_engine/train.py --classifier decision_tree --anomaly-model one_class_svm
```

#### 4. Xem danh mục tất cả các thuật toán hỗ trợ:
```bash
python ml_engine/train.py --list-models
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
          python ml_engine/train.py --classifier decision_tree --optuna --cv 5

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
python ml_engine/inference_service.py
```
*(Lưu ý: Entrypoint dòng lệnh tập trung để tùy chỉnh `--threshold`, `--broker-port` là `python run_system.py`)*

### Bước 3: Khởi động Web Dashboard Server
```bash
python dashboard/backend/app.py
```
Truy cập giao diện: `http://localhost:8000`

### Bước 4: Chạy nguồn phát Telemetry
- **Bộ giả lập ESP32 Simulator**:
  ```bash
  python firmware/simulator/esp32_simulator.py
  ```
- **Hoặc bắt lưu lượng thật từ card mạng máy tính (Host Sniffer)**:
  ```bash
  python firmware/host_probe/host_sniffer.py
  ```
- **Hoặc bo mạch ESP32 vật lý**:
  Xem hướng dẫn nạp code tại: [docs/ESP32_FLASHING_GUIDE.md](file:///d:/STT%202026/docs/ESP32_FLASHING_GUIDE.md)

---

## 📂 Cấu Trúc Thư Mục Dự Án (Decoupled Modular Architecture)

```
d:\STT 2026\
├── firmware\
│   ├── esp32_probe\
│   │   ├── esp32_probe.ino            # Mã nguồn Arduino C++ cho ESP32 bắt gói tin & TinyML
│   │   ├── config.h                   # Cấu hình WiFi SSID, Pass, MQTT Broker IP
│   │   └── tinyml_model.h             # Mô hình TinyML C Header được cập nhật tự động
│   ├── host_probe\
│   │   └── host_sniffer.py            # Bắt lưu lượng mạng thật từ máy tính (Module cho run_system)
│   └── simulator\
│       └── esp32_simulator.py         # Giả lập phát traffic đa kịch bản (Module cho run_system)
├── broker\
│   ├── mosquitto.conf                 # Cấu hình chuẩn Eclipse Mosquitto
│   ├── docker-compose.yml             # Chạy Mosquitto nhanh bằng Docker
│   └── embedded_broker.py             # Embedded pure Python MQTT broker (Module cho run_system)
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
│   │   └── optuna_tuner.py            # Thư viện hàm Optuna HPO (Search Space, Pruners, K-Fold CV & SQLite)
│   ├── algorithms\
│   │   ├── base.py                    # Base protocol cho Classifier & Anomaly Detector
│   │   ├── classifiers.py             # DecisionTree, RandomForest, ExtraTrees, GradientBoosting, MLP...
│   │   └── anomaly_detectors.py       # IsolationForest, OneClassSVM, EllipticEnvelope, LOF
│   ├── exporter\
│   │   ├── __init__.py
│   │   └── tinyml_exporter.py         # Chuyển đổi mô hình sang C Header (ESP32 TinyML)
│   ├── export_tinyml.py               # Tiện ích export TinyML (CLI tập trung tại: train.py --export-tinyml-only)
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
│   ├── train.py                       # Master Training Pipeline (Entrypoint duy nhất: HPO + Final Model + Artifacts)
│   └── inference_service.py           # Service suy luận thời gian thực 2 tầng qua MQTT
├── dashboard\
│   ├── backend\
│   │   ├── app.py                     # FastAPI root application, lifespan & router coordinator
│   │   ├── config.py                  # Cấu hình biến môi trường (MQTT_HOST, MQTT_PORT, PORT)
│   │   ├── models.py                  # Pydantic schema models cho REST API
│   │   ├── state.py                   # In-memory SystemState (history, alerts, connected nodes)
│   │   ├── websocket_manager.py       # ConnectionManager quản lý WebSocket clients & broadcast
│   │   ├── mqtt_bridge.py             # MQTT subscriber bridge chuyển tiếp sang WebSocket
│   │   └── routers\
│   │       ├── api.py                 # REST API endpoints (/api/status, /api/simulator/scenario, etc.)
│   │       └── ws.py                  # WebSocket endpoint (/ws/telemetry)
│   └── frontend\
│       ├── index.html                 # Semantic HTML Layout, nạp script type="module"
│       ├── css\style.css              # Cyberpunk Glassmorphism Styling & Design System
│       └── js\
│           ├── main.js                # Root Application Coordinator (ES Modules Entrypoint)
│           ├── state.js               # Centralized Reactive State Store & Pub/Sub Event Bus
│           ├── services\
│           │   ├── api_service.js     # REST API client (Fetch kịch bản, ngưỡng threshold)
│           │   ├── websocket_service.js # WebSocket client kết nối /ws/telemetry tự động reconnect
│           │   └── audio_service.js   # Web Audio API Synthesizer (còi báo động SOC & alert beeps)
│           └── components\
│               ├── header.js          # Connection status dot, nodes online, audio alarm toggle
│               ├── kpi_grid.js        # 4 thẻ KPI (Packet Rate, Byte Rate, Anomaly Score, Threats)
│               ├── control_bar.js     # Interactive Attack Simulator control buttons
│               ├── charts.js          # Chart.js 3 biểu đồ (Throughput, Protocol, Anomaly) & Threshold Slider
│               ├── risk_assessment.js # Phán quyết Edge TinyML, Phân phối xác suất 15 lớp, Pipeline Flow
│               └── packet_inspector.js# Bảng bắt gói tin Wireshark-Style thời gian thực, filter & clear
├── docs\                              # Tài liệu kỹ thuật kiến trúc, API và ESP32
├── run_system.py                      # Master Runtime Launcher (Nhập trực tiếp broker & probes, quản lý tập trung)
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
