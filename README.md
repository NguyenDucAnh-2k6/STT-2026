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
- **ESP32 Bắt Mọi Mạng Độc Lập (All-Networks Sniffing & Channel Hopping)**: Thoát ly ràng buộc chỉ bắt được mạng Access Point mà máy tính kết nối. Chế độ `SNIFFER_MODE_ALL_NETWORKS` mở khóa phần cứng radio ESP32, nhảy kênh liên tục (Ch 1..13 mỗi 300ms) để thu thập lưu lượng từ mọi Access Point và thiết bị xung quanh trong không gian.
- **Bắn gói tin mạng thật (100% Real Socket Injection)**: Không dùng số liệu giả lập ảo. Module `attack_traffic_generator.py` mở socket thật bắn các luồng gói tin TCP SYN, UDP Flood, HTTP Probe, Exfiltration Data ra mạng thật. Cả Host Sniffer và ESP32 đều thực sự bắt được các gói tin này trong thực tế.
- **Data Lakehouse Pipeline (Parquet Partitioned & SQLite Catalog)**: Tự động thu thập và lưu trữ toàn bộ luồng telemetry mạng từ các phiên vận hành hàng ngày vào kho lưu trữ định dạng chuẩn Parquet (nén Snappy, phân vùng theo ngày `data_lake/raw/date=YYYY-MM-DD/`). Quản lý metadata và session qua SQLite Catalog (`data_lake/catalog.db`).
- **Học Tăng Cường Baseline Thực Tế (Hybrid Real-World Training)**: Khả năng tái huấn luyện mô hình kết hợp `--data-source hybrid`: Isolation Forest học trực tiếp trên baseline lưu lượng bình thường thực tế của môi trường xung quanh được tích lũy trong Data Lakehouse, triệt tiêu hoàn toàn tỷ lệ báo động giả (False Positives) do lệch phân phối.
- **Điều khiển trực tiếp On-Demand từ SOC Web Dashboard**: Khi kích hoạt `--attack-sim`, thanh Control Bar trên Dashboard cung cấp cụm nút bấm tương ứng các kịch bản mã độc, cho phép người dùng click chuột phát động tấn công thật ra mạng ngay tức thì và quan sát phản ứng của AI.
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
- **Đa dạng nguồn Telemetry (Multi-Probe)**: Mặc định bắt card mạng thật từ máy tính (`--probe host`) hoặc phần cứng ESP32 thật qua WiFi/MQTT (`--probe esp32`).

---

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       NGUỒN DỮ LIỆU TELEMETRY (PROBES)                      │
│   [ESP32 WiFi Promiscuous]               │   [Host PC Live Sniffer]         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ MQTT: edge/telemetry/traffic
                                       ▼
                      ┌─────────────────────────────────┐
                      │ Mosquitto MQTT Broker (Port 1883)│ ◄───┐
                      └────────────────┬────────────────┘     │
                                       │                      │ edge/attack/control
         ┌─────────────────────────────┴──────────┐           │ (Lệnh phát động)
         ▼                                        ▼           │
┌───────────────────────────────┐  ┌───────────────────────────────┐  │
│   ML REAL-TIME INFERENCE      │  │   MODULAR FASTAPI BACKEND     │──┘
│  (Loads Pre-trained Artifacts)│  │ ┌───────────────────────────┐ │
│ ┌───────────────────────────┐ │  │ │ REST API & WebSocket Br.  │ │
│ │ Preprocessor (Standardize)│ │  │ └─────────────┬─────────────┘ │
│ └─────────────┬─────────────┘ │  └───────────────┼───────────────┘
│ ┌─────────────▼─────────────┐ │                  │ WebSocket
│ │ Tier 1: Isolation Forest  │ │                  ▼
│ └─────────────┬─────────────┘ │  ┌───────────────────────────────┐
│ ┌─────────────▼─────────────┐ │  │   SOC WEB DASHBOARD (UI)      │
│ │ Tier 2: Attack Classifier │ │  │ ┌───────────────────────────┐ │
│ └───────────────────────────┘ │  │ │ Control Bar: Nút Bấm      │ │
└───────────────┬───────────────┘  │ │ Kích Hoạt Tấn Công Thật   │ │
                │                  │ └───────────────────────────┘ │
                │                  └───────────────────────────────┘
                │
                │ MQTT: edge/attack/control
                ▼
┌────────────────────────────────────────────────────────┐
│  ATTACK TRAFFIC GENERATOR (Module Bắn Gói Tin Thật)    │
│  - Bắn Socket TCP SYN, UDP Flood, Vuln Probe ra mạng   │
│  - Host Sniffer / ESP32 thật bắt được ngay trên mạng   │
└────────────────────────────────────────────────────────┘
```

---

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
# Huấn luyện Decision Tree chuẩn hoặc Hybrid kết hợp Data Lakehouse:
python ml_engine/train.py --classifier decision_tree --data-source hybrid
```
*(Hoặc tối ưu siêu tham số chuyên sâu với Optuna: xem chi tiết tại [Phần 1](#-phần-1-tối-ưu-siêu-tham-số-hpo--huấn-luyện-offline)).*

### 3. Khởi chạy toàn bộ hệ sinh thái chỉ bằng 1 lệnh duy nhất!

Hệ thống hỗ trợ Entry Points trên mọi hệ điều hành (**Windows, Linux, macOS, WSL**) với cơ chế **Zero-Config Wi-Fi**: Tự động nhận diện tên mạng Wi-Fi, mật khẩu và IP LAN của máy chủ ngầm để cấu hình cho thiết bị mà không cần nhập tay!

- **Trên Windows (Command Prompt / PowerShell)**:
  ```cmd
  run_system.bat
  ```
  *Hoặc 1-click tự động build & nạp code firmware cho ESP32 qua cổng USB:*
  ```cmd
  run_system.bat --probe esp32 --attack-sim --flash
  ```

- **Trên Linux / macOS / WSL**:
  ```bash
  chmod +x run_system.sh
  ./run_system.sh
  ```
  *Hoặc nạp firmware ESP32 qua CLI trên Linux/macOS:*
  ```bash
  ./run_system.sh --probe esp32 --attack-sim --flash --port /dev/ttyUSB0
  ```

- **Hoặc khởi chạy trực tiếp qua Python**:
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

### 🧠 Danh Mục & Cơ Chế Hoạt Động Các Mô Hình Học Máy (ML / DL Engine)

Hệ thống AERO trang bị kiến trúc AI 2 tầng: **Tier 1 - Phát hiện bất thường không giám sát (Unsupervised Anomaly Detection)** và **Tier 2 - Phân loại chi tiết cuộc tấn công có giám sát (Supervised Attack Classification)**. Dưới đây là phân tích chi tiết cơ chế hoạt động và ngữ cảnh dữ liệu khuyến nghị cho từng thuật toán:

#### 1. Bộ Phân Loại Cuộc Tấn Công (Supervised Classifiers - 15 Lớp Tấn Công)

| Thuật Toán (`--classifier`) | Cơ Chế Huấn Luyện & Suy Luận | Đặc Tính & Khả Năng Nhúng Biên | Khuyến Nghị Sử Dụng Về Dữ Liệu |
| :--- | :--- | :--- | :--- |
| **`decision_tree`** *(Mặc định)* | **Train**: Xây dựng cây quyết định nhị phân phân tách theo chỉ số Gini/Entropy.<br>**Inference**: Duyệt cây điều kiện `if (feature > threshold)` tuần tự. | **100% TinyML Edge-Ready**.<br>Biên dịch tự động sang mã nguồn C Header (`tinyml_model.h`).<br>Độ trễ: $< 50\,\mu s$ trên ESP32, $< 0.1\,\text{ms}$ trên Host.<br>RAM: $< 25\,\text{KB}$. | **Dữ liệu biên và thiết bị phần cứng tài nguyên thấp (ESP32/MCU)**. Phù hợp với lưu lượng mạng có các ngưỡng chia cắt hành vi phân định rõ ràng (đột biến `packet_rate`, cờ `syn_ratio`, `unique_dst_ports`). |
| **`xgboost`** | **Train**: Gradient Boosting tối ưu hóa theo Hessian & Gradient cấp 2, kiểm soát quá khớp qua L1/L2 regularization.<br>**Inference**: Tính tổng trọng số lá cây song song hóa cao độ. | **Host / Edge Server Ready**.<br>Hiệu năng vượt trội, độ chính xác $> 93\%$, Macro F1 $> 89\%$.<br>Tích hợp early stopping và xử lý dữ liệu thưa.<br>Độ trễ: $\sim 0.6\,\text{ms}$. RAM: $\sim 15\,\text{MB}$. | **Lưu lượng mạng thực tế đa dạng**, chống nhiễu mạnh, tối ưu cho bài toán phát hiện các cuộc tấn công tinh vi (Port Scan, Vulnerability Scan, SQL Injection). |
| **`lightgbm`** | **Train**: Light Gradient Boosting Machine sử dụng Histogram-based binning và thuật toán phát triển lá theo chiều sâu (Leaf-wise).<br>**Inference**: Tra cứu bin nhanh trên CPU. | **Host / Cloud SOC**.<br>Tốc độ huấn luyện siêu tốc (nhanh nhất trong các dòng GBDT).<br>Tiết kiệm RAM vượt bậc.<br>Độ trễ: $\sim 0.4\,\text{ms}$. RAM: $\sim 10\,\text{MB}$. | **Bộ dữ liệu lưu lượng lớn (Big Data / Lakehouse)** với hàng trăm nghìn mẫu telemetry, cần tốc độ huấn luyện và suy luận nhanh. |
| **`catboost`** | **Train**: Categorical Boosting sử dụng Symmetric (Oblivious) Trees, chống target leakage và overfitting trên tập dữ liệu nhỏ.<br>**Inference**: Cây đối xứng cho tốc độ đánh giá cực nhanh trên CPU. | **Host / Server High Stability**.<br>Độ ổn định cao nhất, không cần tinh chỉnh quá nhiều siêu tham số.<br>Độ trễ: $\sim 0.8\,\text{ms}$. | **Môi trường triển khai sản xuất** yêu cầu độ tin cậy cao, ít bị trôi dạt dữ liệu (concept drift). |
| **`pytorch_deep` / `dnn`** | **Train**: Mạng nơ-ron sâu PyTorch đa tầng (Dense 256 -> 128 -> 64 -> 15) với BatchNorm, Dropout(0.3), AdamW Optimizer và CosineAnnealingLR. Tự động vẽ và xuất biểu đồ `loss_curve.png`.<br>**Inference**: Lan truyền tiến PyTorch qua GPU/CPU. | **Host / GPU / NPU Acceleration**.<br>Tự động nạp bộ dữ liệu lớn chuyên biệt `DNN-EdgeIIoT-dataset.csv` (1.2GB).<br>Trực quan hóa Train vs Val Loss qua từng Epoch.<br>Độ trễ: $\sim 1.0\,\text{ms}$. | **Lưu lượng mạng có mối tương quan phi tuyến tính sâu** giữa nhiều tầng giao thức (Application, Transport, Network) mà mô hình tuyến tính không biểu diễn được. |
| **`random_forest`** | **Train**: Tập hợp $N$ cây quyết định độc lập (Bagging) với Bootstrap Sampling.<br>**Inference**: Trung bình cộng xác suất đa số. | **Host/Server Only**.<br>Khả năng tổng quát hóa cao, không bị quá khớp.<br>Độ trễ: $\sim 1.2\,\text{ms}$. | **Lưu lượng mạng thực tế phức tạp, nhiều nhiễu**, làm baseline đối chiếu cho các dòng mô hình boosting. |
| **`extra_trees`** | **Train**: Random Forest cực đoan chọn ngưỡng ngẫu nhiên.<br>**Inference**: Tập hợp xác suất cây cực đoan. | **Host/Server Only**.<br>Tốc độ huấn luyện nhanh gấp đôi Random Forest.<br>Độ trễ: $\sim 1.0\,\text{ms}$. | **Huấn luyện nhanh trên tập dữ liệu lưu lượng lớn**. |
| **`ensemble_voting`** | **Train**: Huấn luyện đồng thời Decision Tree, Random Forest và XGBoost.<br>**Inference**: Soft-Voting trung bình cộng xác suất. | **Host SOC Center**.<br>Độ tin cậy và điểm Macro F1 cao nhất.<br>Độ trễ: $\sim 2.5\,\text{ms}$. | **Trung tâm SOC phân tích sự cố an ninh nghiêm trọng**. |


---

#### 2. Bộ Phát Hiện Bất Thường Không Giám Sát (Unsupervised Anomaly Detectors)

| Thuật Toán (`--anomaly-model`) | Cơ Chế Hoạt Động & Tính Điểm | Đặc Tính Kỹ Thuật | Khuyến Nghị Sử Dụng Về Dữ Liệu |
| :--- | :--- | :--- | :--- |
| **`isolation_forest`** *(Mặc định)* | **Cơ chế**: Cô lập điểm dị biệt bằng cách cắt ngẫu nhiên các đặc trưng. Mẫu bất thường (Anomaly) nằm thưa thớt ở rìa nên bị cô lập với số lần cắt (Path Length) ngắn hơn nhiều so với mẫu bình thường.<br>**Điểm số**: Chuẩn hóa từ độ dài hành trình trung bình thành dải điểm `[0.0, 1.0]`. Điểm $> 0.55$ là bất thường. | **Rất nhẹ, tốc độ huấn luyện $O(n \log n)$**.<br>Tương thích hoàn hảo với dữ liệu mạng nhiều chiều (56 features).<br>Tiêu tốn ít RAM ($< 5\,\text{MB}$). | **Chuẩn mặc định của toàn hệ thống AERO**. Huấn luyện trên lưu lượng `Normal` sạch kết hợp baseline thực tế từ Data Lakehouse. Xuất sắc trong phát hiện tấn công Zero-day, đột biến lưu lượng (DDoS Flood, Scan). |
| **`one_class_svm`** | **Cơ chế**: Ánh xạ dữ liệu lên không gian đặc trưng vô hạn chiều thông qua Kernel RBF, sau đó tìm siêu phẳng (hyperplane) tách biệt cực đại tập điểm Normal khỏi gốc tọa độ.<br>**Điểm số**: Khoảng cách có dấu (Signed Distance) từ vector đặc trưng tới siêu phẳng quyết định. | **Độ nhạy biên giới cao**.<br>Huấn luyện phức tạp ($O(n^2)$ đến $O(n^3)$), tốn nhiều CPU khi tập dữ liệu lớn ($> 50,000$ mẫu). | **Tập dữ liệu Normal có quy mô vừa và nhỏ** với hình thái ranh giới phi tuyến tính phức tạp, không tuân theo phân phối hình học đơn giản. |
| **`elliptic_envelope`** | **Cơ chế**: Giả định dữ liệu phân phối chuẩn đa biến (Gaussian). Tính toán ma trận hiệp phương sai bền vững (Robust Covariance) và khoảng cách Mahalanobis để dựng elip bao bọc vùng an toàn.<br>**Điểm số**: Khoảng cách Mahalanobis chuẩn hóa. | **Tính toán ma trận cực nhanh**.<br>Rất nhạy cảm nếu dữ liệu vi phạm giả định phân phối chuẩn (Non-Gaussian). | **Môi trường mạng cục bộ ổn định**, các thiết bị IoT hoạt động định kỳ theo chu kỳ cố định (như cảm biến công nghiệp gửi số liệu đều đặn), ít nhiễu đột ngột. |
| **`lof`** *(Local Outlier Factor)* | **Cơ chế**: Đo lường độ cô lập cục bộ bằng cách so sánh mật độ xung quanh một điểm với mật độ của $k$ láng giềng gần nhất (k-Nearest Neighbors). Điểm có mật độ thấp hơn đáng kể so với láng giềng được xem là dị biệt.<br>**Điểm số**: Tỷ số mật độ cục bộ (LOF Score). | **Phát hiện dị biệt theo cụm mật độ cục bộ**.<br>Yêu cầu lưu trữ các điểm dữ liệu láng giềng để suy luận (k-NN search). | **Phân tích ngoại tuyến chuyên sâu** hoặc phát hiện các mẫu tấn công chậm (Slow-rate Attacks, APT) ẩn nấp khéo léo trong các phân đoạn mạng mật độ khác nhau. |

---

#### 3. Quy Trình Tái Huấn Luyện Kết Hợp Thực Tế (Hybrid Real-World Retraining)

Để khắc phục hiện tượng **lệch phân phối (Covariate Shift)** giữa tập dữ liệu học thuật (Edge-IIoTset) và môi trường Wi-Fi thực tế tại hiện trường (dẫn tới hiện tượng cảnh báo giả), AERO cung cấp cơ chế học kết hợp:
```bash
# Huấn luyện Hybrid: Kết hợp tập chuẩn Edge-IIoTset + Lưu lượng Normal thực tế từ Data Lakehouse
python ml_engine/train.py --classifier decision_tree --anomaly-model isolation_forest --data-source hybrid
```
- **Bước 1**: `DataLakeManager` quét các phân vùng Parquet (`data_lake/raw/date=YYYY-MM-DD/`) để trích xuất các khung truyền thực tế được gắn nhãn `Normal`.
- **Bước 2**: Pipeline tự động chuẩn hóa vector đặc trưng qua `EdgeTrafficPreprocessor` và gộp vào tập huấn luyện của Isolation Forest.
- **Bước 3**: Mô hình Isolation Forest mới học được cả hành vi an ninh chuẩn và đặc thù lưu lượng thực tế xung quanh, **triệt tiêu hoàn toàn báo động giả (False Positives)** trong các phiên vận hành kế tiếp.

---

## ⏱️ Formulate Bài Toán Dưới Dạng Chuỗi Thời Gian (Time-Series Formulation)

### 1. Quan sát Bản chất Dữ liệu Mạng
- **Bộ benchmark Edge-IIoTset**: Gồm các luồng gói tin pcap/flow được gắn nhãn thời gian `frame.time`, khoảng thời gian giữa các gói (Inter-arrival Time - IAT), độ dài phiên (Flow Duration) và các chỉ số tích lũy theo cửa sổ.
- **Kho dữ liệu Telemetry Data Lakehouse**: Thu thập lưu lượng từ Host/ESP32 theo từng cửa sổ thời gian trượt $\Delta t = 1.0\text{s}$ lưu dưới dạng Parquet. Các chỉ số như `packet_rate`, `byte_rate`, `syn_ratio`, `udp_ratio`, `tcp_fin_ratio`, `unique_dst_ports` tạo thành **Chuỗi thời gian đa biến (Multivariate Time-Series)**.
- **Tính tuần tự của các cuộc tấn công IoT**: Các đợt tấn công thực tế không xuất hiện độc lập mà tuân theo chuỗi các pha thời gian:
  1. *Pha Thăm dò (Reconnaissance)*: Port Scanning, Vulnerability Scanning (tăng đột biến tỷ lệ SYN, packet count trên nhiều cổng).
  2. *Pha Khai thác & Xâm nhập (Exploitation)*: Password Brute-force, SQL Injection, HTTP Flooding.
  3. *Pha Vận hành độc hại (Impact/Exfiltration)*: DoS/DDoS (traffic bão hòa), Exfiltration (traffic outbound lớn bất thường kéo dài).

### 2. Mô hình Hóa Toán học (Formulation)
Thay vì xử lý từng mẫu độc lập tại thời điểm $t$: $x_t \in \mathbb{R}^D$, ta gom chuỗi trượt lịch sử độ dài $W$ (ví dụ $W = 10 \sim 30$ bước thời gian, tương đương $10\text{s} \sim 30\text{s}$):
$$X_t = [x_{t-W+1}, x_{t-W+2}, \dots, x_t] \in \mathbb{R}^{W \times D}$$

Hai hướng tiếp cận kiến trúc chính:
1. **Phát hiện Bất thường Chuỗi Thời gian (Unsupervised Time-Series Anomaly Detection)**:
   - **Reconstruction Error (LSTM / TCN Autoencoder)**: Mô hình Autoencoder chỉ được huấn luyện trên chuỗi Normal. Khi gặp chuỗi bất thường, sai số tái tạo $\|X_t - \hat{X}_t\|_2$ tăng đột biến vượt ngưỡng $\tau$.
   - **Forecasting Residual**: Mô hình dự báo trạng thái kế tiếp $\hat{x}_{t+1} = f(X_t)$. Nếu gói tin thực tế $x_{t+1}$ lệch xa dự báo, gắn cờ Anomaly.
2. **Phân loại Chuỗi Tấn công (Supervised Sequence Classification)**:
   - Mô hình mạng tuần hoàn (Bi-LSTM, GRU) hoặc tích chập 1D (Temporal Convolutional Network - TCN) nhận đầu vào ma trận $X_t \in \mathbb{R}^{W \times D}$ và dự đoán nhãn tấn công $y_t \in \{0, 1, \dots, 14\}$.

### 3. Đánh giá Tính Khả Thi: Edge (ESP32) vs Host/Cloud Server
- **Trên Vi điều khiển biên (ESP32 / MCU)**:
  - Bộ nhớ SRAM giới hạn ($\sim 320\text{KB}$). Duy trì một Ring Buffer kích thước $W \times D = 30 \times 56 \times 4 \approx 6.7\text{KB}$ RAM hoàn toàn khả thi.
  - Tuy nhiên, tính toán tuần tự ma trận của LSTM/GRU tốn $> 200\text{ms}$ mỗi bước nếu không có bộ tăng tốc NPU, không đáp ứng được yêu cầu real-time $< 1\text{ms}$.
  - **Khuyến nghị**: Trên ESP32, giải pháp tối ưu là trích xuất **đặc trưng thống kê tích lũy theo cửa sổ (Aggregated Window Features)** kết hợp **Decision Tree C Code TinyML** (đạt độ trễ $< 50\,\mu s$).
- **Trên Host PC / SOC Server**:
  - Hoàn toàn phù hợp để triển khai PyTorch Deep Learning (LSTM, GRU, TCN, Transformer) trích xuất trực tiếp từ các tệp Parquet Data Lakehouse.

---

## ☁️ Đồng Bộ Kho Dữ Liệu Data Lakehouse Lên MinIO / S3 (Hợp Tác Nhóm)

Khi triển khai thực tế, mỗi thành viên trong nhóm nghiên cứu vận hành hệ thống tại các môi trường mạng khác nhau. Để chia sẻ dữ liệu và nạp dữ liệu chung để huấn luyện, hệ thống tích hợp giải pháp đồng bộ **MinIO / S3 Remote Storage**:

### 1. Kiến trúc Lưu trữ Đối tượng
```
MinIO Bucket: 'edge-lakehouse'
├── data_lake/
│   ├── raw/
│   │   ├── date=2026-09-15/
│   │   │   ├── sess_20260915_100000.parquet
│   │   └── date=2026-09-16/
│   │       └── sess_20260916_090000.parquet
│   └── catalog.db (SQLite Metadata Catalog)
```

### 2. Cấu hình Kết nối MinIO (Tùy chọn qua `.env`)
Tạo hoặc chỉnh sửa file `.env` tại thư mục gốc dự án:
```ini
# Cấu hình MinIO / S3 Object Storage
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET=edge-lakehouse
MINIO_SECURE=false
MINIO_AUTO_SYNC=true
```
*(Nếu chưa có sẵn server MinIO, bạn có thể khởi động nhanh bằng 1 lệnh Docker:)*
```bash
docker run -d -p 9000:9000 -p 9001:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data --console-address ':9001'
```

### 3. Công cụ CLI Đồng Bộ (`data_lake/sync_lakehouse.py`)
- **Kiểm tra trạng thái kết nối MinIO và dung lượng bucket**:
  ```bash
  python data_lake/sync_lakehouse.py --action status
  ```
- **Đẩy toàn bộ phân vùng Parquet và catalog.db từ máy cục bộ lên MinIO**:
  ```bash
  python data_lake/sync_lakehouse.py --action push
  ```
- **Kéo toàn bộ phân vùng dữ liệu của các thành viên khác về máy để huấn luyện**:
  ```bash
  python data_lake/sync_lakehouse.py --action pull
  ```
- **Tự động đồng bộ khi đóng phiên**: Khi bật `MINIO_AUTO_SYNC=true`, bất cứ khi nào bạn nhấn `Ctrl+C` dừng `run_system.py`, tệp Parquet vừa ghi và SQLite Catalog sẽ tự động được tải lên MinIO bucket ngay lập tức.

---

## 🗂️ Quản Lý Artifacts Theo Thư Mục Riêng & Chạy Đa Mô Hình

Để phục vụ so sánh và thử nghiệm nhiều thuật toán mà không bị ghi đè trọng số lẫn nhau, AERO tự động phân chia thư mục xuất artifacts:

### 1. Cấu trúc Thư mục Artifacts
```
ml_engine/models/
├── decision_tree_isolation_forest/    # Artifacts Decision Tree (kèm tinyml_model.h)
├── xgboost_isolation_forest/          # Artifacts XGBoost Model
├── lightgbm_isolation_forest/         # Artifacts LightGBM Model
├── catboost_isolation_forest/         # Artifacts CatBoost Model
├── pytorch_deep_isolation_forest/     # Artifacts PyTorch DNN (kèm loss_curve.png)
└── [Fallback Files]                   # Tự động đồng bộ bản sao mới nhất tại thư mục gốc
```

### 2. Huấn luyện các mô hình vào thư mục riêng
```bash
# Huấn luyện Decision Tree (xuất tinyml_model.h cho ESP32):
python ml_engine/train.py --classifier decision_tree --anomaly-model isolation_forest

# Huấn luyện XGBoost (độ chính xác cao):
python ml_engine/train.py --classifier xgboost --anomaly-model isolation_forest

# Huấn luyện PyTorch Deep Learning (in epoch & vẽ loss_curve.png):
python ml_engine/train.py --classifier pytorch_deep --anomaly-model isolation_forest
```

### 3. Khởi chạy Hệ thống với Mô hình Tùy Chọn
Khi vận hành thời gian thực, `run_system.py` tự động truy vết và nạp đúng thư mục artifacts tương ứng thông qua các cờ:
```bash
# Chạy với mô hình Decision Tree (mặc định):
python run_system.py --classifier decision_tree --anomaly-model isolation_forest

# Chạy với mô hình XGBoost:
python run_system.py --classifier xgboost --anomaly-model isolation_forest

# Chạy với mô hình PyTorch Deep Learning:
python run_system.py --classifier pytorch_deep --anomaly-model isolation_forest

# Hoặc chỉ định trực tiếp thư mục artifacts:
python run_system.py --models-dir ml_engine/models/xgboost_isolation_forest
```

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
# 1. Khởi chạy tiêu chuẩn (Mặc định bắt luồng mạng thật của PC qua Host Sniffer):
python run_system.py

# 2. Khởi chạy KÈM BỘ BẮN GÓI TIN MẠNG THẬT (Điều khiển on-demand từ các nút bấm Web Dashboard):
python run_system.py --attack-sim

# 3. Khởi chạy đón bo mạch ESP32 thật qua WiFi + BẮN GÓI TIN THẬT để ESP32 bắt over-the-air:
python run_system.py --probe esp32 --attack-sim

# 4. 1-Click Tự động build & nạp firmware ESP32 qua CLI (Không cần mở Arduino IDE):
python run_system.py --probe esp32 --attack-sim --flash

# 5. Chỉ định cổng Serial khi nạp ESP32 trên các hệ điều hành khác nhau:
python run_system.py --flash --port COM4              # Windows
python run_system.py --flash --port /dev/ttyUSB0      # Linux
python run_system.py --flash --port /dev/cu.usbserial-0001 # macOS

# 6. Tùy chọn chỉ định IP đích cụ thể để bắn gói tin độc hại:
python run_system.py --attack-sim --attack-target 192.168.1.1

# 7. Tùy chỉnh ngưỡng cảnh báo Anomaly Score (mặc định 0.55):
python run_system.py --threshold 0.65

# 8. Khởi chạy không tự động bật trình duyệt:
python run_system.py --no-browser
```

---

## 📟 Đấu Nối Phần Cứng ESP32 & Màn Hình OLED SSD1306

### Sơ đồ chân I2C & Cảnh báo ngoại vi:
| Linh Kiện | Chân Module | Chân ESP32 (NodeMCU / WROOM) | Mô Tả Chức Năng |
| :--- | :--- | :--- | :--- |
| **OLED SSD1306** | **VDD / VCC** | **3.3V** (Dây Đỏ) | Nguồn cấp 3.3V cho IC điều khiển màn hình |
| *(0.96" hoặc 0.91")* | **GND** | **GND** (Dây Đen) | Chân nối đất |
| | **SCK / SCL** | **GPIO 23 (D23)** hoặc **GPIO 22 (D22)** (Dây Vàng) | Tín hiệu I2C Clock (firmware tự động quét cả D23 & D22) |
| | **SDA** | **GPIO 21 (D21)** (Dây Xanh) | Tín hiệu I2C Data |
| **Đèn LED Đỏ** | Anode (+) | **GPIO 4** (D4) qua trở 220Ω | Sáng rực rỡ khi phát hiện cuộc tấn công |
| | Cathode (-) | **GND** | |
| **Còi Buzzer** | VCC (+) | **GPIO 19** (D19) | Kêu ngắt quãng 25ms (chống sụt áp nguồn 3.3V) |
| | GND (-) | **GND** | |

> [!TIP]
> **Khắc phục sự cố màn hình OLED không hiển thị (Màn hình tối đen):**
> 1. **Kiểm tra dây nối**: 
>    - Đỏ: `3V3` $\rightarrow$ `VDD`
>    - Đen: `GND` $\rightarrow$ `GND`
>    - Vàng: `D23` $\rightarrow$ `SCK` (Firmware đã cấu hình SCL tại GPIO 23 và hỗ trợ tự động quét cả D23 & D22)
>    - Xanh: `D21` $\rightarrow$ `SDA`
> 2. **Kiểm tra loại màn hình (128x64 vs 128x32)**: Nếu bạn dùng màn hình nhỏ **0.91 inch (128x32 pixels)**, hãy mở `firmware/esp32_probe/config.h` và đổi `#define SCREEN_HEIGHT 64` thành `#define SCREEN_HEIGHT 32` để tránh bị đen màn hình do sai chu kỳ quét multiplex!
> 3. **Tính năng Auto-Recovery**: Firmware được trang bị bộ quét I2C tự động (0x3C/0x3D) và tự động thử kích hoạt lại màn hình mỗi 5 giây trong `loop()`, nên ngay cả khi bạn cắm dây màn hình sau khi ESP32 đã boot thì màn hình vẫn tự động sáng!
> 4. Chi tiết xem thêm tại: [docs/ESP32_FLASHING_GUIDE.md](file:///d:/STT%202026/docs/ESP32_FLASHING_GUIDE.md).

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

### Bước 4: Chạy nguồn phát Telemetry & Bộ bắn gói tin độc hại
- **Bắt lưu lượng mạng thật từ card mạng máy tính (Host Sniffer)**:
  ```bash
  python firmware/host_probe/host_sniffer.py
  ```
- **Phát động các đợt tấn công mạng thật qua socket (Attack Traffic Generator)**:
  ```bash
  python firmware/simulator/attack_traffic_generator.py
  ```
- **Hoặc bo mạch ESP32 vật lý (Promiscuous Mode)**:
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
│       └── attack_traffic_generator.py # Module duy nhất bắn gói tin mạng thật (Raw Socket, điều khiển từ Web UI)
├── data_lake\
│   ├── lakehouse.py                   # DataLakeManager (quản lý phân vùng Parquet, nén Snappy, SQLite catalog)
│   ├── remote_storage.py              # MinIO / S3 Object Storage Manager (Upload/Download partitions)
│   ├── sync_lakehouse.py              # CLI Tool đồng bộ kho dữ liệu (push, pull, status)
│   ├── collector.py                   # MQTT DataLakeCollector ghi luồng telemetry nền
│   ├── catalog.db                     # SQLite Metadata Catalog lưu danh mục sessions và ngày
│   └── raw\                           # Thư mục chứa các phân vùng Parquet theo ngày (date=YYYY-MM-DD)
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
│   │   ├── classifiers\               # Modular Classifiers Package
│   │   │   ├── trees.py               # DecisionTree, RandomForest, ExtraTrees (TinyML Ready)
│   │   │   ├── boosting.py            # XGBoost, LightGBM, CatBoost
│   │   │   ├── deep_learning.py       # PyTorch EdgeDeepNet Classifier (Vẽ & xuất loss_curve.png)
│   │   │   ├── linear.py              # LogisticRegression Baseline
│   │   │   └── ensemble.py            # Soft-Voting Ensemble
│   │   └── anomaly_detectors.py       # IsolationForest, OneClassSVM, EllipticEnvelope, LOF
│   ├── exporter\
│   │   ├── __init__.py
│   │   └── tinyml_exporter.py         # Chuyển đổi mô hình sang C Header (ESP32 TinyML)
│   ├── export_tinyml.py               # Tiện ích export TinyML (CLI tập trung tại: train.py --export-tinyml-only)
│   ├── datasets\                      # Thư mục chứa dataset Edge-IIoTset CSV
│   ├── models\                        # Thư mục chứa Artifacts đã huấn luyện
│   │   ├── decision_tree_isolation_forest/ # Artifacts riêng Decision Tree (Weights + C Header)
│   │   ├── xgboost_isolation_forest/       # Artifacts riêng XGBoost Model
│   │   ├── lightgbm_isolation_forest/      # Artifacts riêng LightGBM Model
│   │   ├── pytorch_deep_isolation_forest/  # Artifacts riêng PyTorch DNN (kèm loss_curve.png)
│   │   ├── attack_classifier.joblib   # [Fallback] Bản sao mô hình vừa huấn luyện gần nhất
│   │   ├── isolation_forest.joblib    # [Fallback] Bản sao phát hiện bất thường
│   │   ├── preprocessor.joblib        # Bộ tiền xử lý (Encoders + Scaler)
│   │   ├── scaler.joblib              # Weights của StandardScaler
│   │   ├── model_metadata.json        # Thông số cấu hình & kết quả đánh giá mô hình
│   │   ├── optuna_study.db            # Cơ sở dữ liệu SQLite lưu trữ lịch sử trials Optuna
│   │   └── tinyml_model.h             # Tệp header C sinh ra cho vi điều khiển
│   ├── train.py                       # Master Training Pipeline (Entrypoint: HPO + Multi-model Output)
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
