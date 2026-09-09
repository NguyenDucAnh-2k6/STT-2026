# AERO - Hệ Thống Edge AI Phát Hiện Bất Thường Lưu Lượng Mạng

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![ESP32 Compatible](https://img.shields.io/badge/Hardware-ESP32%20%7C%20ESP32--S3-brightgreen.svg)](https://www.espressif.com/)
[![MQTT Mosquitto](https://img.shields.io/badge/MQTT-Mosquitto%203.1.1-orange.svg)](https://mosquitto.org/)

Hệ thống giám sát và phát hiện bất thường an ninh mạng thời gian thực dựa trên kiến trúc **Edge AI**. Dự án kết hợp thiết bị biên vi điều khiển (ESP32) hoạt động ở chế độ Promiscuous Mode, giao thức truyền tải siêu nhẹ MQTT (Mosquitto), mô hình học máy phát hiện dị biệt (Isolation Forest) kết hợp TinyML nhúng trực tiếp on-device, cùng giao diện giám sát SOC (Security Operations Center) hiện đại thời gian thực.

---

## 🌟 Tính Năng Nổi Bật

- **Bắt gói tin biên (Edge Promiscuous Sniffing)**: ESP32 bắt trực tiếp các khung WiFi 802.11, trích xuất 8 đặc trưng lưu lượng mạng quan trọng (tốc độ gói, băng thông byte, cờ TCP SYN/ACK, tỷ lệ UDP/ICMP, entropy cổng đích) mà không cần cấu hình mạng phức tạp.
- **Truyền dẫn độ trễ thấp qua MQTT**: Đóng gói JSON telemetry nhẹ, publish định kỳ qua Eclipse Mosquitto Broker.
- **Mô hình học máy kép (Dual AI Pipeline)**:
  - **Isolation Forest (Unsupervised)**: Phát hiện các bất thường lưu lượng chưa từng thấy (Zero-day anomalies) với F1-Score **0.97+**.
  - **Decision Classifier (Supervised & TinyML)**: Phân loại chính xác các cuộc tấn công mạng phổ biến: **SYN Flood**, **Port Scan**, **Volumetric UDP DDoS**, **Data Exfiltration**.
- **TinyML On-Device Ready**: Kèm công cụ chuyển đổi mô hình sang C Header (`tinyml_model.h`), cho phép nhúng trực tiếp vào ESP32 để suy luận 100% trên chip với thời gian thực thi $< 50\,\mu s$.
- **SOC Web Dashboard Real-time**: Giao diện Cyberpunk Glassmorphism Dark Mode tuyệt đẹp, biểu đồ Chart.js tự động cập nhật qua WebSocket, đồng hồ đo mức độ đe dọa và bảng nhật ký cảnh báo trực quan.
- **Bộ giả lập Simulator tương tác**: Giả lập trạm ESP32 với bảng điều khiển kích hoạt các kịch bản tấn công ngay trên Web UI hoặc terminal để demo kiểm thử ngay cả khi chưa cắm phần cứng thật.

---

## 🏗️ Kiến Trúc Hệ Thống

```
ESP32 WiFi Sniffer (Promiscuous Mode)
         │  [MQTT: edge/telemetry/traffic]
         ▼
Mosquitto MQTT Broker (Port 1883)
    ├──► ML Inference Engine (Isolation Forest + Attack Classifier)
    │         │  [MQTT: edge/telemetry/prediction & edge/alerts/high_priority]
    │         ▼
    └──► FastAPI Backend & WebSocket Server (Port 8000)
              │  [WebSocket: /ws/telemetry]
              ▼
         SOC Web Dashboard (Real-time HTML5/CSS3/Chart.js)
```

---

## 🚀 Khởi Động Nhanh (Quick Start)

### 1. Cài đặt thư viện Python
```bash
pip install -r requirements.txt
```

### 2. Khởi chạy toàn bộ hệ thống bằng 1 lệnh duy nhất!
### 2. Khởi chạy toàn bộ hệ thống bằng 1 lệnh duy nhất!

Hệ thống hỗ trợ cả 3 Entry Points tùy thuộc vào môi trường phát triển của bạn:

- **Trên Windows (Command Prompt / PowerShell)**:
  ```cmd
  run_system.bat
  ```
  *Hoặc chọn mô hình khác:*
  ```cmd
  run_system.bat --classifier random_forest
  ```

- **Trên Linux / macOS / WSL / Git Bash**:
  ```bash
  chmod +x run_system.sh
  ./run_system.sh --classifier random_forest
  ```

- **Hoặc chạy trực tiếp qua Python**:
  ```bash
  # Mặc định (Decision Tree + TinyML + Isolation Forest):
  python run_system.py

  # Tùy chọn mô hình khác & ngưỡng cảnh báo:
  python run_system.py --classifier gradient_boosting --anomaly-model isolation_forest --threshold 0.60
  ```

Trình duyệt sẽ tự động mở trang Dashboard tại: **`http://localhost:8000`**

---

## 🛠️ Vận Hành Từng Thành Phần (Manual Execution)

Nếu bạn muốn mở từng terminal riêng biệt để quan sát chi tiết từng tầng:

### Bước 1: Khởi động MQTT Broker
- **Cách 1: Sử dụng Embedded Python Broker (Không cần cài đặt thêm)**:
  ```bash
  python broker/embedded_broker.py
  ```
- **Cách 2: Sử dụng Docker Mosquitto**:
  ```bash
  cd broker && docker-compose up -d
  ```

### Bước 2: Huấn luyện và xuất mô hình ML & TinyML
Hệ thống hỗ trợ nhiều thuật toán phân loại và phát hiện bất thường:
```bash
# Xem danh sách tất cả các thuật toán hỗ trợ:
python ml_engine/train.py --list-models

# Huấn luyện Decision Tree và xuất C code cho ESP32:
python ml_engine/train.py --classifier decision_tree --export-tinyml

# Huấn luyện Random Forest hoặc Gradient Boosting:
python ml_engine/train.py --classifier random_forest
python ml_engine/train.py --classifier gradient_boosting

# So sánh benchmark đối chứng toàn bộ các bộ phân loại:
python ml_engine/train.py --classifier all_compare
```

### Bước 3: Chạy Service suy luận thời gian thực
```bash
python ml_engine/inference_service.py --threshold 0.55
```

### Bước 4: Khởi động Web Dashboard
```bash
python dashboard/backend/app.py
```
Truy cập: `http://localhost:8000`

### Bước 5: Chạy thiết bị bắt gói tin
- **Nếu dùng bộ giả lập (Simulator)**:
  ```bash
  # Chế độ tự động đổi kịch bản sau 15s để demo:
  python firmware/simulator/esp32_simulator.py --auto-cycle

  # Hoặc bấm phím 0, 1, 2, 3, 4 trong terminal để kích hoạt tấn công tùy ý:
  python firmware/simulator/esp32_simulator.py
  ```
- **Nếu dùng board ESP32 thật**:
  Xem hướng dẫn nạp code tại: [docs/ESP32_FLASHING_GUIDE.md](file:///d:/STT%202026/docs/ESP32_FLASHING_GUIDE.md)

---

## 📂 Cấu Trúc Thư Mục Dự Án (Modular Architecture)

```
d:\STT 2026\
├── firmware\
│   ├── esp32_probe\
│   │   ├── esp32_probe.ino            # Mã nguồn Arduino C++ cho ESP32 bắt gói tin & TinyML
│   │   ├── config.h                   # Cấu hình WiFi SSID, Pass, MQTT Broker IP
│   │   └── tinyml_model.h             # Mô hình TinyML xuất sang C header chạy trên ESP32
│   └── simulator\
│       └── esp32_simulator.py         # Giả lập ESP32 phát traffic & nhận lệnh từ Web UI
├── broker\
│   ├── mosquitto.conf                 # Cấu hình chuẩn Eclipse Mosquitto
│   ├── docker-compose.yml             # Chạy Mosquitto nhanh bằng Docker
│   └── embedded_broker.py             # Embedded pure Python MQTT broker dự phòng
├── ml_engine\
│   ├── config\
│   │   └── schema.py                  # Định nghĩa Feature Vector, Label Map, hằng số
│   ├── preprocessing\
│   │   ├── dataset_generator.py       # Bộ sinh dữ liệu synthetic traffic đa kịch bản
│   │   └── feature_preprocessor.py    # Chuẩn hóa dữ liệu (StandardScaler) & trích xuất vector
│   ├── algorithms\
│   │   ├── base.py                    # Base protocol cho Classifier & Anomaly Detector
│   │   ├── classifiers.py             # DecisionTree, RandomForest, ExtraTrees, GradientBoosting, MLP
│   │   └── anomaly_detectors.py       # IsolationForest, OneClassSVM, EllipticEnvelope, LOF
│   ├── exporter\
│   │   └── tinyml_exporter.py         # Chuyển đổi mô hình sang C Header (ESP32 TinyML)
│   ├── datasets\                      # Dữ liệu huấn luyện lưu lượng mạng mẫu
│   ├── models\                        # Trọng số mô hình (.joblib, .json, .h)
│   ├── train.py                       # CLI huấn luyện mô hình đa cờ (--classifier, --anomaly-model)
│   ├── inference_service.py           # Service suy luận thời gian thực MQTT
│   └── export_tinyml.py               # Wrapper CLI xuất mã C TinyML
├── dashboard\
│   ├── backend\
│   │   └── app.py                     # FastAPI server, WebSocket broadcaster & REST APIs
│   └── frontend\
│       ├── index.html                 # Giao diện SOC Dashboard Cyberpunk Dark Mode
│       ├── css\style.css              # Glassmorphism styling, animations & theme
│       └── js\app.js                  # WebSocket client, Chart.js visualizations
├── docs\                              # Tài liệu kỹ thuật kiến trúc, API và ESP32
├── run_system.py                      # Master Launcher đa nền tảng (hỗ trợ flags)
├── run_system.bat                     # Entry point Windows Command Prompt / Batch
├── run_system.sh                      # Entry point Linux / macOS / WSL Shell Script
├── test_pipeline.py                   # Automated Integration Pipeline Test
├── requirements.txt                   # Danh sách thư viện Python
└── README.md                          # Tài liệu dự án
```

---

## 📊 Kịch Bản Tấn Công Được Hỗ Trợ

| Kịch Bản | Đặc Trưng Nhận Diện | Hành Vi & Phân Loại |
|---|---|---|
| **Normal Traffic** | Tốc độ gói 40-220 pkts/s, SYN thấp (2-8%), ACK cân bằng | Lưu lượng web/video thông thường, Anomaly Score $< 0.35$ |
| **SYN Flood** | Tốc độ gói tăng vọt ($> 1500$ pkts/s), SYN ratio $> 90\%$, kích thước gói nhỏ | Tấn công làm tràn bảng kết nối TCP của máy chủ |
| **Port Scan** | Số lượng cổng đích duy nhất tăng vọt ($> 80$ ports), SYN cao | Kẻ tấn công quét các cổng dịch vụ mở để dò lỗ hổng |
| **Volumetric DDoS** | Băng thông cực lớn, gói tin UDP áp đảo ($> 75\%$), kích thước gói lớn | Tấn công làm ngập băng thông mạng |
| **Data Exfiltration** | Kích thước gói tin cực đại ($\approx 1500$ bytes MTU), cờ ACK cao, băng thông tăng bất thường | Dấu hiệu mã độc đang đánh cắp và truyền dữ liệu nhạy cảm ra ngoài |

---

## 📜 Giấy Phép (License)
Dự án được phát hành theo giấy phép [MIT License](LICENSE).
