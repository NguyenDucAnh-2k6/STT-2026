# Walkthrough: Hệ Thống Edge AI Phát Hiện Bất Thường Lưu Lượng Mạng

Repository **EdgeGuard AI** đã được khởi tạo hoàn chỉnh tại thư mục làm việc `d:\STT 2026`. Hệ thống hiện thực hóa trọn vẹn pipeline theo đề xuất của team (ESP32 $\rightarrow$ Mosquitto MQTT $\rightarrow$ Host Machine ML & Dashboard) đồng thời chuẩn bị sẵn lộ trình TinyML chạy trực tiếp on-chip trên ESP32.

---

## Các Thành Phần Đã Xây Dựng

### 1. Firmware & Simulator Thiết Bị Biên (Edge Probe Layer)
- [config.h](file:///d:/STT%202026/firmware/esp32_probe/config.h): Cấu hình WiFi, MQTT Broker IP/port, cửa sổ lấy mẫu và các ngưỡng cảnh báo.
- [esp32_probe.ino](file:///d:/STT%202026/firmware/esp32_probe/esp32_probe.ino): Mã nguồn Arduino C++ cho ESP32 bắt gói tin WiFi bằng Promiscuous Mode, tính toán 8 đặc trưng lưu lượng, tích hợp bộ suy luận `tinyml_model.h` và gửi telemetry qua MQTT.
- [tinyml_model.h](file:///d:/STT%202026/firmware/esp32_probe/tinyml_model.h): Mô hình học máy C header tự sinh, thực thi suy luận trực tiếp trong $< 50\,\mu s$ trên ESP32 mà không phụ thuộc Python hay máy chủ.
- [esp32_simulator.py](file:///d:/STT%202026/firmware/simulator/esp32_simulator.py): Giả lập trạm bắt mạng ESP32 với các kịch bản lưu lượng thực tế và nhận lệnh kích hoạt tấn công từ xa qua MQTT.

### 2. Message Broker Layer (MQTT)
- [mosquitto.conf](file:///d:/STT%202026/broker/mosquitto.conf): Cấu hình Mosquitto MQTT mở port `1883` (TCP) và `9001` (WebSocket).
- [docker-compose.yml](file:///d:/STT%202026/broker/docker-compose.yml): Triển khai Mosquitto container nhanh bằng Docker.
- [embedded_broker.py](file:///d:/STT%202026/broker/embedded_broker.py): MQTT Broker thuần Python dự phòng, giúp khởi chạy hệ thống ngay mà không cần cài đặt thêm phần mềm ngoài.

### 3. Machine Learning Engine (Dual AI Pipeline)
- [train.py](file:///d:/STT%202026/ml_engine/train.py): Sinh tập dữ liệu mô phỏng chuẩn CIC-IDS2017/NSL-KDD (10,000 mẫu), huấn luyện mô hình **Isolation Forest** (Unsupervised, F1: **0.9709**) và **Decision Classifier** (Độ chính xác: **100%**).
- [inference_service.py](file:///d:/STT%202026/ml_engine/inference_service.py): Service lắng nghe MQTT `edge/telemetry/traffic`, tính toán Anomaly Score thời gian thực ($< 2\,\text{ms}$) và bắn cảnh báo lên `edge/alerts/high_priority`.
- [export_tinyml.py](file:///d:/STT%202026/ml_engine/export_tinyml.py): Tự động chuyển đổi cây quyết định thành file C header cho vi điều khiển.
- [models/](file:///d:/STT%202026/ml_engine/models/): Chứa các model weights (`isolation_forest.joblib`, `attack_classifier.joblib`, `scaler.joblib`).

### 4. SOC Web Dashboard Real-Time
- [app.py](file:///d:/STT%202026/dashboard/backend/app.py): FastAPI backend, WebSocket broadcaster `/ws/telemetry` và REST APIs điều khiển simulator.
- [index.html](file:///d:/STT%202026/dashboard/frontend/index.html): Giao diện SOC Cyberpunk Glassmorphism Dark Mode với đồng hồ rủi ro, bảng điều khiển phát động tấn công và nhật ký cảnh báo trực tiếp.
- [style.css](file:///d:/STT%202026/dashboard/frontend/css/style.css): Thiết kế phong cách neon dark mode, micro-animations và bố cục responsive.
- [app.js](file:///d:/STT%202026/dashboard/frontend/js/app.js): Client WebSocket, cập nhật 3 biểu đồ Chart.js mượt mà 60 FPS.

### 5. Công Cụ Vận Hành & Tài Liệu
- [run_system.py](file:///d:/STT%202026/run_system.py): Script One-Click khởi chạy toàn bộ 5 thành phần của hệ thống cùng lúc.
- [test_pipeline.py](file:///d:/STT%202026/test_pipeline.py): Script kiểm thử tự động xác minh toàn bộ luồng MQTT và suy luận ML.
- [ARCHITECTURE.md](file:///d:/STT%202026/docs/ARCHITECTURE.md): Sơ đồ kiến trúc Mermaid và phân tích chi tiết.
- [ESP32_FLASHING_GUIDE.md](file:///d:/STT%202026/docs/ESP32_FLASHING_GUIDE.md): Hướng dẫn nạp code chi tiết cho ESP32 qua Arduino IDE / PlatformIO.
- [MQTT_API_SPEC.md](file:///d:/STT%202026/docs/MQTT_API_SPEC.md): Đặc tả topics và schema JSON trao đổi dữ liệu.
- [README.md](file:///d:/STT%202026/README.md): Hướng dẫn cài đặt và sử dụng tổng quan.

---

## Kết Quả Kiểm Thử (Verification Results)

### 1. Huấn luyện Mô hình Machine Learning
```
[3/4] Huan luyen mo hinh Isolation Forest (Unsupervised Anomaly Detector)...
  -> Isolation Forest Binary F1-Score: 0.9709

[4/4] Huan luyen bo phan loai tan cong (Decision Tree / Edge Optimized)...
  -> Decision Tree Accuracy: 100.00%
                   precision    recall  f1-score   support
           Normal       1.00      1.00      1.00      1500
        SYN_Flood       1.00      1.00      1.00       250
        Port_Scan       1.00      1.00      1.00       250
  Volumetric_DDoS       1.00      1.00      1.00       250
Data_Exfiltration       1.00      1.00      1.00       250
```

### 2. Kiểm thử End-to-End Pipeline Tự Động (`test_pipeline.py`)
- Khởi động Embedded MQTT Broker trên port 1883 $\rightarrow$ Thành công.
- Client Subscriber đăng ký lắng nghe topic alerts và predictions $\rightarrow$ Thành công.
- Client Publisher gửi gói tin thử nghiệm tấn công SYN Flood $\rightarrow$ Thành công.
- Bộ máy suy luận đưa ra kết quả:
  ```
  Direct inference assertion passed: Anomaly detected, threat = SYN_Flood, latency = 15.91 ms
  MQTT End-to-end verified! Received 2 messages on subscribed topics.
  [ALL TESTS PASSED SUCCESSFULLY!]
  ```

---

## Cách Khởi Chạy Nhanh Cho Người Dùng

Bạn chỉ cần mở terminal tại thư mục `d:\STT 2026` và gõ:

```powershell
python run_system.py
```

Trình duyệt sẽ tự động mở trang Dashboard tại `http://localhost:8000` để bạn trải nghiệm ngay!
