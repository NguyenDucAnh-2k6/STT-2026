# Hướng Dẫn Nạp Code Cho ESP32 Probe (Flashing Guide)

Tài liệu này hướng dẫn chi tiết cách nạp mã nguồn firmware cho board ESP32 để thiết lập trạm bắt gói tin (Edge Probe).

---

## 1. Yêu Cầu Phần Cứng

1. **Board mạch**: ESP32 bất kỳ (ESP32-WROOM-32, ESP32 NodeMCU, ESP32-S3, ESP32-CAM).
2. **Cáp Micro-USB hoặc Type-C** truyền được dữ liệu (Data Cable).
3. **Driver cổng COM**: Cài đặt driver CP210x hoặc CH340 tùy loại chip giao tiếp trên board của bạn.

---

## 2. Nạp Bằng Arduino IDE (Khuyên Dùng Cho Người Mới)

### Bước 2.1: Cài đặt Board ESP32
1. Mở **Arduino IDE** $\rightarrow$ **File** $\rightarrow$ **Preferences**.
2. Tại mục *Additional boards manager URLs*, dán URL sau:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Vào **Tools** $\rightarrow$ **Board** $\rightarrow$ **Boards Manager...**, tìm `esp32` và bấm **Install** (bản 2.x hoặc 3.x).

### Bước 2.2: Cài đặt Thư Viện Cần Thiết
Vào **Tools** $\rightarrow$ **Manage Libraries...**, tìm và cài đặt 2 thư viện sau:
1. **`PubSubClient`** (bởi Nick O'Leary) - Thư viện giao tiếp MQTT.
2. **`ArduinoJson`** (bởi Benoit Blanchon) - Bản 6.x hoặc 7.x.

> [!TIP]
> Để tránh lỗi tràn bộ đệm gói tin MQTT của thư viện PubSubClient, mở file `PubSubClient.h` trong thư viện và đảm bảo hằng số `MQTT_MAX_PACKET_SIZE` tối thiểu là `512` (mã nguồn trong project này đã gọi hàm `mqttClient.setBufferSize(512)` tự động).

### Bước 2.3: Cấu hình File `config.h`
Mở thư mục `firmware/esp32_probe/` và chỉnh sửa file `config.h`:
```cpp
// Đặt tên và mật khẩu WiFi mà máy tính và ESP32 cùng truy cập được
#define WIFI_SSID           "Ten_WiFi_Cua_Ban"
#define WIFI_PASSWORD       "Mat_Khau_WiFi"

// Đặt địa chỉ IP của máy tính đang chạy Mosquitto Broker
// Bạn có thể xem IP máy tính bằng lệnh 'ipconfig' trên cmd
#define MQTT_BROKER_HOST    "192.168.1.15" 
#define MQTT_BROKER_PORT    1883
```

### Bước 2.4: Biên dịch và Nạp Code
1. Vào **Tools** $\rightarrow$ **Board** $\rightarrow$ chọn **ESP32 Dev Module** (hoặc board tương ứng).
2. Vào **Tools** $\rightarrow$ **Port** $\rightarrow$ chọn cổng COM của ESP32 (ví dụ `COM3`, `COM5`).
3. Đặt **Upload Speed**: `921600` hoặc `115200`.
4. Bấm nút **Upload** (mũi tên sang phải).
   *(Nếu màn hình hiển thị `Connecting...___...`, hãy bấm giữ nút **BOOT** trên board ESP32 trong 1-2 giây để bắt đầu nạp)*.

---

## 3. Nạp Bằng PlatformIO (VS Code)

Nếu bạn dùng VS Code với extension **PlatformIO**, tạo file `platformio.ini` với nội dung:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps =
    knolleary/PubSubClient@^2.8
    bblanchon/ArduinoJson@^7.0.4
```
Sau đó bấm nút **Build** và **Upload** ở thanh trạng thái PlatformIO.

---

## 4. Kiểm Tra Hoạt Động (Serial Monitor)

Mở **Serial Monitor** với baudrate **`115200`**. Nếu nạp thành công, màn hình sẽ in ra:

```text
==================================================
  EDGE AI NETWORK ANOMALY DETECTION - ESP32 PROBE 
==================================================
[WiFi] Dang ket noi den WiFi: MyHomeWiFi...
[WiFi] Ket noi thanh cong! IP: 192.168.1.55
[MQTT] Dang ket noi den Broker 192.168.1.15... Ket noi thanh cong!
[Sniffer] Promiscuous mode bat tren kenh 1!
[Telemetry] Pkts/s: 85.0 | Bytes/s: 42500 | SYN: 0.04 | Ports: 8 | Threat: Normal
```

Lúc này, dữ liệu lưu lượng mạng thực tế xung quanh đã bắt đầu được truyền trực tiếp về Mosquitto Broker và hiển thị lên Web Dashboard!
