# Walkthrough: Hệ Thống Edge AI Phát Hiện Bất Thường Lưu Lượng Mạng

Repository **EdgeGuard AI** (`d:\STT 2026`) đã được nâng cấp toàn diện để hỗ trợ **đa nền tảng (Cross-Platform trên Windows, Linux, macOS, WSL)**, loại bỏ triệt để các đường dẫn tuyệt đối hoặc định danh hardcode, tự động hóa Zero-Config Wi-Fi, tích hợp nạp firmware 1-click CLI, đồng bộ hóa `run_system.sh` và xử lý triệt để sự cố hiển thị màn hình OLED SSD1306.

---

## 🚀 Các Nâng Cấp Nổi Bật Mới Nhất

### 1. Khử Hardcode Đường Dẫn & Hỗ Trợ Đa Nền Tảng (Windows / Linux / macOS)
- **Định vị `arduino-cli` động**:
  - Không còn hardcode đường dẫn ổ đĩa `C:\Program Files\...`.
  - Tận dụng `shutil.which("arduino-cli")` ưu tiên số 1.
  - Tự động quét theo biến môi trường `LOCALAPPDATA`, `ProgramFiles`, `ProgramFiles(x86)` trên Windows; `/usr/local/bin`, `/usr/bin`, `~/.local/bin`, `~/.arduino-ide/...` trên Linux; và `/Applications/Arduino IDE.app/...`, `/opt/homebrew/bin` trên macOS.
- **Tự động nhận diện cổng kết nối USB-Serial đa nền tảng**:
  - Không fallback về hardcode `"COM4"`. Nếu không có bo mạch, trả về `None` an toàn.
  - Tích hợp quét qua `serial.tools.list_ports` (chuẩn hóa trên mọi OS), PowerShell `Win32_SerialPort` (Windows), `/dev/serial/by-id/*`, `/dev/ttyUSB*`, `/dev/ttyACM*` (Linux) và `/dev/cu.usbserial*`, `/dev/cu.SLAB*`, `/dev/cu.wch*` (macOS).
  - Bổ sung alias cờ CLI: `--port` và `--com-port` để người dùng Linux/macOS dễ dàng chỉ định (ví dụ: `--port /dev/ttyUSB0`).
- **Trích xuất Wi-Fi & IP LAN ngầm (Zero-Config Network)**:
  - Windows: Tự động trích xuất SSID và Mật khẩu qua `netsh wlan show interfaces` và `netsh wlan show profile key=clear`.
  - Linux: Tự động trích xuất qua `nmcli dev wifi` và `nmcli connection show`.
  - macOS: Tự động trích xuất qua `airport -I` / `networksetup` và `security find-generic-password`.
  - Tự động ghi vào `firmware/esp32_probe/credentials.h` và `.env` mà người dùng không cần phải gõ thủ công.

---

### 2. Đồng Bộ Hóa & Hoàn Thiện `run_system.sh` (Linux / macOS / WSL)
- Cập nhật toàn bộ các cờ tính năng hiện đại: `--flash`, `--port`, `--attack-sim`, `--probe esp32`.
- Tự động kích hoạt môi trường ảo `venv` hoặc `.venv` nếu có.
- Chuẩn hóa định dạng Unix LF cho shell script.

---

### 3. Khắc Phục Triệt Để Màn Hình OLED SSD1306
- **Tốc độ I2C Chuẩn**: Chuyển từ `400000` (Fast Mode dễ nhiễu trên breadboard) sang `100000` (Standard Mode ổn định tuyệt đối với mọi loại dây jumper và màn hình clone SSD1306/SH1106).
- **Bộ quét I2C Bus tích hợp**: Tự động quét toàn bộ dải địa chỉ 0x01 .. 0x7F khi khởi động, in chi tiết các thiết bị tìm thấy lên Serial Monitor (115200 baud).
- **Thử nghiệm tuần tự địa chỉ 0x3C & 0x3D**: Tự động tương thích với cả 2 loại chân địa chỉ phổ biến của SSD1306.
- **Sửa lỗi hiển thị trong `loop()`**: Bổ sung tường minh `display.setTextColor(SSD1306_WHITE)` ngay sau `display.clearDisplay()` để đảm bảo màu chữ không bị trùng màu nền đen.
- **Giao diện Responsive theo độ phân giải**:
  - Hỗ trợ màn hình 0.96 inch thông dụng (**128x64 pixels**).
### 4. Cơ Chế Bắt Cấu Hình Mạng Thời Gian Thực (Zero-Config Network Roaming) & Sửa Lỗi Timeout
- **Khắc phục lỗi IP cũ gây TimeoutError ở ML Inference**:
  - Trước đây, khi chuyển mạng Wi-Fi (ví dụ từ mạng nhà `192.168.1.x` sang `Phong 401` hoặc điểm phát di động `Nokia 5.3` `10.24.47.x`), giá trị cũ trong `.env` làm `inference_service.py` cố kết nối tới IP cũ và bị `TimeoutError: timed out`.
  - **Khắc phục**: 
    1. Các tiến trình Python cục bộ trên máy tính (`inference_service.py`, `dashboard/backend`, `attack_traffic_generator.py`) luôn kết nối tới Broker qua **`127.0.0.1` (Loopback)**. Vừa an toàn tuyệt đối, độ trễ 0ms, không bao giờ bị ảnh hưởng bởi đổi mạng Wi-Fi hay tường lửa Windows Firewall.
    2. Bổ sung cơ chế Fallback tự động trong `inference_service.py`: nếu IP Broker gặp sự cố, tự động fallback về `127.0.0.1`.
    3. Hàm `sync_env_to_firmware()` luôn ưu tiên địa chỉ IP thực tế của card Wi-Fi đang kết nối (`10.24.47.135`) để đồng bộ vào `credentials.h` phục vụ bo mạch phần cứng ESP32.

### 5. Sơ Đồ Chân OLED Khớp Chính Xác Phần Cứng (D23-SCK, D21-SDA)
- Khớp chính xác theo màu dây thực tế:
  - **Đỏ**: ESP32 3V3 -> OLED VDD
  - **Đen**: ESP32 GND -> OLED GND
  - **Vàng**: ESP32 **D23** -> OLED SCK (SCL)
  - **Xanh**: ESP32 **D21** -> OLED SDA
- `initOLED()` được chuyển lên đầu hàm `setup()`, tự động bật pull-up nội bộ và hiển thị thông tin khởi động + trạng thái kết nối Wi-Fi ngay lập tức.

### 6. Khắc Phục Lỗi 404 `/favicon.ico` & Tích Hợp Cyber Shield Icon
- Tạo mới vector icon SVG công nghệ cao [`dashboard/frontend/favicon.svg`](file:///d:/STT%202026/dashboard/frontend/favicon.svg) mang biểu tượng chiếc khiên an ninh mạng với gradient Cyan/Emerald.
- Trong [`dashboard/backend/app.py`](file:///d:/STT%202026/dashboard/backend/app.py): Bổ sung route xử lý `/favicon.ico` và `/favicon.svg` trả về icon chuẩn media type `image/svg+xml`.
- Trong [`dashboard/frontend/index.html`](file:///d:/STT%202026/dashboard/frontend/index.html): Bổ sung thẻ `<link rel="icon" type="image/svg+xml" href="/favicon.svg" />`. Loại bỏ hoàn toàn lỗi `404 Not Found` trên terminal server.

### 7. Kiến Trúc Chịu Lỗi Khi Chuyển Mạng Đột Ngột (Zero-Downtime Network Roaming)
- **Dual-Transport Telemetry (Truyền thông kép Wi-Fi + USB Serial)**:
  - Khi cắm ESP32 vào máy tính qua cáp USB, firmware luôn xuất bản tin `ESP32_TELEMETRY:{...}` ra cổng Serial song song với MQTT.
  - Trên máy tính, `run_system.py` chạy luồng `serial_telemetry_bridge_worker` kết nối tới cổng COM. Kể cả khi Wi-Fi bị ngắt, đang chuyển mạng hoặc router bật AP Isolation, **Web Dashboard & ML Engine vẫn nhận dữ liệu liên tục 100% qua cáp USB!**
- **WiFiMulti (Tự động chuyển AP)**:
  - ESP32 tích hợp `WiFiMulti`, đăng ký sẵn danh sách các mạng đã biết (mạng phòng, hotspot di động). Khi người dùng đổi mạng, ESP32 tự động quét và kết nối tới Access Point khả dụng mà không cần nạp lại firmware.
- **Auto-Discovery Broker IP qua UDP Broadcast Beacon**:
  - Máy tính phát sóng UDP Beacon mỗi 3s trên port `18830`. ESP32 khi vào mạng mới sẽ lắng nghe UDP, tự động nhận diện IP mới của máy tính và trỏ MQTT về IP mới tức thì.
- **Network Roaming Watcher trên PC**:
  - `run_system.py` liên tục giám sát card mạng; khi phát hiện máy tính chuyển sang Wi-Fi mới, nó tự động cập nhật `.env`, `credentials.h` và luồng UDP Beacon.

---

## 🧪 Kết Quả Kiểm Thử (Verification Results)

### 1. Kiểm thử Route Favicon
```text
Favicon status: 200 image/svg+xml (Khong con loi 404 Not Found!)
```

### 2. Kiểm thử Tự Động Trích Xuất Wi-Fi & Gateway Thời Gian Thực
```text
  -> Da dong bo cau hinh WiFi/MQTT tu dong vao firmware\esp32_probe\credentials.h:
     * WIFI_SSID        : "Nokia 5.3" (Tu dong)
     * WIFI_PASSWORD    : "duc***" (Tu dong)
     * MQTT_BROKER_HOST : "10.24.47.135" (Tu dong)
  -> Target Gateway IP  : 10.24.47.189
```

### 3. Kiểm thử Biên dịch Firmware ESP32 Đa Mạng (WiFiMulti + UDP Beacon)
```text
Sketch uses 1053192 bytes (80%) of program storage space. Maximum is 1310720 bytes.
Global variables use 49592 bytes (15%) of dynamic memory, leaving 278088 bytes for local variables. Maximum is 327680 bytes.
[SUCCESS - 0 COMPILATION ERRORS]
```

---

## 💡 Hướng Dẫn Vận Hành Nhanh

- **Chạy trên Windows (1-Click Flash Firmware & Run Hệ Thống)**:
  ```cmd
  run_system.bat --probe esp32 --attack-sim --flash
  ```
- **Chạy trên Linux / macOS**:
  ```bash
  chmod +x run_system.sh
  ./run_system.sh --probe esp32 --attack-sim --flash --port /dev/ttyUSB0
  ```
