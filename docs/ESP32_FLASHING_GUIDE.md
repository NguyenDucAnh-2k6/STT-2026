# Hướng Dẫn Nạp Code Cho ESP32 Probe (Flashing Guide)

Tài liệu này hướng dẫn chi tiết cách nạp mã nguồn firmware cho bo mạch ESP32 để thiết lập trạm bắt gói tin mạng không dây (Promiscuous Edge Probe) hỗ trợ đa nền tảng (**Windows, Linux, macOS**) và cách khắc phục sự cố màn hình OLED SSD1306.

---

## 1. Yêu Cầu Phần Cứng & Đấu Nối Ngoại Vi

### 1.1. Bo Mạch & Cáp Nối
1. **Board mạch**: ESP32 bất kỳ (ESP32 NodeMCU, ESP32-WROOM-32, ESP32-S3, Heltec WiFi Kit 32).
2. **Cáp Micro-USB hoặc Type-C**: Phải là cáp dữ liệu (Data Cable), không dùng cáp chỉ sạc.
3. **Driver USB-UART**: 
   - Chip CP210x (Silicon Labs) hoặc CH340 / CH9102 / FTDI.
   - Hầu hết Windows 10/11, Linux (kernel 5+) và macOS Monterey/Sonoma/Sequoia đã tích hợp sẵn driver.

### 1.2. Sơ Đồ Đấu Nối Phần Cứng Ngoại Vi
| Thiết Bị | Chân Module | Chân ESP32 Chuẩn (NodeMCU/WROOM) | Ghi Chú |
| :--- | :--- | :--- | :--- |
| **Màn hình OLED SSD1306 (0.96" hoặc 0.91")** | **VCC / VDD** | **3.3V** (Dây Đỏ) | Cấp nguồn 3.3V hoặc 5V |
| | **GND** | **GND** (Dây Đen) | Nối mass chung |
| | **SCK / SCL** | **GPIO 23 (D23)** hoặc **GPIO 22 (D22)** (Dây Vàng) | Đường Clock I2C (firmware tự động quét cả D23 & D22) |
| | **SDA** | **GPIO 21 (D21)** (Dây Xanh) | Đường Data I2C |
| **Đèn LED Đỏ Cảnh Báo (Tùy chọn)** | Anode (+) | **GPIO 4** (D4) qua trở 220Ω | Báo động khi phát hiện tấn công |
| | Cathode (-) | **GND** | |
| **Còi Chíp Buzzer (Tùy chọn)** | VCC (+) | **GPIO 19** (D19) | Kêu ngắt quãng 25ms cảnh báo |
| | GND (-) | **GND** | |

> [!NOTE]
> Bo mạch có sẵn đèn LED onboard màu xanh tại **GPIO 2**. Firmware đã tích hợp sẵn cơ chế nháy đèn GPIO 2 khi có tấn công ngay cả khi bạn không gắn LED ngoài!

---

## 2. Phương Pháp 1: Nạp 1-Click Tự Động Qua CLI (Khuyên Dùng)

Hệ thống hỗ trợ nạp firmware hoàn toàn tự động chỉ với 1 dòng lệnh mà **không cần mở Arduino IDE**, tự động dò tìm cổng USB và tự động đồng bộ cấu hình mạng ngầm (Zero-Config).

### 2.1. Lệnh Nạp 1-Click
- **Trên Windows**:
  ```cmd
  run_system.bat --flash
  ```
  *(Hoặc chạy kèm hệ thống: `run_system.bat --probe esp32 --attack-sim --flash`)*

- **Trên Linux / macOS / WSL**:
  ```bash
  chmod +x run_system.sh
  ./run_system.sh --flash
  ```
  *(Hoặc chỉ định cổng cụ thể: `./run_system.sh --flash --port /dev/ttyUSB0`)*

### 2.2. Cơ Chế Tự Động Hóa (Zero-Config Wi-Fi)
Khi bạn chạy `--flash`:
1. Script tự động phát hiện tên Wi-Fi (SSID) và Mật khẩu của máy tính thông qua lệnh hệ thống ngầm (`netsh` trên Windows, `nmcli` trên Linux, `airport` trên macOS).
2. Tự động phát hiện IPv4 nội bộ của máy tính đang chạy Broker (ví dụ `192.168.1.83`).
3. Tự động ghi vào `firmware/esp32_probe/credentials.h` và file `.env`.
4. Gọi `arduino-cli` ngầm để build và nạp code lên ESP32!

> [!TIP]
> **Lưu ý trên Linux**: Nếu gặp lỗi `Permission Denied` khi truy cập cổng `/dev/ttyUSB0`, hãy thêm user của bạn vào nhóm `dialout`:
> ```bash
> sudo usermod -a -G dialout $USER
> ```
> Sau đó đăng xuất và đăng nhập lại hệ điều hành để quyền có hiệu lực.

---

## 3. Phương Pháp 2: Nạp Bằng Arduino IDE (Thủ Công)

### Bước 3.1: Cài đặt Gói Bo Mạch ESP32
1. Mở **Arduino IDE** $\rightarrow$ **File** $\rightarrow$ **Preferences**.
2. Tại mục *Additional boards manager URLs*, dán URL:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Vào **Tools** $\rightarrow$ **Board** $\rightarrow$ **Boards Manager...**, tìm `esp32` và bấm **Install**.

### Bước 3.2: Cài đặt Thư Viện
Vào **Tools** $\rightarrow$ **Manage Libraries...**, cài đặt:
1. **`PubSubClient`** (bởi Nick O'Leary)
2. **`ArduinoJson`** (bởi Benoit Blanchon - bản 6.x hoặc 7.x)
3. **`Adafruit SSD1306`** (bởi Adafruit)
4. **`Adafruit GFX Library`** (bởi Adafruit)

### Bước 3.3: Cấu hình WiFi & MQTT trong `config.h`
Mở `firmware/esp32_probe/config.h`:
```cpp
#define WIFI_SSID           "Ten_WiFi_Nha_Ban"
#define WIFI_PASSWORD       "Mat_Khau_WiFi"
#define MQTT_BROKER_HOST    "192.168.1.83" // IP may tinh chay Broker
#define MQTT_BROKER_PORT    1883
```

### Bước 3.4: Nạp Code
1. Chọn Board: **ESP32 Dev Module**.
2. Chọn Port: Cổng COM của bo mạch (ví dụ `COM4` trên Win, `/dev/ttyUSB0` trên Linux).
3. Bấm **Upload** (Mũi tên sang phải).
   *(Nếu hiện `Connecting...___...`, nhấn giữ nút **BOOT** trên bo mạch 1-2 giây để bắt đầu nạp)*.

---

## 4. Xử Lý Sự Cố Màn Hình OLED SSD1306 (Troubleshooting)

Nếu màn hình OLED không hiển thị gì (màn hình đen/tối đen), hãy kiểm tra lần lượt các nguyên nhân sau:

### 4.1. Kiểm Tra Serial Monitor & I2C Scanner
Firmware đã tích hợp **bộ quét I2C Bus tự động** trong hàm `initOLED()`. Mở Serial Monitor tại baudrate **`115200`** khi khởi động:
- **Nếu in ra**: `[I2C] -> Phat hien thiet bi tai dia chi: 0x3C` và `[OLED] Khoi tao SSD1306 THANH CONG!`:
  $\rightarrow$ I2C kết nối tốt, màn hình sẽ hiển thị splash screen ngay lập tức.
- **Nếu in ra**: `[I2C] Canh bao: Khong tim thay bat ky thiet bi I2C nao tren bus!`:
  $\rightarrow$ Phần cứng chưa tiếp xúc điện. Hãy kiểm tra:
  1. Dây **VCC** đã cắm đúng 3.3V hoặc 5V chưa?
  2. Dây **GND** đã cắm vào GND của ESP32 chưa?
  3. Dây **SDA** đã cắm đúng **GPIO 21** chưa?
  4. Dây **SCL** đã cắm đúng **GPIO 22** chưa?

### 4.2. Khắc Phục Sai Độ Phân Giải (128x64 vs 128x32)
Nhiều module màn hình là loại nhỏ **0.91 inch (128x32)** thay vì 0.96 inch (128x64). 
- Nếu dùng màn hình 128x32 mà cấu hình trong code là 128x64, IC điều khiển sẽ bị **sai chu kỳ quét multiplex**, dẫn đến **màn hình bị đen hoàn toàn**!
- **Cách khắc phục**: Mở file `firmware/esp32_probe/config.h`, sửa:
  ```cpp
  #define SCREEN_HEIGHT 32  // Đổi từ 64 thành 32 nếu dùng màn 0.91 inch
  ```
  Firmware đã được lập trình giao diện responsive tự động thu gọn layout cho màn hình 32 pixels.

### 4.3. Bo Mạch ESP32 Tích Hợp Sẵn Màn Hình (Heltec / TTGO)
Nếu bạn dùng bo mạch tích hợp sẵn màn hình (ví dụ **Heltec WiFi Kit 32**):
Chân I2C không nằm ở 21/22 mà ở chân riêng:
```cpp
#define PIN_I2C_SDA 4   // Heltec WiFi Kit 32
#define PIN_I2C_SCL 15  // Heltec WiFi Kit 32
#define OLED_RESET  16  // Chân Reset màn hình bắt buộc
```

### 4.4. Tính Năng Tự Động Kết Nối Lại (Auto-Recovery)
Firmware hiện tại có tính năng **OLED Auto-Recovery**: Nếu lúc cắm nguồn dây I2C chưa tiếp xúc hoặc bạn cắm màn hình OLED vào sau khi ESP32 đã boot, ESP32 sẽ tự động dò và thắp sáng màn hình mỗi 5 giây mà bạn không cần phải bấm nút Reset!
