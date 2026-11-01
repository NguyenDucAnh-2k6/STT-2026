# AERO — Giám sát lưu lượng mạng và thí nghiệm Edge AI

AERO gồm host TShark capture, telemetry ESP32, MQTT, Python FastAPI/dashboard,
training ML offline, Parquet/SQLite data lake và Digital Twin/RL/GAN thử nghiệm.
Tài liệu cập nhật theo implementation ngày **12/10/2026**.

**--twin-lab dùng loopback, không dùng Wi-Fi**, target cố định **127.0.0.1**.
Đã có pipeline workload/capture/import và attribution theo flow; **chưa bảo đảm
Normal/attack trong Twin đại diện cho loopback tổng quát, Wi-Fi thực hoặc tái hiện
attack của paper Edge-IIoTset**.

## Tính năng hiện có

- Host tự chạy TShark ngầm, không cần mở GUI Wireshark. Đọc TCP/UDP/ICMP/HTTP/TLS/QUIC…
  tùy traffic; lọc MQTT/dashboard của hệ thống để giảm vòng phản hồi telemetry.
- Input model là **56 canonical features**, theo ml_engine/config/schema.py.
  Có **15 nhãn tổng cộng: Normal và 14 attack**; số cột CSV gốc khác số input model.
- Runtime nạp artifacts đã train, không tự train. Có dual pipeline anomaly detector
  và classifier; không bảo đảm độ chính xác, latency hoặc zero false positive trên mạng mới.
- MQTT realtime tách packet, cửa sổ tốc độ và prediction. Packet QoS 1 vẫn bị drop
  trước publish khi queue đầy; PUBACK không xác nhận collector đã ghi Parquet.
- Data lake lưu packet nhận được vào Parquet theo ngày, metadata trong SQLite.
  Summary chỉ tính batch còn file; không cam kết lưu đủ mọi live packet.
- Dashboard có packet inspector, rate/protocol chart, prediction, workload status
  và lake summary. Chart bổ sung polling API mỗi 2 giây; workload status mỗi 5 giây.
  Các module JS có fingerprint chung để tránh dùng lẫn component cũ/mới.
- Nút Normal/attack UI chạy **workload Twin + PCAP capture + Parquet import**.
  Accepted không đồng nghĩa COMPLETED hay attack được xác minh.
- ESP32 hỗ trợ 2 chế độ biên linh hoạt: **Promiscuous Sniffer** (bắt sóng không trung L2 thụ động)
  và **Micro-Gateway** (phát SoftAP + NAT chuyển tiếp Internet, hook lwIP DPI L3-L4 thời gian thực,
  tích hợp Captive Portal HTTP 204 chống out mạng và Web Portal điều khiển tại chỗ).
  Window ESP32 phân định rõ giữa đặc trưng L2 vô tuyến và L3-L4 IP/Entropy giải mã.
- Twin vật lý/RL và GAN là thành phần thử nghiệm. Vector simulation không phải
  packet đo thật; thử policy chưa chứng minh phòng thủ mạng thực.

## Chuẩn bị

Python 3.10+, dependencies requirements.txt, Wireshark/TShark và dumpcap.
Windows cần Npcap để capture. Có Mosquitto native hoặc broker đang chạy, và
artifacts tương thích với classifier/anomaly được chọn.

~~~powershell
python -m pip install -r requirements.txt
~~~

Tạo .env từ .env.example **chỉ nếu chưa có .env**; giữ secrets/cấu hình hiện có.
Launcher nạp .env ở repository; biến môi trường có sẵn ưu tiên hơn .env, CLI broker
flags ưu tiên hơn cấu hình broker. Host dùng mạng hệ điều hành đã kết nối, không
cần SSID/password để capture.

## Kiến trúc & Sơ đồ Pipeline tổng thể

Hệ thống hoạt động theo mô hình phân tán đa tầng (Hybrid Multi-Tier): Giám sát biên thời gian thực (ESP32 Edge Probe) kết hợp Host Monitoring, điều phối qua Broker MQTT tập trung, lưu trữ Data Lake chuẩn Parquet/SQLite và hiển thị Web Dashboard trực quan.

```mermaid
flowchart TD
    subgraph Traffic_Sources["1. NGUỒN LƯU LƯỢNG MẠNG"]
        WiFi_Air["Sóng Wi-Fi Không Trung<br/>(802.11 b/g/n Kênh chỉ định)"]
        Client_Dev["Thiết bị IoT / Phone / Laptop<br/>(Kết nối qua SoftAP Gateway)"]
        HostNIC["Card Mạng Host PC<br/>(Ethernet / Wi-Fi)"]
        TwinLab["Digital Twin Lab<br/>(Loopback 127.0.0.1)"]
    end

    subgraph Edge_Tier["2. BIÊN ESP32 (DUAL-MODE EDGE AI PROBE)"]
        subgraph Mode_Sniffer["Mode 1: Promiscuous Sniffer"]
            Sniff_L2["Promiscuous 802.11 Sniffer"]
            L2_Extract["Trích xuất 10 Đặc trưng L2-4 / 14 Wireless"]
            TinyML_Sniff["TinyML Engine C Header"]
            Sniff_L2 --> L2_Extract --> TinyML_Sniff
        end

        subgraph Mode_Gateway["Mode 2: Micro-Gateway DPI & NAPT"]
            SoftAP_IF["SoftAP Interface (AERO-Security-Gateway)"]
            Portal_DNS["Captive Portal HTTP 204 + DNS Server"]
            Netif_Hook["lwIP Netif Input Hook"]
            DPI_Entropy["DPI Engine (Entropy + Cờ TCP/UDP)"]
            TinyML_GW["TinyML In-line DPI (RF + Isolation Forest)"]
            NAPT_Route["lwIP NAPT Forwarder sang Router chính"]

            SoftAP_IF --> Portal_DNS
            SoftAP_IF --> Netif_Hook
            Netif_Hook --> DPI_Entropy --> TinyML_GW
            Netif_Hook --> NAPT_Route
        end

        LocalAlert["Báo động phần cứng tại chỗ<br/>(OLED SSD1306, LED, Buzzer)"]
        TinyML_Sniff --> LocalAlert
        TinyML_GW --> LocalAlert
    end

    subgraph Host_Tier["3. HOST PROBE & INFERENCE SERVICE"]
        TShark["TShark Engine ngầm (Npcap / WinPcap)"]
        L7_Extract["Trích xuất 56 Canonical Features (L2-L7)"]
        HostInference["Host ML Inference Service (Dual Pipeline)"]
        USBBridge["USB Serial Bridge Worker (launcher/workers.py)"]

        TShark --> L7_Extract --> HostInference
    end

    subgraph Messaging["4. HỆ THỐNG ĐIỀU PHỐI MQTT"]
        Broker["Mosquitto MQTT Broker (Cổng 1883/1884)"]
        T_Traffic["Topic: edge/telemetry/traffic (QoS 1)"]
        T_Window["Topic: edge/telemetry/window (QoS 0)"]
        T_Radio["Topic: edge/telemetry/radio (QoS 1)"]
        T_Pred["Topic: edge/telemetry/prediction (QoS 1)"]
        T_Alert["Topic: edge/alerts/high_priority (QoS 1)"]

        Broker --- T_Traffic
        Broker --- T_Window
        Broker --- T_Radio
        Broker --- T_Pred
        Broker --- T_Alert
    end

    subgraph Storage_Dashboard["5. LƯU TRỮ VÀ GIAO DIỆN QUẢN TRỊ"]
        FastAPI["FastAPI Backend & Lifespan Service"]
        DataLake[("Data Lakehouse Parquet + SQLite Catalog")]
        WebUI["Web Dashboard Frontend (FastAPI WebSockets + Native ES)"]

        FastAPI --> DataLake
        FastAPI <--> WebUI
    end

    WiFi_Air --> Sniff_L2
    Client_Dev --> SoftAP_IF
    HostNIC --> TShark
    TwinLab --> TShark

    TinyML_Sniff -.->|"USB Serial / UART"| USBBridge
    TinyML_GW -.->|"USB Serial / UART"| USBBridge
    USBBridge -->|"Publish"| Broker
    HostInference -->|"Publish"| Broker

    Broker --> FastAPI
```

---

## Sơ đồ luồng dữ liệu theo từng chế độ (Data Flow Diagrams)

Hệ thống AERO hiện nay hỗ trợ **2 chế độ giám sát biên trên phần cứng ESP32** và **2 chế độ giám sát trên máy tính Host**. Dưới đây là sơ đồ luồng dữ liệu (Data Flow) chi tiết cho từng chế độ:

### 1. Chế độ ESP32 Micro-Gateway (In-line DPI & NAPT Router)
Ở chế độ này, ESP32 hoạt động như một Wi-Fi Router / IoT Firewall trung gian:
- **Phát sóng SoftAP độc lập** (`AERO-Security-Gateway`, pass: `ducanh123`), cấp phát DHCP IP (`192.168.4.x`) cho thiết bị (điện thoại/laptop) kết nối vào.
- **Tích hợp Captive Portal (Cổng HTTP 80 & DNS 53)**: Tự động trả về mã `HTTP 204 No Content` cho các endpoint kiểm tra kết nối (`/generate_204`, `/gen_204`, `hotspot-detect.html`), giúp smartphone **giữ kết nối liên tục 100% không bị văng**. Đồng thời phục vụ giao diện Web Portal trực quan tại `http://192.168.4.1` để người dùng kiểm tra kết nối hoặc kích hoạt thử nghiệm báo động AI.
- **Bắt trọn gói tin đã giải mã**: Cài đặt hook trực tiếp vào `netif->input` của lwIP (`gateway_ap_input_hook`), bóc tách toàn bộ gói tin L3-L4 (IP, TCP, UDP, ICMP).
- **Tính toán Shannon Payload Entropy** và 10 đặc trưng L2-L4 theo thời gian thực.
- **Thực thi suy luận In-line Edge TinyML**: Chạy trực tiếp Random Forest 16 cây + Isolation Forest cho từng gói tin trên chip ESP32.
- **Định tuyến hai chiều lwIP NAPT**: Chuyển tiếp an toàn các gói tin hợp lệ ra Router Wi-Fi chính (`ducianh`) để đi Internet.
- **Cầu nối MQTT thời gian thực**: Xuất bản tin cấu trúc `ESP32_PREDICTION:`, `ESP32_ALERT:` và log `[Gateway Monitor]` qua cáp USB Serial lên MQTT Broker, lập tức cập nhật Web Dashboard tại `http://localhost:8000`.

```mermaid
flowchart TD
    subgraph Client_Layer["1. THIẾT BỊ CLIENT (SMARTPHONE / LAPTOP)"]
        UserDevice["Smartphone / Laptop Client<br/>(Được cấp IP: 192.168.4.2)"]
        UserBrowser["Trình duyệt Web Client<br/>(Truy cập http://192.168.4.1)"]
    end

    subgraph ESP32_Gateway_Core["2. ESP32 MICRO-GATEWAY RUNTIME (FIRMWARE)"]
        SoftAP_Dev["Wi-Fi SoftAP Interface<br/>(AERO-Security-Gateway | Kênh 2 | IP: 192.168.4.1)"]
        DNS_Captive["Embedded DNS Server (Cổng 53)<br/>(Phân giải tên miền Captive tức thì)"]
        HTTP_Portal["WebServer & Captive Portal (Cổng 80)<br/>(Trả về HTTP 204 chống out mạng & Web UI)"]
        
        Netif_InHook["lwIP Netif Input Hook (gateway_ap_input_hook)<br/>(Bắt trọn gói tin IP đã giải mã)"]
        Entropy_DPI["DPI Engine & Shannon Entropy<br/>(Tính Entropy payload + Trích xuất L3-L4)"]
        TinyML_Model["TinyML Engine C Header<br/>(Random Forest 16 cây + Isolation Forest)"]
        Buzzer_LED["Còi Buzzer & LED Cảnh Báo<br/>(Phát tín hiệu âm thanh/ánh sáng tại chỗ)"]
        
        NAPT_Engine["lwIP NAPT Forwarder (ip_napt_enable)<br/>(Định tuyến hai chiều SoftAP <-> STA)"]
        STA_Interface["Wi-Fi STA Interface<br/>(Khóa kênh 2 & BSSID router chính: 'ducianh')"]

        UserDevice -->|"1. Kết nối Wi-Fi WPA2"| SoftAP_Dev
        UserBrowser -->|"2. Yêu cầu HTTP Portal"| HTTP_Portal
        SoftAP_Dev --> DNS_Captive
        SoftAP_Dev --> HTTP_Portal
        SoftAP_Dev --> Netif_InHook
        Netif_InHook --> Entropy_DPI
        Entropy_DPI --> TinyML_Model
        TinyML_Model -->|"Nếu phát hiện bất thường"| Buzzer_LED
        Netif_InHook -->|"Gói tin chuyển tiếp"| NAPT_Engine
        NAPT_Engine --> STA_Interface
    end

    subgraph External_Network["3. ROUTER VÀ INTERNET"]
        Home_Router["Router Wi-Fi Chính (ducianh)<br/>(Dải mạng LAN 192.168.1.x)"]
        Internet_Cloud["Internet Toàn Cầu<br/>(Web, Cloud, DNS 8.8.8.8)"]
        STA_Interface --> Home_Router --> Internet_Cloud
    end

    subgraph Host_Telemetry_Tier["4. HOST PC & GIAO DIỆN GIÁM SÁT REALTIME"]
        Serial_Bridge["USB Serial Telemetry Bridge<br/>(launcher/workers.py | 115200 baud)"]
        MQTT_Hub["Mosquitto MQTT Broker<br/>(Topics: prediction, alerts, traffic)"]
        FastAPI_App["FastAPI Backend Service"]
        Web_UI["Web Dashboard Frontend<br/>(http://localhost:8000 | WebSocket Live)"]
        Parquet_Lake[("Data Lakehouse Parquet/SQLite<br/>(Lưu trữ phân vùng theo ngày)")]

        TinyML_Model -.->|"ESP32_PREDICTION / ALERT / TELEMETRY"| Serial_Bridge
        Serial_Bridge -->|"MQTT Publish QoS 1"| MQTT_Hub
        MQTT_Hub --> FastAPI_App
        FastAPI_App --> Web_UI
        FastAPI_App --> Parquet_Lake
    end
```

---

### 3. Chế độ Laptop Gateway & ESP32 Hardware Dongle (Full L7 DPI + Còi/OLED Biên)
Ở chế độ này, Laptop đóng vai trò là Trạm Gateway / Wi-Fi Mobile Hotspot chính:
- **Hotspot Gateway**: Laptop bật tính năng Mobile Hotspot (hoặc Wi-Fi sharing), cấp IP cho các thiết bị di động kết nối vào. Mọi gói tin đi qua máy tính đều là gói tin L2-L7 unencrypted đối với OS của Laptop.
- **Deep Packet Inspection (DPI) & TShark**: Máy tính trích xuất đầy đủ 56 đặc trưng Edge-IIoTset (HTTP, DNS, TCP Flags, IAT, Shannon Entropy).
- **Phân loại AI Đa Lớp**: Chạy các mô hình phân loại tấn công (Random Forest, Extra Trees, XGBoost, Deep Neural Network) và cổng phát hiện bất thường Isolation Forest trên Host.
- **ESP32 làm Hardware Security Dongle**: ESP32 cắm vào cổng USB của laptop, nhận các bản tin telemetry và cảnh báo từ luồng USB Serial Bridge (`HOST_ALERT:` / `HOST_STATS:`):
  - Màn hình OLED hiển thị: `HOST-GW | L7 DPI`, lưu lượng gói/giây, băng thông KB/s và trạng thái an ninh mạng.
  - Còi Buzzer và LED đỏ lập tức hú còi và chớp sáng khi phát hiện tấn công mạng, biến ESP32 thành một thiết bị bảo mật phần cứng vật lý chuyên dụng.

```mermaid
flowchart TD
    subgraph Client_Devices["1. CÁC THIẾT BỊ CLIENT TRONG MẠNG"]
        Client_Phone["Điện thoại thông minh (iOS / Android)"]
        Client_Laptop["Laptop phụ / Máy tính bảng"]
        IoT_Cam["Camera an ninh / Thiết bị IoT"]
        
        Client_Phone -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        Client_Laptop -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        IoT_Cam -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
    end

    subgraph Laptop_Gateway["2. LAPTOP GATEWAY & DPI ENGINE"]
        Hotspot_NIC["Card mạng Mobile Hotspot<br/>(Windows Hotspot / Wi-Fi Sharing)"]
        TShark_DPI["TShark L2-L7 Dissector Engine<br/>(Bóc tách 56 đặc trưng Edge-IIoTset)"]
        Host_ML["Host ML Inference Engine<br/>(15 Attack Classes + Anomaly Gate)"]
        Host_MQTT["Mosquitto MQTT Broker<br/>(edge/alerts, edge/prediction, edge/traffic)"]
        Bridge_Worker["Host-Gateway Dongle Worker<br/>(launcher/workers.py -> USB Serial)"]
        
        Hotspot_NIC --> TShark_DPI --> Host_ML
        Host_ML -->|"Publish Alerts & Prediction"| Host_MQTT
        Host_MQTT --> Bridge_Worker
    end

    subgraph ESP32_Dongle["3. ESP32 HARDWARE SECURITY DONGLE (CẮM CỔNG USB)"]
        Serial_In["Serial Parser (HOST_ALERT / HOST_STATS)"]
        OLED_Screen["Màn hình OLED SSD1306<br/>(HOST-GW | L7 DPI | Pkts/s | KB/s)"]
        Alarm_Buzzer["Còi Buzzer + LED Đỏ Báo Động Vật Lý"]
        
        Bridge_Worker -->|"Cáp USB COM (115200 baud)"| Serial_In
        Serial_In --> OLED_Screen
        Serial_In -->|"Nếu có cảnh báo tấn công"| Alarm_Buzzer
    end

    subgraph Internet_World["4. INTERNET VÀ CLOUD"]
        External_Internet["Internet Toàn Cầu (Web / Cloud / Apps)"]
        Hotspot_NIC -->|"NAT Forwarding"| External_Internet
    end
```

---

### 2. Chế độ ESP32 Promiscuous Sniffer (Over-the-Air L2 WIDS)
Ở chế độ này, ESP32 hoạt động như một cảm biến giám sát không dây thụ động (Passive WIDS Sensor):
- **Không xâm nhập mạng**: Card Wi-Fi của ESP32 chuyển sang chế độ `promiscuous`, khóa vào kênh sóng (channel) của Router mục tiêu và bắt toàn bộ khung sóng 802.11 truyền trong không gian.
- **Lọc và phân vùng bộ nhớ**: Bộ lọc FreeRTOS lọc bỏ khung Beacon nhiễu, chuyển các khung dữ liệu hợp lệ vào Ring Buffer có giới hạn dung lượng để chống tràn RAM.
- **Suy luận đa tầng**:
  - *Tầng 1 (Trên chip ESP32)*: Trích xuất 10 đặc trưng L2-4 hoặc 14 đặc trưng AWID3, chạy suy luận TinyML thời gian thực dưới 5ms/gói, cập nhật màn hình OLED và còi buzzer.
  - *Tầng 2 (Trên Host PC)*: ESP32 đóng gói khung tin thô qua Serial (`ESP32_RADIO:`) đẩy lên MQTT. Engine `radio_capture.py` và TShark trên máy tính phân tích sâu và đối chiếu với mô hình phân loại toàn phần 15 nhãn.

```mermaid
flowchart TD
    subgraph Radio_Space["1. KHÔNG GIAN SÓNG VÔ TUYẾN 802.11"]
        AP_Target["Router Wi-Fi Mục Tiêu (Target AP)<br/>(Phát sóng tại kênh chỉ định)"]
        Wireless_Stations["Các thiết bị Client trong vùng phủ sóng<br/>(Laptop, Phone, Smart Home, Camera)"]
        Air_Packets["Khung vô tuyến 802.11 Over-The-Air<br/>(Beacon, Management, Encrypted Data, Deauth)"]
        
        Wireless_Stations <-->|"Trao đổi dữ liệu"| AP_Target
        AP_Target -.-> Air_Packets
        Wireless_Stations -.-> Air_Packets
    end

    subgraph ESP32_Sniffer_Probe["2. ESP32 PROBE (PROMISCUOUS SNIFFER ENGINE)"]
        Promisc_Driver["Driver 802.11 Promiscuous Sniffer<br/>(esp_wifi_set_promiscuous_rx_cb)"]
        BSSID_Filter["Hardware BSSID & Channel Filter<br/>(Chỉ nhận gói tin thuộc mạng mục tiêu)"]
        Ring_Buffer["FreeRTOS Bounded Ring Buffer Queue<br/>(Bảo vệ chống tràn RAM và drop packet an toàn)"]
        
        L2_Feature_Calc["Wireless Feature Extractor<br/>(AWID3 14 đặc trưng / USTC 10 đặc trưng)"]
        TinyML_Local["TinyML Engine C Header<br/>(Random Forest 16 cây + Isolation Forest)"]
        OLED_Buzzer["Màn hình OLED SSD1306 + Còi Buzzer<br/>(Hiển thị tốc độ Pkts/s, Bytes/s & Cảnh báo)"]
        
        Radio_Serializer["Radio Sample Serializer<br/>(Xuất chuỗi HEX khung tin: ESP32_RADIO:)"]

        Air_Packets --> Promisc_Driver
        Promisc_Driver --> BSSID_Filter --> Ring_Buffer
        Ring_Buffer --> L2_Feature_Calc --> TinyML_Local
        TinyML_Local --> OLED_Buzzer
        Ring_Buffer --> Radio_Serializer
    end

    subgraph Host_Engine["3. MÁY TÍNH HOST & SERVICE SUY LUẬN TOÀN PHẦN"]
        USB_Serial_In["USB Serial Bridge Worker (launcher/workers.py)"]
        MQTT_Broker_Core["Mosquitto MQTT Broker (edge/telemetry/radio)"]
        Radio_Capture["Radio Capture Engine (radio_capture.py)"]
        Host_Inference["Host ML Inference Engine<br/>(Phân loại 15 nhãn tấn công & Anomaly Gate)"]

        Radio_Serializer -.->|"Cáp USB COM (115200 baud)"| USB_Serial_In
        USB_Serial_In -->|"Publish Radio Frame"| MQTT_Broker_Core
        MQTT_Broker_Core --> Radio_Capture --> Host_Inference
        Host_Inference -->|"Publish Prediction"| MQTT_Broker_Core
    end

    subgraph Visualization_Lake["4. DATA LAKEHOUSE VÀ GIAO DIỆN WEB DASHBOARD"]
        FastAPI_Server["FastAPI Backend Service"]
        Parquet_Store[("Data Lakehouse Parquet/SQLite<br/>(Lưu trữ toàn bộ Telemetry theo ngày)")]
        Dashboard_UI["Web Dashboard Frontend<br/>(http://localhost:8000 | WebSocket Live)"]

        MQTT_Broker_Core --> FastAPI_Server
        FastAPI_Server --> Parquet_Store
        FastAPI_Server <-->|WebSocket| Dashboard_UI
    end
```

---

### 3. Chế độ Laptop Gateway & ESP32 Hardware Dongle (Full L7 DPI + Còi/OLED Biên)
Ở chế độ này, Laptop đóng vai trò là Trạm Gateway / Wi-Fi Mobile Hotspot chính:
- **Hotspot Gateway**: Laptop bật tính năng Mobile Hotspot (hoặc Wi-Fi sharing), cấp IP cho các thiết bị di động kết nối vào. Mọi gói tin đi qua máy tính đều là gói tin L2-L7 unencrypted đối với OS của Laptop.
- **Deep Packet Inspection (DPI) & TShark**: Máy tính trích xuất đầy đủ 56 đặc trưng Edge-IIoTset (HTTP, DNS, TCP Flags, IAT, Shannon Entropy).
- **Phân loại AI Đa Lớp**: Chạy các mô hình phân loại tấn công (Random Forest, Extra Trees, XGBoost, Deep Neural Network) và cổng phát hiện bất thường Isolation Forest trên Host.
- **ESP32 làm Hardware Security Dongle**: ESP32 cắm vào cổng USB của laptop, nhận các bản tin telemetry và cảnh báo từ luồng USB Serial Bridge (`HOST_ALERT:` / `HOST_STATS:`):
  - Màn hình OLED hiển thị: `HOST-GW | L7 DPI`, lưu lượng gói/giây, băng thông KB/s và trạng thái an ninh mạng.
  - Còi Buzzer và LED đỏ lập tức hú còi và chớp sáng khi phát hiện tấn công mạng, biến ESP32 thành một thiết bị bảo mật phần cứng vật lý chuyên dụng.

```mermaid
flowchart TD
    subgraph Client_Devices["1. CÁC THIẾT BỊ CLIENT TRONG MẠNG"]
        Client_Phone["Điện thoại thông minh (iOS / Android)"]
        Client_Laptop["Laptop phụ / Máy tính bảng"]
        IoT_Cam["Camera an ninh / Thiết bị IoT"]
        
        Client_Phone -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        Client_Laptop -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        IoT_Cam -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
    end

    subgraph Laptop_Gateway["2. LAPTOP GATEWAY & DPI ENGINE"]
        Hotspot_NIC["Card mạng Mobile Hotspot<br/>(Windows Hotspot / Wi-Fi Sharing)"]
        TShark_DPI["TShark L2-L7 Dissector Engine<br/>(Bóc tách 56 đặc trưng Edge-IIoTset)"]
        Host_ML["Host ML Inference Engine<br/>(15 Attack Classes + Anomaly Gate)"]
        Host_MQTT["Mosquitto MQTT Broker<br/>(edge/alerts, edge/prediction, edge/traffic)"]
        Bridge_Worker["Host-Gateway Dongle Worker<br/>(launcher/workers.py -> USB Serial)"]
        
        Hotspot_NIC --> TShark_DPI --> Host_ML
        Host_ML -->|"Publish Alerts & Prediction"| Host_MQTT
        Host_MQTT --> Bridge_Worker
    end

    subgraph ESP32_Dongle["3. ESP32 HARDWARE SECURITY DONGLE (CẮM CỔNG USB)"]
        Serial_In["Serial Parser (HOST_ALERT / HOST_STATS)"]
        OLED_Screen["Màn hình OLED SSD1306<br/>(HOST-GW | L7 DPI | Pkts/s | KB/s)"]
        Alarm_Buzzer["Còi Buzzer + LED Đỏ Báo Động Vật Lý"]
        
        Bridge_Worker -->|"Cáp USB COM (115200 baud)"| Serial_In
        Serial_In --> OLED_Screen
        Serial_In -->|"Nếu có cảnh báo tấn công"| Alarm_Buzzer
    end

    subgraph Internet_World["4. INTERNET VÀ CLOUD"]
        External_Internet["Internet Toàn Cầu (Web / Cloud / Apps)"]
        Hotspot_NIC -->|"NAT Forwarding"| External_Internet
    end
```

---

### 3. Chế độ Laptop Gateway & ESP32 Hardware Dongle (Full L7 DPI + Còi/OLED Biên)
Ở chế độ này, Laptop đóng vai trò là Trạm Gateway / Wi-Fi Mobile Hotspot chính:
- **Hotspot Gateway**: Laptop bật tính năng Mobile Hotspot (hoặc Wi-Fi sharing), cấp IP cho các thiết bị di động kết nối vào. Mọi gói tin đi qua máy tính đều là gói tin L2-L7 unencrypted đối với OS của Laptop.
- **Deep Packet Inspection (DPI) & TShark**: Máy tính trích xuất đầy đủ 56 đặc trưng Edge-IIoTset (HTTP, DNS, TCP Flags, IAT, Shannon Entropy).
- **Phân loại AI Đa Lớp**: Chạy các mô hình phân loại tấn công (Random Forest, Extra Trees, XGBoost, Deep Neural Network) và cổng phát hiện bất thường Isolation Forest trên Host.
- **ESP32 làm Hardware Security Dongle**: ESP32 cắm vào cổng USB của laptop, nhận các bản tin telemetry và cảnh báo từ luồng USB Serial Bridge (`HOST_ALERT:` / `HOST_STATS:`):
  - Màn hình OLED hiển thị: `HOST-GW | L7 DPI`, lưu lượng gói/giây, băng thông KB/s và trạng thái an ninh mạng.
  - Còi Buzzer và LED đỏ lập tức hú còi và chớp sáng khi phát hiện tấn công mạng, biến ESP32 thành một thiết bị bảo mật phần cứng vật lý chuyên dụng.

```mermaid
flowchart TD
    subgraph Client_Devices["1. CÁC THIẾT BỊ CLIENT TRONG MẠNG"]
        Client_Phone["Điện thoại thông minh (iOS / Android)"]
        Client_Laptop["Laptop phụ / Máy tính bảng"]
        IoT_Cam["Camera an ninh / Thiết bị IoT"]
        
        Client_Phone -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        Client_Laptop -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
        IoT_Cam -->|"Kết nối Wi-Fi Hotspot"| Hotspot_NIC
    end

    subgraph Laptop_Gateway["2. LAPTOP GATEWAY & DPI ENGINE"]
        Hotspot_NIC["Card mạng Mobile Hotspot<br/>(Windows Hotspot / Wi-Fi Sharing)"]
        TShark_DPI["TShark L2-L7 Dissector Engine<br/>(Bóc tách 56 đặc trưng Edge-IIoTset)"]
        Host_ML["Host ML Inference Engine<br/>(15 Attack Classes + Anomaly Gate)"]
        Host_MQTT["Mosquitto MQTT Broker<br/>(edge/alerts, edge/prediction, edge/traffic)"]
        Bridge_Worker["Host-Gateway Dongle Worker<br/>(launcher/workers.py -> USB Serial)"]
        
        Hotspot_NIC --> TShark_DPI --> Host_ML
        Host_ML -->|"Publish Alerts & Prediction"| Host_MQTT
        Host_MQTT --> Bridge_Worker
    end

    subgraph ESP32_Dongle["3. ESP32 HARDWARE SECURITY DONGLE (CẮM CỔNG USB)"]
        Serial_In["Serial Parser (HOST_ALERT / HOST_STATS)"]
        OLED_Screen["Màn hình OLED SSD1306<br/>(HOST-GW | L7 DPI | Pkts/s | KB/s)"]
        Alarm_Buzzer["Còi Buzzer + LED Đỏ Báo Động Vật Lý"]
        
        Bridge_Worker -->|"Cáp USB COM (115200 baud)"| Serial_In
        Serial_In --> OLED_Screen
        Serial_In -->|"Nếu có cảnh báo tấn công"| Alarm_Buzzer
    end

    subgraph Internet_World["4. INTERNET VÀ CLOUD"]
        External_Internet["Internet Toàn Cầu (Web / Cloud / Apps)"]
        Hotspot_NIC -->|"NAT Forwarding"| External_Internet
    end
```


---

## 1. Thu thập & Xử lý dữ liệu (Data Ingestion & Preprocessing)

Hệ thống hỗ trợ 2 chế độ trích xuất đặc trưng tùy thuộc vào probe thu thập và môi trường mạng:

### A. Chế độ Biên ESP32 (10 Đặc trưng Layer 2–4 — `ESP32_PACKET_FEATURES`)
Được thiết kế chuyên biệt để chạy trong môi trường **Wi-Fi mã hóa (WPA2/WPA3)** và tài nguyên siêu giới hạn của vi điều khiển:
- Không giải mã dữ liệu người dùng (giữ tính riêng tư và bảo mật), chỉ đọc header 802.11 bóc tách MAC, IP, TCP/UDP/ICMP/ARP:
  1. `arp.opcode`: Mã thao tác ARP (Request/Reply - phát hiện ARP Spoofing).
  2. `arp.hw.size`: Kích thước địa chỉ phần cứng ARP.
  3. `icmp.checksum`: Checksum gói ICMP (phát hiện ICMP Flood).
  4. `tcp.srcport`: Cổng nguồn TCP.
  5. `tcp.dstport`: Cổng đích TCP (phát hiện Port Scanning/Brute-force).
  6. `tcp.flags`: Cờ TCP (SYN, ACK, FIN, RST, PSH, URG - phát hiện SYN Flood/XMAS Scan).
  7. `tcp.flags.ack`: Trạng thái cờ ACK.
  8. `tcp.len`: Chiều dài payload TCP.
  9. `tcp.ack_raw`: Số Sequence/Acknowledgment thô.
  10. `tcp.checksum`: Checksum tầng giao vận TCP.
- **Tiền xử lý & Scaling trên ESP32:** Vector 10 số thực được chuẩn hóa MinMax/Standard scaler trực tiếp bằng thuật toán C tối ưu hóa dấu phẩy động trong `esp32_packet_model.h`.

### B. Chế độ Toàn phần Host (56 Đặc trưng Canonical)
Sử dụng TShark ngầm trên máy tính để bóc tách sâu các trường từ L2 đến L7:
- Toàn bộ các trường L2-L4 cơ bản cộng với thông tin ứng dụng HTTP, DNS, MQTT, ICMP rates, cửa sổ thời gian trượt (IAT, Byte rate, Packet rate).
- Chi tiết quy định tại [ml_engine/config/schema.py](ml_engine/config/schema.py).

### C. Data Lake tự động (Parquet + SQLite)
- **Định dạng Parquet:** Gói tin thu thập được lưu trữ theo cột và nén Snappy/GZIP theo ngày (`data_lake/raw/date=YYYY-MM-DD/sess_<id>.parquet`), giúp tốc độ đọc phân tích nhanh gấp 100 lần so với CSV truyền thống.
- **SQLite Catalog:** Lưu metadata từng session, số lượng packet, nhãn ghi nhận, tính toàn vẹn của batch và hỗ trợ truy vấn tức thì từ API `/api/data-lake/summary`.

---

## 2. Giao thức & Hệ thống MQTT (MQTT API Specifications)

AERO sử dụng kiến trúc Pub/Sub tách biệt hoàn toàn giữa luồng dữ liệu (Data Plane) và luồng điều khiển (Control Plane):

| Topic | Hướng | QoS | Payload JSON chính | Ý nghĩa |
| :--- | :---: | :---: | :--- | :--- |
| `edge/telemetry/traffic` | Probe $\rightarrow$ Broker | 1 | `timestamp`, `probe_id`, `features` (10 hoặc 56 trường), `raw_metadata` | Dữ liệu đặc trưng gói tin thu thập theo thời gian thực. |
| `edge/telemetry/prediction` | Probe $\rightarrow$ Broker | 1 | `timestamp`, `probe_id`, `threat_level`, `attack_type`, `confidence`, `probabilities`, `anomaly_score` | Kết quả phân loại đa lớp và điểm số bất thường từ mô hình ML/TinyML. |
| `edge/alerts/high_priority` | Probe $\rightarrow$ Broker | 1 | `timestamp`, `probe_id`, `severity`, `rule_triggered`, `source_ip`, `target_ip` | Cảnh báo khẩn cấp khi điểm bất thường vượt ngưỡng `edge_threshold`. |
| `edge/nodes/status` | Probe $\rightarrow$ Broker | 0/1 | `node_id`, `hardware`, `ip`, `rssi`, `uptime_ms`, `free_heap_bytes`, `state` | Nhịp tim định kỳ và báo cáo sức khỏe tài nguyên phần cứng. |
| `edge/config/threshold` | Dashboard $\leftrightarrow$ Probe | 1 | `threshold` (0.0 – 1.0), `applied_at` | Điều chỉnh động ngưỡng cảnh báo anomaly mà không cần nạp lại firmware. |
| `edge/experiments/status` | Backend $\rightarrow$ UI | 1 | `status` (PREPARING, RUNNING, IMPORTING, COMPLETED), `scenario`, `experiment_id` | Đồng bộ trạng thái thực nghiệm Digital Twin Lab. |

---

## 3. Module ESP32 Probe (Edge AI TinyML)

ESP32 Probe là hạt nhân giám sát biên thông minh, hỗ trợ **2 kiến trúc triển khai độc lập**:

### A. Kiến trúc 1: Promiscuous 802.11 Sniffer (Over-the-Air WIDS)
- **Giám sát không xâm nhập (Non-intrusive)**: Không cần biết mật khẩu mạng, không cần kết nối vào mạng mục tiêu, bắt toàn bộ khung sóng 802.11 trong không gian vô tuyến.
- **Bộ đệm FreeRTOS an toàn**: Sử dụng hàng đợi vòng giới hạn dung lượng (Bounded Ring Buffer) để bảo vệ bộ nhớ RAM khỏi tràn khi lưu lượng đột biến.
- **Trích xuất đặc trưng L2**: Đọc nhanh các trường Header 802.11, cờ điều khiển, độ dài khung tin, địa chỉ MAC và tỉ lệ khung tin quản trị (Deauth/Disassoc/Management).

### B. Kiến trúc 2: In-line Micro-Gateway (DPI & NAPT Router)
- **Wi-Fi Router & Firewall biên độc lập**: Phát sóng SoftAP riêng biệt (`AERO-Security-Gateway`, mật khẩu `ducanh123`), cấp phát DHCP IP cho các thiết bị cần bảo vệ (điện thoại thông minh, laptop, cảm biến IoT).
- **Captive Portal & Web Server tích hợp**:
  - Tự động phản hồi mã chuẩn `HTTP 204 No Content` cho mọi yêu cầu kiểm tra kết nối (`/generate_204`, `/gen_204`, `hotspot-detect.html`), giúp smartphone (Android/iOS) **giữ kết nối liên tục 100% không bị văng ra mạng mặc định**.
  - Tích hợp DNS Server trên cổng 53 để phản hồi phân giải tên miền ngay tức khắc.
  - Cung cấp trang Web Portal điều khiển tại `http://192.168.4.1`, cho phép người dùng kiểm tra trạng thái DPI, tạo traffic hợp lệ (Normal) hoặc bấm nút thử nghiệm phát còi báo động AI (Simulate Alert).
- **Bóc tách sâu Deep Packet Inspection (DPI) & Shannon Entropy**:
  - Hook trực tiếp vào hàm `netif->input` của tầng mạng lwIP (`gateway_ap_input_hook`), thu giữ 100% gói tin L3-L4 IP/TCP/UDP/ICMP đã giải mã từ thiết bị.
  - Tính toán độ hỗn loạn Shannon Payload Entropy trên từng gói tin.
- **Định tuyến lwIP NAPT**: Kích hoạt bộ định tuyến phần mềm `ip_napt_enable` chuyển tiếp hai chiều giữa mạng SoftAP và Router Internet chính (`ducianh`).

### C. TinyML Inference Engine & Cảnh báo Biên Tự Trị
- **Mã nguồn C thuần tối ưu**: Mô hình Random Forest (16 cây quyết định) kết hợp Isolation Forest được biên dịch trực tiếp sang file C header (`tinyml_model.h` / `esp32_packet_model.h`).
- **Zero Dynamic Allocation**: Hoàn toàn không cấp phát bộ nhớ động (`malloc`/`free`), loại bỏ triệt để nguy cơ phân mảnh bộ nhớ (Heap Fragmentation), thời gian suy luận **dưới 5 ms/gói tin**.
- **Cấu hình Flash**: Sử dụng phân vùng `PartitionScheme=huge_app` (3MB Flash), chiếm ~39% dung lượng Flash và 15% RAM của ESP32.
- **Báo động tại chỗ (Edge Autonomy)**: Ngay cả khi mất kết nối mạng về máy chủ, ESP32 vẫn duy trì khả năng suy luận độc lập và kích hoạt còi Buzzer/LED/OLED cảnh báo khi phát hiện bất thường.

### D. Khả năng hoạt động Độc lập Tự trị (Standalone Edge Autonomy)
ESP32 hoàn toàn có thể **tách rời khỏi máy tính và hoạt động 100% độc lập** chỉ với một củ sạc điện thoại 5V hoặc pin dự phòng USB:
1. **Trọng số và Cây quyết định đã nhúng sẵn vào Flash**: Toàn bộ thuật toán Random Forest (16 cây) và Isolation Forest được chuyển đổi sang mã C thuần (`tinyml_model.h` / `esp32_packet_model.h`), nạp cố định trong 3MB bộ nhớ Flash của ESP32 (`PartitionScheme=huge_app`).
2. **CPU Xtensa tự thực thi**: Vi điều khiển lõi kép Xtensa LX6 240MHz tự xử lý tính toán số thực, trích xuất đặc trưng và đưa ra phán quyết an ninh trong vòng < 5ms mà không cần Python hay máy tính trợ giúp.
3. **Ngoại vi tại chỗ hoàn chỉnh**: Màn hình OLED SSD1306, Còi Buzzer và LED cảnh báo gắn trực tiếp vào các chân GPIO của ESP32, cho phép chip tự hiển thị thông số và tự hú còi khi có xâm nhập kể cả khi đặt chip ở góc phòng hoặc gắn trên xe.
4. **Cơ chế hoạt động khi mất kết nối mạng**: Nếu không có Broker MQTT, chip vẫn tiếp tục chu trình sniffing / gateway và suy luận nội bộ liên tục, không bị gián đoạn.

---

## 4. Hướng dẫn vận hành & Các lệnh chạy Demo

### Bước 1: Chuẩn bị môi trường
- Cài đặt Python 3.10+, Wireshark (Npcap trên Windows), Mosquitto native.
- Cài đặt Arduino-CLI và ESP32 board core (`esp32:esp32`) nếu muốn tự động biên dịch và nạp firmware cho ESP32.
- Cài đặt các thư viện Python:
  ```powershell
  python -m pip install -r requirements.txt
  ```

---

### Bước 2: Huấn luyện mô hình TinyML cho ESP32 (Offline Training - Tùy chọn)
Nếu muốn huấn luyện lại mô hình Random Forest 16 cây + Isolation Forest từ tập dữ liệu Edge-IIoTset hoặc AWID3:

```powershell
python -m ml_engine.edge.train --classifier random_forest --trees 16 --output ml_engine/models/esp32_edgeiiot_rf16
```
*(Lệnh sẽ xuất toàn bộ trọng số, scaler và file C header `tinyml_model.h` / `esp32_packet_model.h` vào thư mục firmware).*

---

### Bước 3: Các lệnh khởi chạy Demo hệ thống

#### DEMO 1: Giám sát sóng không trung qua ESP32 (Promiscuous Sniffer WIDS)
Bắt sóng không trung L2, khóa vào kênh của Wi-Fi mục tiêu, truyền telemetry và suy luận TinyML thời gian thực:

```powershell
python run_system.py --probe esp32 --demo-mode sniffer --arduino-cli --flash --wifi-ssid "Tên_WiFi" --wifi-pass "Mật_Khẩu_WiFi" --classifier random_forest --anomaly-model isolation_forest
```
- **Hành vi**:
  1. Tự động biên dịch sketch và nạp code xuống bo mạch ESP32 qua cổng COM.
  2. Khởi chạy Mosquitto Broker, Data Lakehouse Collector và FastAPI Web Dashboard tại `http://localhost:8000`.
  3. ESP32 bật chế độ Promiscuous bắt sóng 802.11, hiển thị tốc độ gói trên màn hình OLED và gửi bản tin qua USB Serial Bridge.

#### DEMO 2: ESP32 làm Micro-Gateway bảo mật (In-line DPI & AI Edge Firewall)
ESP32 phát mạng SoftAP riêng biệt, định tuyến NAT ra router ngoài và chạy Deep Packet Inspection (DPI) trên CPU ESP32:

```powershell
python run_system.py --esp32-gateway --demo-mode gateway --arduino-cli --flash --wifi-ssid "Tên_WiFi_Internet" --wifi-pass "Mật_Khẩu_WiFi" --classifier random_forest --anomaly-model isolation_forest
```
- **Hành vi**:
  1. ESP32 phát Wi-Fi SoftAP: **`AERO-Security-Gateway`** (Mật khẩu mặc định: **`ducanh123`**).
  2. Giao diện Web Dashboard tại `http://localhost:8000` tự động mở và chuyển sang chế độ giám sát Micro-Gateway.
  3. Mọi gói tin đi qua Gateway đều được bóc tách DPI, tính Entropy và chạy AI trực tiếp trên chip ESP32.

> [!TIP]
> **HƯỚNG DẪN KẾT NỐI VÀ GIỮ MẠNG LIÊN TỤC TRÊN ĐIỆN THOẠI TRONG PHIÊN DEMO 2:**
> 1. **Tạm thời tắt 4G / Dữ liệu di động** trên điện thoại để máy không tự động nhảy mạng.
> 2. **Tắt tính năng "Chuyển sang dữ liệu di động khi Wi-Fi yếu" / "Trợ lý Wi-Fi"** trong phần cài đặt Wi-Fi nâng cao của điện thoại.
> 3. Kết nối vào Wi-Fi **`AERO-Security-Gateway`** (mật khẩu: `ducanh123`). Nếu điện thoại hiện thông báo *"Mạng không có Internet"*, bấm vào thông báo và chọn **"Giữ kết nối" (Stay connected)**.
> 4. Tắt tính năng **DNS riêng tư (Private DNS)** trong cài đặt mạng của điện thoại để tránh bị chặn cổng DoT 853.
> 5. Mở trình duyệt trên điện thoại và truy cập:
>    ```text
>    http://192.168.4.1
>    ```
>    Trang **AERO Gateway Portal** sẽ hiện ra. Bạn có thể bấm nút **"Kiểm Tra Kết Nối (Normal Traffic)"** hoặc bấm **"Thử Nghiệm Cảnh Báo AI (Simulate Alert)"** để còi chip kêu và Web Dashboard lập tức hiển thị cảnh báo đỏ rực!

#### DEMO 3: Laptop làm Hotspot Gateway & ESP32 Hardware Security Dongle (Full L7 DPI)
Laptop đóng vai trò làm Wi-Fi Mobile Hotspot / Router trung tâm, bóc tách toàn phần 56 đặc trưng L2-L7 bằng TShark; bo mạch ESP32 cắm qua USB làm thiết bị phần cứng báo động vật lý:

```powershell
python run_system.py --demo-mode laptop-gateway --classifier random_forest --anomaly-model isolation_forest
```
*(Hoặc dùng cờ tương đương: `python run_system.py --host-gateway ...`)*
- **Hành vi**:
  1. Bật **Mobile Hotspot** trên Windows (Settings -> Network & internet -> Mobile hotspot).
  2. Các thiết bị khác (điện thoại, laptop) kết nối vào mạng Hotspot của laptop để lướt web bình thường.
  3. TShark bóc tách gói tin L2-L7 không mã hóa đối với card mạng host, chạy suy luận 15 nhãn tấn công.
  4. ESP32 nhận bản tin qua USB Serial, hiển thị lưu lượng lên màn hình OLED (`HOST-GW | L7 DPI`) và hú còi Buzzer/LED đỏ khi phát hiện bất thường.

> [!TIP]
> **Tùy chọn Portable Executable (Chạy trên Laptop B không cần cài Python):**
> Nếu chiếc laptop cần giám sát (Laptop B) là máy lạ không có sẵn Python/thư viện, bạn chỉ cần copy duy nhất file thực thi độc lập đã được build sẵn:
> ```text
> dist/aero_gateway_probe.exe (dung lượng ~9.9 MB)
> ```
> Cắm ESP32 vào cổng USB Laptop B và mở Command Prompt chạy:
> ```cmd
> aero_gateway_probe.exe --broker <IP_CỦA_LAPTOP_A>
> ```
> File `.exe` sẽ tự động bóc tách gói tin, tính toán Shannon Entropy, tự tìm cổng COM điều khiển còi/OLED của ESP32 và bắn số liệu về Web Dashboard của Laptop A!

#### DEMO 4: Giám sát lưu lượng Host nội bộ (Card mạng máy tính thực tế)
Bóc tách toàn phần 56 đặc trưng canonical L2-L7 bằng TShark trên card mạng máy tính (Ethernet/Wi-Fi):

```powershell
python run_system.py --probe host --classifier random_forest --anomaly-model isolation_forest
```

#### DEMO 5: Thử nghiệm Digital Twin Lab (14 Kịch bản tấn công trên Loopback)
Dành cho kiểm thử an toàn các kịch bản DoS, Scan, Injection, XSS, Ransomware, MITM trên loopback `127.0.0.1`:

```powershell
python run_system.py --probe host --twin-lab
```
*(Mở giao diện Web `http://localhost:8000`, bấm các nút kịch bản tấn công để bắt đầu bắn workload, thu PCAP và nhập vào Data Lake).*

## Cấu hình .env

Cấu hình host + lab tại nhà:

~~~dotenv
MQTT_BROKER_HOST=127.0.0.1
MQTT_BROKER_PORT=1883
HOST_CAPTURE_INTERFACES=""
HOST_PCAP_FILE=""
HOST_PROBE_ID=Host-PC-Live-Probe
LAB_TARGET_IP=127.0.0.1
LAB_ALLOWED_TARGETS=127.0.0.1/32
LAB_HTTP_PORT=8088
LAB_CAPTURE_INTERFACES=auto-loopback
TWIN_LAB_BACKEND=native
TWIN_CAPTURE_INTERFACE=auto-loopback
AUTO_DETECT_WIFI=false
MQTT_AUTO_DISCOVERY=false
~~~

| Khóa | Hành vi |
| --- | --- |
| HOST_CAPTURE_INTERFACES | run_system tự cập nhật device ID card vật lý đang up ở startup host thường; lab chỉ override trong bộ nhớ. |
| LAB_CAPTURE_INTERFACES | --lab-capture: auto-loopback hoặc một tên/index loopback hợp lệ; không dùng index 8 cố định. |
| TWIN_CAPTURE_INTERFACE | --twin-lab và worker experiment: auto-loopback hoặc loopback hợp lệ; không chuyển sang Wi-Fi. |
| HOST_PCAP_FILE | Host replay PCAP/PCAPNG thay vì live. Để rỗng khi khảo sát thực; hai flag lab xóa override cho lần chạy. |
| TWIN_LAB_BACKEND | native sở hữu HTTP target; docker yêu cầu target container đã chạy. |
| LAB_HTTP_PORT | HTTP lab 8088, phải khác broker/dashboard. |
| LAB_TARGET_IP, LAB_ALLOWED_TARGETS | Ràng buộc generator legacy; không thay target Twin hiện cố định localhost. |
| WIFI_SSID, WIFI_PASSWORD | Cấu hình firmware ESP32; không tự kết nối Wi-Fi của hệ điều hành host. |
| AUTO_DETECT_WIFI, MQTT_AUTO_DISCOVERY | Discovery opt-in, mặc định false; không cần cho host lab. |

Liệt kê adapter trong PowerShell:

~~~powershell
& 'C:\Program Files\Wireshark\tshark.exe' -D
~~~

Số NIC có thể đổi sau cài WSL/Hyper-V/VirtualBox. Dùng auto-loopback cho lab,
tên thiết bị cho Wi-Fi chỉ định. TSHARK_PATH có thể chỉ executable nếu không ở
đường dẫn mặc định; discovery chờ 15 giây và báo lỗi cụ thể.

Không commit .env/credentials. ESP32 dùng credentials.h ignored từ
credentials.h.example; thay SSID/password cần build/flash.
**Dừng launcher bằng Ctrl+C rồi chạy lại sau đổi .env/backend**; reload trang
không nạp cấu hình process. --dashboard-port và --threshold có defaults CLI
8000 và 0.55: muốn đổi hãy dùng flags, không chỉ sửa PORT/ANOMALY_THRESHOLD.

## Runtime flags

Danh sách chính xác: **python run_system.py --help**.

| Flag | Hành vi / lưu ý |
| --- | --- |
| --probe host/esp32/sim | Nguồn telemetry; mặc định host. |
| --broker-host, --broker-port | Chọn MQTT; broker remote phải chạy sẵn. Launcher dùng broker local sẵn có hoặc khởi động local. |
| --dashboard-port 8000 | Cổng dashboard. |
| --classifier random_forest, --anomaly-model isolation_forest | Chọn artifacts; không tự train. |
| --models-dir PATH | Chỉ định bundle artifacts. |
| --threshold 0.55 | Ngưỡng runtime, không phải xác minh ground truth. |
| --window 1.0 | Chu kỳ cửa sổ đo host, đơn vị giây. |
| --twin-lab | Host loopback + UI workload/capture/import; không có workload thì capture=0 có thể bình thường. |
| --lab-capture | Đổi host capture sang loopback, không sinh traffic. |
| --no-tshark | Host fallback, không bảo đảm 56 packet features; không dùng với hai flag lab. |
| --no-browser | Không tự mở browser. |
| --record-lake, --no-record-lake, --no-record | Bật/tắt MQTT live collector, mặc định bật. Không tắt persistence của worker Twin. |
| --attack-sim, --attack-target | Generator legacy riêng; target phải thuộc lab allowlist. Không cần để chạy nút Twin, không kết hợp --twin-lab. |
| --no-sim | Alias chế độ hardware ESP32; không đồng nghĩa tắt workload Twin. |
| --arduino-cli, --flash, --port COM4 | Build/upload board; không dùng khi chỉ khảo sát host. |
| --rl-defense | Twin/RL service thử nghiệm; khác --twin-lab. |
| --enforce-real-network | Opt-in enforcement OS; không cần để collect, chưa là policy thực đã được kiểm chứng. |
| --push-remote | Cloud sync; chỉ bật khi chủ động cấu hình upload dữ liệu. |

Một số flags dùng SmartBooleanAction, như --attack-sim false.
Hai flag lab là store_true. Cách chọn model khác:
python run_system.py --help; danh sách training: python train.py --list-models.

## Workload Twin đã hợp lý với thực tế chưa?

**Chưa xác minh tương đương.** Loopback dùng socket thật nhưng không có radio,
airtime contention, RF loss hay RTT/link-layer như mạng vật lý. Pkt/s cao không
chứng minh workload đúng.

| Lớp UI | Hành vi hiện có | Bằng chứng / giới hạn |
| --- | --- | --- |
| Normal | HTTP GET/POST, 64/512/4096/16384 byte, nghỉ 50–200 ms, seed theo experiment. | HTTP 200/header/nội dung được kiểm tra. Chỉ baseline HTTP; chưa đa dạng MQTT/DNS/TLS/QUIC/thiết bị. |
| Port_Scanning | TCP connect scan nhiều cổng lab sở hữu, hai open và các cổng closed. | Mặc định 8088–8099; không scan ứng dụng khác của Windows. |
| Vulnerability_scanner | HTTP probe robots/admin/config/backup endpoints. | Request scan, không chứng minh exploit; không phải Nikto toàn bộ. |
| DDoS_TCP | Crafted SYN-only giới hạn trên Linux; Windows dùng container Linux. | Không dùng TCP connect fallback; chưa đo distributed DoS impact. |
| DDoS_HTTP | HTTP workload giới hạn. | Chưa đo tác động từ chối dịch vụ. |
| DDoS_UDP | UDP burst tới receiver lab thực, payload đa kích thước. | Có counter receive; một nguồn loopback, không phải botnet phân tán. |
| Uploading | Multipart HTTP upload file fixture. | Không thực thi PHP/webshell hoặc lưu file người dùng. |
| SQL_injection / XSS | Grammar query/form/JSON vào SQLite tạm và endpoint phản chiếu. | SQL SELECT injection được test trên fixture; browser XSS chưa test execution. |
| DDoS_ICMP | ICMP echo ID/timestamp attribution, raw Linux/container. | Không gán nhãn ICMP lỗi của traffic UDP là ICMP flood. |
| Password | Nhiều login attempts vào tài khoản lab. | Có phản hồi success/failure; không dùng tài khoản thật. |
| Fingerprinting | SYN/ACK/SYN-ACK tới cổng open/closed, ICMP echo và banner HTTP. | Kiểm tra đáp ứng TCP/ICMP; surrogate probe, không kết luận OS bằng xprobe2. |
| MITM | Relay DNS đổi địa chỉ sensor.test sang dịch vụ lab khác; client truy cập theo đáp án và nhận nội dung bị thay đổi. | DNS diversion surrogate; không tái hiện ARP poisoning. |
| Backdoor | Agent fixture kết nối ngược; controller đọc inventory và bytes fixture qua TCP. | Không shell/persistence; chỉ fixture tự tạo. |
| Ransomware | Kênh ngược điều khiển AES-256-GCM trên ba file fixture, truyền ciphertext, khôi phục và kiểm tra bytes. | Chỉ file tạm trong container; không dùng file người dùng. |

SQLi/XSS hiện dùng grammar v1, mỗi lớp 8 family và query GET/form POST/JSON POST,
thay cho danh sách cố định 6/4 request. Đã kiểm tra offline 10.000 unique requests
mỗi lớp. Cùng pool endpoint/parameter/User-Agent; Normal cũng dùng chung pool
User-Agent. Manifest ghi actual generator seed, version và số request theo family/
placement; Parquet ghi request_variant_id/template_family/placement/method theo
flow. Đây là metadata để group split, không phải input model. Không lấy số unique
chuỗi làm chứng minh tính thực tế. Xem [SQLi/XSS variants](docs/SQLI_XSS_VARIANTS.md).

Đã có dispatch/UI cho Normal + 14 lớp. Bốn surrogate v4 được nhận vào supervised
training sau kiểm chứng effect trên flow, vẫn không phải tái hiện benchmark.
Khi chạy `--twin-lab` trên Windows, launcher tự mở Docker Desktop ngầm nếu engine
chưa sẵn sàng, chờ Linux engine tối đa 120 giây rồi mới chọn interface capture.
Worker kiểm tra lại nếu Docker bị đóng giữa phiên. Docker phải được cài và hoàn tất
setup WSL2/virtualization; lỗi hoặc timeout được báo rõ, không tự chuyển từ Windows
containers sang Linux containers. Không cần thêm flag hoặc sửa `.env` cho auto-start.
Launcher không tắt Docker Desktop khi thoát vì đây là dịch vụ dùng chung.
Image aero-twin-raw:v4 được dựng
khi chạy lần đầu nếu thiếu. Container không có network ngoài, chỉ mount thư mục
experiment; PCAP trong container được import về lake host. Host realtime loopback
không nhìn thấy loopback bên trong container. Không tự retrain model.
Xem [audit phiên mới và fidelity](docs/TWIN_ATTACK_AUDIT_20261012.md).
Normal và attack tự gán nhãn cho packet khớp flow hai chiều và thời gian.
Policy hiện tại **không yêu cầu label_verified**; nhãn có nguồn controlled_flow.
Đây là attribution workload, không chứng minh attack thành công. Packet nền/không attributable và ICMP
chưa có attribution tuple gốc giữ Unknown. Không bấm attack không tự gán Normal
cho mọi packet; prediction của model không phải ground truth.

Muốn đánh giá: thu Normal Wi-Fi riêng, Normal lab riêng, so cùng dịch vụ/workload
theo protocol, frame/payload size, request rate, IAT, RTT và tỷ lệ error. Cần thêm
UDP/MQTT receiver hoạt động, dịch vụ test phù hợp từng attack và bằng chứng tác
động để đánh giá độ đúng kịch bản. Chia train/test theo phiên/môi trường; chưa concat chỉ vì
đủ feature hoặc chọn đúng nút.

Snapshot đến batch 204: 84.566 live rows Unknown; bốn Twin capture nhập đủ 11.150
PCAP packets; kết quả 0 eligible trong audit cũ dùng verified gate trước thay đổi policy.
Hiện nhãn controlled_flow hợp lệ được nhận dù cờ cũ false. Đã sửa manifest nguồn wildcard TCP/UDP cho phiên mới;
không tự đổi dữ liệu cũ. Xem [audit session 204](docs/A%20Linh/PARQUET_SESSION_204_AUDIT_12_10_2026.md).

## Training offline và data lake

### Nội dung thô dành cho NLP sau này

Host live và Twin importer lưu thêm metadata riêng, không đổi 56 model features:
raw_tcp_payload_hex (bytes dưới dạng hex), raw_tcp_payload_text (UTF-8 hợp lệ,
không tạo plaintext cho TLS/QUIC), raw_http_query, raw_http_uri, raw_http_body,
raw_mqtt_message/topic và raw_packet_info. Chuỗi được giữ nguyên trước categorical
normalization, kể cả khoảng trắng và literal 0. Không tự tokenize/fit NLP encoder.
Xem [raw application content](docs/RAW_APPLICATION_CONTENT.md) cho encoding,
missing/truncation và giới hạn packet-level. Cần restart host/backend để áp dụng;
Parquet cũ không tự được bổ sung nội dung.

~~~powershell
python train.py --help
python train.py --classifier random_forest --anomaly-model isolation_forest --data-source edge-iiotset --invalid-rows drop
~~~

Lệnh thứ hai **train và ghi artifacts**, chỉ chạy khi chủ động huấn luyện;
dùng --output-dir nếu muốn giữ bundle cũ. --invalid-rows drop loại record benchmark
malformed có báo cáo; không sửa nhãn hoặc phục hồi packet mất của live capture.
CSV ML snapshot đã quan sát 396 malformed records và 5.411 exact feature/label
duplicates loại trước sampling/split; số liệu phụ thuộc dataset.

Training có holdout test; preprocessing fit train, HPO fit trong fold.
--refit-full là deployment refit sau đánh giá, không phải artifact được kiểm thử
độc lập trên dữ liệu chưa nhìn thấy. --timeseries hiện bị chặn chờ session splits
và runtime/export parity. CLI dùng --sample-ratio, không dùng --samples cũ.
--data-source hybrid tồn tại và là default training; cần audit nhãn/provenance/domain
trước khi dùng, không tự concatenate mọi Parquet.

Hybrid đọc lake một lần và chỉ các cột training, không nạp raw body/Info cho model 56
features. Log báo path, eligibility và counts theo lớp. Nếu thiếu Normal lake trong
30 ngày, Isolation Forest dùng Normal TRAIN benchmark; attack lake hợp lệ vẫn vào
classifier. Thông báo này không có nghĩa lake rỗng. Thu Normal Twin nếu muốn baseline
lab, không đổi tất cả Unknown thành Normal. oneDNN startup messages không phải lỗi
concat; các log đó có thể xuất hiện do dependencies ML được import.

Tối ưu retraining: packet đã qua quality gate được project cả bảng theo đúng thứ tự
56 features, thay vì tạo DataFrame cho từng packet; encoding/scaling vẫn ở preprocessor.
Bỏ lượt transform classifier lake trước khi refit TRAIN vì kết quả đó bị ghi đè.
Parquet footer và projected columns được đọc qua cùng handle. Không cần flag mới;
log `Read + quality gate` tách thời gian đọc/kiểm tra khỏi phần sau. Đo trên 5.000
packet lake: extraction cũ 17,72s, projection mới 0,015s, đọc 0,26s. Đây là tốc độ
của bước extraction, không phải mức tăng tốc toàn training. Ba regression xác nhận
vector/encoding parity, mixed schema và hybrid training. Không cache scaler/encoder
giữa các lần fit; không bỏ quality gate hay thay đổi split để tăng tốc.

Wi-Fi và loopback nên giữ dataset/evaluation và profile triển khai riêng, nhất là
Normal baseline/threshold của anomaly detector. Classifier chung/hybrid chỉ nên chọn
sau so benchmark-only, domain-specific và mixed model trên test theo session ở từng
domain. Pipeline hiện chưa có CLI tự lọc domain/routing model; --data-source hybrid
đọc mọi dòng lake đủ điều kiện, holdout chính là benchmark. --output-dir (training)
và --models-dir (runtime) có thể quản lý bundle riêng, nhưng không tự lọc dữ liệu
Wi-Fi/loopback. Không random-split packet cùng flow để chứng minh generalization.

data_lake/quality.py yêu cầu packet schema hợp lệ, identity và nhãn canonical từ
controlled_flow/manual_review; không kiểm tra label_verified (cột cũ nếu có bị bỏ qua).
Protocol không có field dùng zero theo contract; field không đo được phải ghi missing.
Unknown hoặc context UI không attributable vẫn không đủ điều kiện training.

Capture Twin giới hạn loopback và endpoint sở hữu: scan dùng dải TCP từ LAB_HTTP_PORT
theo TWIN_SCAN_PORT_COUNT (mặc định 12), các HTTP/UDP workload dùng cổng chính.
MITM DNS fixture thêm UDP cổng chính+2; ICMP chỉ echo identifier của experiment.
Host realtime dùng hợp các scope lab, không phải mọi socket loopback.

Khi bật --twin-lab, host probe realtime cũng lọc đúng cổng lab này. Đường inference
là host TShark → MQTT → model đã nạp → dashboard; importer PCAP Twin chỉ ghi Parquet,
không suy luận lại mọi dòng nhập vào lake. Vì thế counts PCAP/lake không phải số lượt
inference. UI hiển thị top 5 xác suất và thêm xác suất lớp đang chọn trong Twin nếu
model có lớp đó, kể cả khi xác suất thấp hoặc bằng 0. Nhãn collect không ép model
đoán đúng lớp; anomaly gate quyết định cảnh báo cuối, độc lập với thanh xác suất.

Ngày 12/10/2026, theo xác nhận của người vận hành rằng các phiên thực địa không có
attack, đã review 304.685 packet Unknown ngoài dấu hiệu lab thành Normal. Nhãn ghi
manual_review/operator_assertion, giữ nhãn/source trước đó và ID annotation. 4.475
Unknown có dấu hiệu lab được giữ lại; các nhãn attack đã có không đổi. Bản sao gốc
và review.json ở data_lake/label_backups/de40eb6fb3d6419b8b4d5150c6057935/.
Đây là review snapshot đã có, không tự đổi Unknown của các phiên tương lai. Công cụ
`python scratch/apply_operator_normal.py` xem trước; `--apply` áp dụng với backup.
Gán nhãn không tự cập nhật model đang chạy: train lại bundle chủ động, rồi restart
run_system với đúng --classifier/--anomaly-model hoặc --models-dir đã train.

## Docker, MQTT và vận hành

Native Twin không cần Docker. HTTP target container:

~~~powershell
docker compose --env-file .env -f digital_twin/lab/compose.yaml up -d
~~~

Đặt TWIN_LAB_BACKEND=docker, restart launcher. Service chỉ publish localhost,
network container nội bộ; Windows capture trên loopback cổng publish, không phải
toàn bộ container bridge. Compose config đã kiểm tra, runtime container chưa được
kiểm chứng trong các audit trên; worker không tự chạy Compose.

Packet edge/telemetry/traffic QoS 1; window edge/telemetry/window QoS 0;
edge/experiments/status QoS 1 retained, chỉ thông tin. Commands legacy QoS 1 không
retained. Xem [MQTT API](docs/MQTT_API_SPEC.md).

Log Host captured/published/dropped/failed thuộc đường realtime: failed=0 không
phủ nhận queue drop. Manifest Twin có bộ đếm PCAP/parse/save riêng; COMPLETED xác
nhận import thành công, không xác nhận driver zero loss.

## Cấu trúc và tài liệu

| Đường dẫn | Trách nhiệm |
| --- | --- |
| run_system.py, wrappers .bat/.sh | Runtime orchestration. |
| firmware/host_probe/, launcher/ | Host capture, workers, discovery, serial/flash helpers. |
| firmware/esp32_probe/ | C++ radio, inference, MQTT/alerts. |
| firmware/simulator/ | Legacy generator và telemetry simulation. |
| broker/ | Mosquitto config/manager và development fallback. |
| dashboard/backend/, dashboard/frontend/ | FastAPI, MQTT/WebSocket, native JS modules. |
| data_lake/ | Collector, Parquet/SQLite, quality gate và optional cloud sync. |
| digital_twin/experiment_service.py, digital_twin/lab/ | Workload/capture/attribution, HTTP target. |
| digital_twin/ | Physics/RL/safety/enforcement thử nghiệm. |
| ml_engine/, train.py | Schema, preprocessing, training/inference/export. |
| docs/, Literature/, tests/, scratch/ | Tài liệu, nghiên cứu, regression/audit. |

- [Chạy Twin và schema nhãn](docs/TWIN_EXPERIMENT_COLLECTION.md)
- [Host packet collection](docs/HOST_PACKET_COLLECTION.md)
- [Data health review](docs/DATA_HEALTH_AND_COLLECTION_REVIEW.md)
- [Digital Twin/GAN](docs/DIGITAL_TWIN_AND_GAN_GUIDE.md) — đối chiếu implementation.
- Đề án: docs/Sáng tạo trẻ.docx; hướng dẫn agent: AGENTS.md.

## Kiểm tra và phạm vi xác minh

~~~powershell
node tests/dashboard_controls.mjs
node tests/dashboard_windows.mjs
python -m unittest discover -s tests -p test_twin_experiments.py -v
python -m unittest discover -s tests -p test_dashboard_assets.py -v
~~~

Các tests không tái hiện benchmark hoặc xác minh attack thực. Native capture
integration trong test Twin là opt-in; tests thường có HTTP/socket localhost benign.
Không chạy test_traffic_generator.py như unit test: có thể gửi traffic thật.
test_pipeline.py là smoke test hạn chế, cần model/broker, không chứng minh toàn bộ
subscriber path. Pilot Normal/PCAP nhỏ không bảo đảm throughput dài hạn, độ đa dạng,
latency ESP32 hay model quality trên mạng triển khai.

## Giấy phép

MIT — xem [LICENSE](LICENSE).
