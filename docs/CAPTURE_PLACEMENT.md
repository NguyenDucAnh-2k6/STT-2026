# Chọn interface và đo mạng khác

## Capture bằng 0 sau khi đổi chỗ

Phân biệt cổng dịch vụ TCP/UDP (MQTT 1883, lab 8088) với capture interface/card mạng.
Các cổng dịch vụ không cần scan lại chỉ vì đổi Wi-Fi. Npcap interface index có thể
thay đổi; card Wi-Fi tồn tại cũng có thể đang disconnected.

Mỗi startup host thường, run_system tự chạy `tshark -D`, lấy link state qua psutil và trên Windows
đối chiếu Get-NetAdapter GUID với Npcap. Chọn các card vật lý đang up,
loại loopback/virtual, rồi ghi đè riêng HOST_CAPTURE_INTERFACES trong .env bằng device
ID đã tìm được và truyền vào worker. Không giữ interface cũ chỉ vì index còn tồn tại.
Các subprocess discovery/capture chạy headless; không đọc
password, không kết nối Wi-Fi khác, không đổi cấu hình mạng. Các setting và credentials
khác được giữ nguyên; cập nhật .env atomic. Discovery thất bại giữ file cũ và báo lỗi.

Nếu cả Wi-Fi và Ethernet đều up, auto lấy cả hai: có thể chọn một card để hạn chế
phạm vi hoặc tránh cùng traffic xuất hiện ở hai điểm capture qua cấu hình probe riêng.
Startup run_system hiện tự chọn cả hai. Auto không tự đổi
card giữa phiên; restart khi cần chọn lại.

```powershell
python run_system.py --probe host --broker-host 127.0.0.1 --broker-port 1883 --classifier random_forest --anomaly-model isolation_forest
```

Không còn cờ --capture-interface. --twin-lab/--lab-capture tự chọn loopback qua
TWIN_CAPTURE_INTERFACE/LAB_CAPTURE_INTERFACES, mặc định auto-loopback, chỉ trong bộ
nhớ của phiên chạy; không persist loopback vào HOST_CAPTURE_INTERFACES. Replay PCAP,
--no-tshark và chế độ không chạy host probe không cập nhật capture setting.

`--twin-lab` chỉ capture loopback TCP/UDP cổng LAB_HTTP_PORT (mặc định 8088).
Chưa chạy nút thí nghiệm thì captured=0 có thể đúng; Wi-Fi đang dùng không thuộc
filter Twin. Nếu experiment đã RUNNING mà vẫn 0, kiểm tra experiment status/errors,
lab service/cổng và Npcap; không tự chuyển sang Wi-Fi để che lỗi scope. Sau 10 giây
không có parsed packet, log cảnh báo kèm rejected count và hướng kiểm tra.
`--lab-capture` quan sát loopback rộng hơn, vẫn không tự sinh workload.

## Quan sát giữa AP/router và thiết bị khi trung tâm ở mạng khác

Card host ở chế độ thông thường không tự nhận mọi unicast giữa hai thiết bị khác;
SSID/password không thay đổi vị trí quan sát. Trên switched Ethernet cần mirror
port/SPAN hoặc TAP đặt trên đường traffic cần đo.
[Wireshark Ethernet capture](https://wiki.wireshark.org/CaptureSetup/Ethernet).

Hướng phù hợp nhất với 56 features hiện tại là **probe tại AP/router hoặc mirror**:

1. AP/router hỗ trợ capture trên bridge/LAN sau lớp mã hóa Wi-Fi; hoặc mirror đúng
   link AP trên managed switch sang NIC của probe. Link mirror chỉ thấy traffic đi
   qua link đó, có thể không thấy trao đổi nội bộ AP hay VLAN khác.
2. Probe Linux/PC gần mạng T dùng TShark và canonical extractor. Transport riêng
   qua Ethernet/Internet/VPN gửi telemetry về broker/trung tâm; trung tâm không cần
   tham gia Wi-Fi T. Mirror NIC và management NIC phải chọn scope tường minh.
3. Dùng device_id/capture_id/interface/provenance riêng; broker reachable, ACL/TLS,
   queue/counters/buffering. Đánh giá latency/loss và model theo môi trường đo.

Code hiện có host probe, MQTT và central inference; chưa có installer/router agent,
remote provisioning, reconnect/buffer bảo đảm delivery hay kiểm chứng deployment này.
Đây là kiến trúc đề xuất, không phải chế độ chỉ nhập SSID là đã hoạt động.

Một lựa chọn thụ động khác là **NIC Wi-Fi hỗ trợ monitor mode** đặt gần AP, cùng
channel/band và driver phù hợp. Nên tách NIC monitor khỏi NIC kết nối của trung tâm;
monitor mode có thể làm card ngắt kết nối mạng hiện tại. Khả năng này tùy hardware/OS.
[Wireshark WLAN capture](https://wiki.wireshark.org/CaptureSetup/WLAN),
[Wireshark manual](https://www.wireshark.org/docs/man-pages/wireshark).

Monitor bắt được frame không có nghĩa đọc được IP/TCP/HTTP bên trong: WPA2-Personal
cần khóa phù hợp và handshake của phiên; WPA3 không giải mã chỉ bằng SSID/password
và handshake. HTTPS/TLS vẫn mã hóa nội dung dù đã giải mã lớp Wi-Fi.
[Wireshark decryption keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html).

ESP32 promiscuous firmware hiện tại chủ yếu quan sát metadata/frame của Wi-Fi;
không phải probe thay thế TShark cho đủ 56 feature packet trên Wi-Fi mã hóa. Nếu
dùng monitor metadata/ESP32, cần model riêng theo các field thực sự đo được.

## Kiểm chứng thay đổi chọn interface

Ngày 12/10/2026: read-only discovery native tìm 10 interface và chọn Wi-Fi,
Ethernet 2 đang hoạt động. Sáu tests offline kiểm tra link/GUID/name/explicit scope
đều pass. Không chạy lại Twin attack hay triển khai monitor/AP/remote probe trong
validation này; kết quả discovery không chứng minh end-to-end capture/inference.
