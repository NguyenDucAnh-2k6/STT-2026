# Chạy thu packet trên host

Luồng mặc định: TShark → một JSON/packet trên MQTT → raw Parquet theo lô;
model nhận cùng 56 feature raw, tự dùng encoder/scaler đã lưu.
Thống kê dashboard đi qua `edge/telemetry/window` mỗi giây.

## Capture trực tiếp

Trong PowerShell tại thư mục gốc:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

Chọn đúng index interface từ kết quả, sửa `.env`:

```dotenv
HOST_CAPTURE_INTERFACES="<index-interface-cua-ban>"
HOST_PCAP_FILE=""
HOST_PROBE_ID="Host-PC-Live-Probe"
```

Host dùng mạng Windows đang kết nối. SSID/password không làm host tự đổi mạng.
Npcap/interface phải có quyền capture; nếu TShark thất bại, packet mode báo lỗi
và dừng thay vì âm thầm dùng psutil.
Tự chọn interface không thêm loopback. Nếu cần khảo sát ứng dụng localhost,
chọn loopback rõ ràng trong `HOST_CAPTURE_INTERFACES`. Traffic của dashboard được
loại theo địa chỉ local và port server, kể cả khi chủ động capture loopback.

```powershell
python run_system.py --probe host --broker-host 127.0.0.1 --broker-port 1883
```

Launcher tìm Mosquitto native hoặc kết nối broker đã chạy. Data lake bật mặc định.
Không thêm `--no-tshark` nếu cần packet. Không cần ESP32 hay flash firmware.
Không bật attack simulator để kiểm tra thu thập thông thường.

Kiểm tra dòng `captured=... published=... dropped=... failed=...` trong console.
`published` là broker đã ACK, không phải xác nhận ghi xuống đĩa. Khi lưu hoạt động,
file `session_<id>_batch_*.parquet` xuất hiện trong `data_lake/raw/date=.../` sau
flush 5 giây hoặc mỗi 500 record. Ctrl+C cho probe dừng và drain queue trước khi
collector flush. Nếu model cũ báo `preprocessing version 2` / `unavailable`, việc thu
raw packet vẫn chạy; cần train lại riêng để có suy luận hợp lệ, không sửa metadata
model cũ để vượt qua kiểm tra.

Capture trực tiếp loại TCP tới/từ **địa chỉ + port broker telemetry** để không bắt
lại telemetry rồi tạo vòng lặp. MQTT trên broker khác vẫn được capture. Nếu MQTT
của mạng khảo sát dùng chung endpoint với telemetry, dùng PCAP đọc offline hoặc
broker telemetry trên port khác (ví dụ 1884, giữ MQTT khảo sát trên 1883).
Port dashboard truyền từ `--dashboard-port` được loại ở endpoint local để tránh
vòng lặp WebSocket → capture → inference → WebSocket. Điều này cũng bỏ ứng dụng
local khác dùng chung port đó; đổi port dashboard nếu cần khảo sát ứng dụng ấy.

## Đọc PCAP/PCAPNG có sẵn

Sửa `.env` rồi chạy cùng lệnh launcher:

```dotenv
HOST_PCAP_FILE="D:/path/to/survey.pcapng"
```

TShark chạy hai lượt (`-2 -r`) và không loại port broker trong file. Đọc đến EOF,
probe drain queue rồi launcher đóng các dịch vụ. Xóa giá trị `HOST_PCAP_FILE` để
quay lại live capture. Dữ liệu replay giữ timestamp capture; `receipt_timestamp`
ghi thời điểm nhận hiện tại. Replay cùng một file tạo capture ID mới: phải loại
trùng nội dung/session trước khi chia train/test, không chỉ dựa vào packet ID.

## Tương thích và nhãn

Đã khớp tên/thứ tự/kiểu raw với **contract 56 feature của dự án**. Không thể cam kết
giống từng giá trị CSV tác giả khi thiếu PCAP gốc và cấu hình Wireshark tương ứng.
Capture live cũng không biết packet tương lai; chế độ PCAP hai lượt bổ sung ngữ cảnh
phân tích/reassembly, cần đối chiếu trên cùng PCAP thay vì mặc định hai chế độ giống nhau.
Riêng `dns.retransmit_request_in` tham chiếu request gốc trước đó. Các field không xuất hiện được
ghi sentinel 0 và liệt kê trong `absent_fields`; trường sai hoặc frame bị truncate
được đánh dấu `missing_features` và không được đưa vào model/training.

TLS/mã hóa không được giải mã tự động. Các cột HTTP/MQTT không có plaintext không
trở thành phép đo giả. `mqtt.msg_decoded_as` được xử lý categorical đúng kiểu text.

Mọi packet mới có `ground_truth_scenario=Unknown`, `label_verified=false`.
Cần nhãn `manual_review` hoặc `controlled_flow` có căn cứ trước khi concat training;
trạng thái simulator hoặc dự đoán model không phải ground truth. Nếu toàn bộ packet
chưa có nhãn, training gate chấp nhận 0 record là hành vi đúng.

## Kiểm thử đã thực hiện

`python -m unittest discover -s tests`: kiểm thử offline, gồm PCAP giả lập qua native
TShark, Mosquitto localhost trên port riêng, collector và Parquet. Không capture mạng
thật, không phát traffic tấn công, không train lại/ghi đè model đang dùng.
Tài liệu định dạng: [MQTT_API_SPEC.md](MQTT_API_SPEC.md).

Tham khảo TShark: https://www.wireshark.org/docs/man-pages/tshark.html
