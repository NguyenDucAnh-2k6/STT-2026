# Kiểm tra lần chạy host ngày 2026-10-11

Nguồn: `output.csv` xuất bởi `view_parquet.py`, batch 000015 của phiên thu đang được
script chỉ định; snapshot 19 Parquet đã hoàn tất trong phân vùng ngày 2026-10-11.
Không sửa CSV, Parquet hoặc model. Script đọc lại: `scratch/audit_host_capture.py`;
thống kê tổng hợp: `scratch/host_capture_health.json`. Không đưa payload/IP vào báo cáo.

## Dữ liệu thực sự thu được

| Kiểm tra | Batch CSV/Parquet | Toàn snapshot |
|---|---:|---:|
| Record | 500 | 7.910 |
| Cột | 93 | 93 |
| Thiếu cột trong 56 feature chuẩn | 0 | 0 |
| Feature null / số không finite | 0 / 0 | 0 / 0 |
| Record có `missing_features` | 0 | 0 |
| Frame bị truncate | 0 | 0 |
| Trùng device/packet ID | 0 | 0 |
| Số `absent_fields` trung vị | 46 | 46 |
| Feature thay đổi giá trị | 12 | 28 |
| Nhãn xác minh | 0 | 0 |

CSV có cùng số dòng và cùng giá trị 56 feature với batch Parquet nguồn. CSV là bản
xuất phục vụ đọc; Parquet vẫn giữ kiểu/list tốt hơn CSV. Các field categorical phải
đọc theo kiểu string để không mất leading zero của payload hex.

Batch: 406 TCP, 84 WebSocket, 10 TLSv1.2. Việc không có ARP/ICMP/UDP/DNS/MQTT/Modbus
trên các packet này là bình thường. `tcp.payload` absent trên 234 packet có thể là
ACK/control không có TCP payload. `tcp.connection.syn/fin` là marker sự kiện, không
phải field bắt buộc xuất hiện trên mọi packet TCP. HTTP request không xuất hiện trên
mỗi frame WebSocket sau handshake. TLS không tự tạo HTTP plaintext.

`absent_fields` là field không xuất hiện trong dissection, được ghi sentinel 0.
`missing_features` là lỗi/malformed/truncate theo extractor. Đủ 56 cột không đồng
nghĩa có đủ 56 phép đo độc lập, và cũng không chứng minh khả năng phát hiện tấn công.

## Các vấn đề quan trọng

- 7.526/7.910 record (95,1%) có cả source/destination IPv4 loopback. 2.124 record là
  loopback với port 8000, tương ứng endpoint dashboard mặc định. Có 516 WebSocket
  trong toàn snapshot. Đây chủ yếu là dữ liệu máy local, chưa đại diện mạng khảo sát.
  Không đủ process attribution để gán mọi loopback còn lại cho AERO.
- Sequence 1..64.579 chỉ có 7.910 ID được lưu: thiếu 56.669 ID trong khoảng đó.
  Các batch 000000..000018 đều có mặt. Đây là dấu hiệu dữ liệu bị bỏ/mất giữa các
  record đã lưu; không chứng minh NIC/TShark đã mất đúng số packet đó. Cần đối chiếu
  counter capture/rejected/dropped/failed của lần chạy và log persistence.
- Cả 7.910 record đều Unknown/unverified. Không được tự xem là Normal hoặc concat
  vào supervised training. Không nên chọn phiên này làm baseline mạng thật.

## Lỗi UI và sửa code

Backend đã subscribe window nhưng chỉ xử lý Wi-Fi, còn số tốc độ lấy từ inference
packet không có rate. Vì thế UI hiện 0 dù capture hoạt động. Đã sửa:

1. `TRAFFIC_WINDOW_UPDATE` mang rate/counter đo được đến KPI và chart, độc lập trạng
   thái model. Prediction packet không còn ghi đè rate bằng 0. Counter capture dùng
   số tích lũy theo capture ID, không cộng packet rate như thể đó là packet count.
2. Prediction mẫu trên UI tối đa 5 lần/giây/device; inference vẫn nhận từng packet.
   Null anomaly được hiển thị N/A, không vẽ thành điểm an toàn 0. Protocol chart bỏ
   tỷ lệ mặc định bịa 30% UDP / 5% ICMP khi thiếu dữ liệu.
3. Callback MQTT đưa xử lý state về event loop của dashboard.
4. Auto interface không tự chọn loopback. Capture loại endpoint MQTT telemetry và
   endpoint dashboard local. Interface/port CLI vẫn được dùng khi chạy. IPv6 source/
   destination được giữ trong metadata, không đưa vào canonical model features.
5. Publisher có tối đa 16 QoS message chờ ACK đồng thời; trước đó đợi ACK từng packet
   có thể tạo bottleneck. Queue vẫn bounded, timeout/drop được đếm. Chưa đo throughput
   thực tế sau sửa. Snapshot/reset window atomic, không mất update giữa hai bước.

Restart launcher/backend và reload trang sau sửa. Chọn Wi-Fi/Ethernet đúng bằng
`tshark -D`; ghi rõ index vào `.env` như [HOST_PACKET_COLLECTION.md](HOST_PACKET_COLLECTION.md).
Lần chạy mới phải theo dõi drop/failure và tỷ trọng loopback. Việc chỉnh code không
sửa lại dữ liệu phiên cũ, không chứng minh mọi packet của lần chạy mới sẽ được lưu.

## Edge-IIoTset có phù hợp?

Paper mô tả testbed IoT/IIoT có nhiều giao thức và thiết bị. Tập lưu lượng laptop ở
trên có khác biệt về môi trường, điểm capture, plaintext/mã hóa và traffic ứng dụng.
Kết luận kỹ thuật: Edge-IIoTset hữu ích cho benchmark tham khảo hoặc môi trường lab
tương ứng, chưa đủ làm căn cứ duy nhất cho model giám sát mạng bất kỳ.

Kiểm tra bản ML cục bộ 157.800 record: `mbtcp.len` khác 0 trên **0 record**. Đặc biệt,
predicate `mqtt.topic == "0.0"` phân biệt Attack/Normal chính xác **100%** trên file
chưa normalize. Đây là artifact của cách serialize sentinel, không phải phát hiện
hành vi. Preprocessor hiện tại chuẩn hóa `0`/`0.0`, nên không nên đưa raw sentinel
spellings hay `absent_fields` vào feature model để vô tình tái tạo shortcut đó.

Một preprint tháng 8/2026 cũng báo cáo vấn đề sentinel/provenance và suy giảm khi
đánh giá trên device khác. Đây là nghiên cứu sơ bộ, chưa phải kết quả chúng ta đã
tái hiện toàn bộ; phép kiểm tra shortcut phía trên được đo độc lập trên CSV local.

Khuyến nghị: giữ benchmark làm đối chứng; xây dữ liệu mạng mục tiêu có nhãn gắn với
flow/sự kiện và chia theo thời gian/session/môi trường. Cho phát hiện scan/flood,
ưu tiên feature flow/window đo được (packet/byte rate, flags, đa dạng endpoint,
IAT), tránh ordinal encoding payload hex/checksum/stream ID như thể là hành vi có
thứ tự. Cho SQLi/XSS cần plaintext hợp lệ hoặc telemetry từ application/proxy;
không kỳ vọng extractor tự phục hồi nội dung HTTP từ TLS. Thay feature phải tạo
contract/model mới, huấn luyện và đánh giá lại; chưa thay model ở lượt sửa này.

Nguồn:
- Paper gốc: https://doi.org/10.1109/ACCESS.2022.3165809
- Preprint về artifact: https://arxiv.org/abs/2608.15761
- TShark semantics: https://www.wireshark.org/docs/man-pages/tshark.html
