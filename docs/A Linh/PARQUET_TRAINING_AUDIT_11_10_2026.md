# Audit Parquet mới: điều kiện concat với Edge-IIoTset

Ngày kiểm tra: 11/10/2026. Chỉ đọc dữ liệu; không sửa Parquet, không đổi nhãn, không train hoặc ghi đè model.

## Phạm vi và cách kiểm tra

- Snapshot 86 file `.parquet` đã tồn tại khi bắt đầu trong `data_lake/raw/`, tổng 37.034 dòng, 102 cột, một capture. File `.tmp` chưa hoàn tất không được tính.
- Đọc toàn bộ các dòng trong snapshot, không lấy mẫu. Đối chiếu đầy đủ 56 đặc trưng canonical với schema và bộ lọc `data_lake/quality.py` đang dùng.
- So sánh với toàn bộ CSV ML Edge-IIoTset local: 157.800 dòng; loại 396 dòng sai numeric khi tính phân bố so sánh, còn 157.404 dòng. So sánh này chưa loại exact duplicates của benchmark và chưa thực hiện split/train.
- CSV DNN 1,2 GB chỉ kiểm tra header đủ 56 cột; không tuyên bố đã kiểm tra toàn bộ dữ liệu DNN.
- Báo cáo máy đọc được: [parquet_training_audit_2026-10-11.json](../../scratch/parquet_training_audit_2026-10-11.json). Có SHA-256 từng file, schema Arrow, phân bố mỗi feature và fingerprint CSV ML; không xuất payload hoặc địa chỉ endpoint.

## Kết luận

**Có thể ghép ở mức định dạng sau khi chọn đúng 56 cột và bổ sung nhãn hợp lệ. Hiện chưa có dòng đủ điều kiện concat cho supervised training.** Lỗi chính không phải thiếu cột hay NaN, mà là thiếu ground truth, nội dung traffic quá hẹp và capture lưu không đầy đủ.

| Kiểm tra | Kết quả |
| --- | ---: |
| Đặc trưng canonical có đủ | 56/56 |
| Null trong 56 đặc trưng | 0 |
| NaN/Inf trong đặc trưng numeric | 0 |
| Dòng numeric malformed / port sai range | 0 |
| `missing_features` không rỗng | 0 |
| Packet có `captured_length < frame_length` | 0 |
| Trùng `(device_id, packet_id)` | 0 |
| Vector 56 đặc trưng lặp thêm | 10 |
| `label_verified=True` | 0 |
| Bộ lọc training chấp nhận | 0/37.034 |

Tất cả dòng là `record_kind=packet`, schema version 2, `edgeiiot-packet-v1`, capture TShark live-one-pass. 102 cột bao gồm cả metadata; chỉ 56 canonical features được đưa vào model. Không đưa scenario/status, ID, timestamp, prediction hoặc provenance vào X.

## Những vấn đề ngăn training hoặc làm kết quả sai lệch

### 1. Không có nhãn ground truth

Toàn bộ 37.034 dòng:

- `ground_truth_scenario=Unknown`
- `label_source=unverified`
- `requested_attack_label=Unknown`
- Không có dòng target-match được xác định từ scenario.

Trong snapshot này, thậm chí không có nhãn UI để tham khảo. Không thể kết luận generator chưa chạy chỉ từ việc thiếu context: có thể không có status hợp lệ cùng thời gian, capture sau khi scenario hết hạn, hoặc thu traffic khác. Không được tự đổi Unknown thành Normal hay dùng dự đoán model làm `Attack_type`.

Preprocessing không thể tạo ground truth. Muốn giữ các dòng này cho training phải có bằng chứng đối chiếu từ log/PCAP/scenario/flow, sau đó gán nhãn xác minh theo từng luồng. Dòng không thể xác minh vẫn giữ Unknown.

### 2. Dữ liệu gần như toàn bộ là TCP loopback

| Nội dung | Số dòng |
| --- | ---: |
| Protocol TCP | 36.852 |
| WebSocket | 96 |
| TLSv1.2 | 86 |
| Hai endpoint IPv4 loopback | 37.024 |
| Có endpoint IPv6 | 10 |
| HTTP lab TCP cổng 8088 | 0 |
| MQTT của hệ thống TCP 1883 trên IPv4 loopback | 0 |
| Dashboard TCP 8000 trên IPv4 loopback | 0 |

Các con số cổng chỉ kiểm tra cổng mặc định, không chứng minh mọi transport của ứng dụng đã được loại. TLS và WebSocket cũng dùng TCP bên dưới; snapshot không có bằng chứng traffic UDP/HTTP lab của các kịch bản đang muốn thu. Không suy ra SQLi/XSS/Uploading hoặc trạng thái Normal từ tên protocol.

45/56 đặc trưng là hằng số trong snapshot. Không có ARP, ICMP, HTTP, UDP, DNS, MQTT hoặc Modbus canonical measurements khác 0. `tcp.flags.ack` có giá trị khác 0 trên mọi dòng; không có `tcp.connection.syn`/`synack` khác 0. Snapshot có thể bắt giữa các kết nối đang tồn tại và không đại diện quá trình thiết lập kết nối.

Gộp theo cặp endpoint TCP hai chiều cho thấy chỉ 19 nhóm, trong đó 3 nhóm lớn nhất chiếm 36.407/37.034 dòng (98,31%). Đây là nhóm endpoint, không phải số kết nối độc lập được xác minh bằng handshake/TCP stream. Có 18.315 dòng chỉ chứa 1 byte TCP payload. Vì vậy 37 nghìn dòng không đồng nghĩa 37 nghìn hành vi độc lập, dù gần như không có vector trùng hoàn toàn.

Một packet TCP không cần chứa các field MQTT/DNS/ARP. Median 47 `absent_fields` là điều có thể xảy ra bình thường; extractor ghi zero placeholder. Đây không phải 47 giá trị lỗi mỗi dòng. Tuy nhiên toàn bộ dataset thiếu nhóm giao thức đó thì coverage không phù hợp để bổ sung đủ 15 lớp benchmark.

### 3. Thiếu frame trong dữ liệu đã persist

Một capture kéo dài khoảng 190,34 giây; sequence nhỏ nhất 1, lớn nhất 227.197. Snapshot chứa 37.034 sequence khác nhau, thiếu 190.163 sequence trong khoảng này, tức lưu được khoảng 16,3%.

Đây là số frame không có trong snapshot Parquet, không phải phép đo kernel/Npcap drop. Khoảng trống có thể liên quan queue, publish, collector, reject hoặc batch chưa persist; audit không tự quy tất cả cho một tầng. Bộ đếm realtime ở lần kiểm tra trước cũng từng cho thấy queue drop lớn, nhưng thuộc snapshot/phiên khác, không cộng trộn vào số trên.

Mất gói có thể làm tập được giữ lệch về một số flow/giai đoạn. Không phục hồi frame mất bằng fillna/interpolation hoặc nhân bản các dòng còn lại. Cần PCAP gốc nếu muốn tái trích xuất đầy đủ và đối chiếu bằng frame number.

### 4. Phân bố khác benchmark và categorical chưa biết

So sánh với CSV ML sau loại malformed numeric:

| Chỉ số | Parquet | ML benchmark |
| --- | ---: | ---: |
| `tcp.len` bằng 0 | 50,03% | 73,36% |
| Percentile 95 của `tcp.len` | 1 byte | 495 byte |
| `tcp.options` zero placeholder | 99,98% | 49,62% |
| `tcp.payload` zero placeholder | 50,03% | 73,36% |

49,97% tổng dòng Parquet có giá trị category `tcp.payload` chưa xuất hiện trong CSV ML. Đây là giá trị mới, không tự động là dữ liệu hỏng. Nhưng encoder hiện fallback category chưa biết về 0, cùng mã placeholder, nên model đã train trên Kaggle có thể bỏ mất thông tin payload của các dòng đó. Nếu tạo model combined thì phải fit encoder trên train mới, cập nhật metadata/export, và giữ validation/test riêng; không fit vocabulary trên test.

Hash vector canonical không thấy trùng với benchmark ML trong snapshot. Đây là kiểm tra chẩn đoán, không phải chứng minh không có leakage. Dữ liệu trong cùng capture/flow vẫn tương quan dù chỉ 10 vector trùng hoàn toàn; split ngẫu nhiên từng packet có thể đánh giá quá lạc quan.

## Dữ liệu này có phải bỏ hết không?

Không. Giữ riêng làm tập unlabeled để phân tích traffic, drift, encoder và pipeline. Schema/giá trị numeric đã đạt mức tốt để tái sử dụng nếu xác minh được nhãn. Với snapshot hiện tại, không bypass training gate và không chuyển cả tập thành Normal.

Bước ưu tiên:

1. Lưu PCAPNG của cùng phiên nếu còn, đối chiếu frame số thứ tự và log dịch vụ/scenario để biết đang thu ứng dụng nào.
2. Thu lại một thử nghiệm nhỏ, có cả baseline và workload HTTP lab, xác nhận cổng 8088 thật sự xuất hiện và metadata experiment đi cùng packet. Nhãn request SQLi/XSS chỉ thành ground truth attack khi mức xác minh được định nghĩa và có bằng chứng; service không có lỗ hổng không chứng minh khai thác thành công.
3. Tách đường PCAPNG → batch Parquet khỏi queue MQTT realtime để đo và giảm loss.
4. Tạo tập lab có nhãn riêng, chia theo capture/flow/máy; đánh giá Kaggle-only trên test lab. Chỉ concat phần lab được xác minh sau khi có báo cáo coverage, category mapping và split độc lập.
