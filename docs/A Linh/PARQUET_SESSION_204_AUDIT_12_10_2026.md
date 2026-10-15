# Khảo sát phiên kết thúc ở batch 204 — 12/10/2026

## Phạm vi và số liệu

Đọc 205 file batch 000000–000204 của session `sess_f45ad6899ecb4195a88352f39c6ff5c0`, kết thúc tại `session_sess_f45ad6899ecb4195a88352f39c6ff5c0_batch_000204.parquet`. Đối chiếu các capture Twin bắt đầu trong khoảng timestamp của session. Không sửa Parquet, PCAP, manifest hay tự đổi nhãn dữ liệu cũ. Script: `scratch/audit_session_204.py`; số liệu máy đọc được: `scratch/session_204_audit_2026-10-12.json`.

Collector realtime lưu **84.566 dòng**, toàn bộ Unknown/unverified, không duplicate packet ID, null canonical feature hoặc numeric malformed. Có 26/56 features là hằng số. Phân bố: TCP 82.715; TLSv1.2 1.337; ICMP 271; UDP 241; MDNS 1; HTTP 1. Median và p95 frame length đều 45 byte; frame lớn nhất 65.539 byte. Đây là kích thước capture loopback, không coi là MTU/frame Wi-Fi trên dây.

Khoảng sequence quan sát có 536.590 số; lưu 84.566 unique sequence, tương đương **15,76%**. Đây là coverage trong khoảng sequence, không phải phép đo driver drop và không bao gồm các số trước/sau khoảng này. Collector realtime gán Unknown đúng theo thiết kế: packet đi qua MQTT không có quy trình xác minh flow của thí nghiệm. Không dùng trạng thái nút UI hoặc model prediction để đổi tất cả thành attack/Normal.

| Capture Twin | Tổng dòng | Có nhãn lớp | Unknown | Verified | Parse reject |
| --- | ---: | ---: | ---: | ---: | ---: |
| DDoS_TCP, `f556…` | 3.023 | 2.261 | 762 | 0 | 0 |
| Uploading, `b2d8…` | 1.792 | 0 | 1.792 | 0 | 0 |
| DDoS_TCP, `2d9d…` | 2.879 | 2.149 | 730 | 0 | 0 |
| DDoS_UDP, `2453…` | 3.456 | 0 | 3.456 | 0 | 0 |
| **Tổng** | **11.150** | **4.410** | **6.740** | **0** | **0** |

Mỗi manifest COMPLETED đối chiếu `pcap_packets = parsed_packets = saved_rows`, và sequence import đầy đủ. Điều này chứng minh nhập đủ file PCAP đã thu; không chứng minh kernel/driver capture không mất gói. Không có phiên Normal COMPLETED trong khoảng audit này. Phiên Vulnerability_scanner ERROR xuất hiện sau endpoint 204 nên không cộng vào bảng: TShark `-G fields` kết thúc lỗi; capture được giữ, chưa có số nhập thành công.

## Vì sao Unknown trong Twin?

- **4.116 packet TCP/UDP:** manifest có nguồn `0.0.0.0`, packet thực nguồn `127.0.0.1`, khiến đối chiếu exact flow thất bại. Hai phiên TCP có 762 và 730 packet thuộc nhóm này; UDP có 1.728, Uploading có 896. Socket UDP không bind thường trả wildcard; kết nối TCP thất bại cũng có thể trả wildcard. Đây là lỗi attribution, không phải preprocessing thiếu feature.
- **2.624 packet ICMP:** chưa được gán nhãn bởi matcher transport flow. Có đúng một ICMP trên mỗi UDP trong hai capture UDP/Uploading. Không tự đổi nhãn tất cả ICMP theo scenario đang chạy; muốn attribution ICMP cần trích và kiểm tra tuple của datagram gốc được nhúng trong ICMP.

Đọc lại PCAP DDoS_UDP bằng TShark xác nhận cả 1.728 ICMP đều **type 3, code 3: Destination Unreachable / Port Unreachable**. HTTP target không có dịch vụ UDP ở cổng 8088. Vì vậy capture này là UDP gửi tới cổng không mở kèm lỗi trả về, chưa thể gọi là tấn công vào dịch vụ UDP hoạt động. Matcher được chặn rõ ICMP/ICMPv6 để không vô tình coi port UDP/TCP nhúng trong ICMP là flow transport trực tiếp sau sửa nguồn wildcard.

Đã sửa socket Twin bind nguồn loopback trước thao tác và giữ endpoint đã bind khi hệ điều hành trả wildcard sau connect thất bại. Không thay địa chỉ packet trong preprocessing, không nới matcher thành IP/port bất kỳ. Fix áp dụng cho phiên mới; dữ liệu cũ cần quy trình sửa attribution riêng có audit nếu muốn phục hồi nhãn. Nhãn attack vẫn `label_verified=false` vì workload chưa được xác minh là attack chuẩn của paper.

## Chất lượng cho training và tính thực tế

**Bộ lọc training chấp nhận 0 dòng** ở cả live session và bốn capture Twin. Các vector đủ schema nhưng ground truth chưa verified. Không concatenate trực tiếp vào Kaggle.

Hai capture TCP có median frame 44 byte, p95 56 byte, toàn bộ `tcp.len=0`, và 43 features hằng số: đây là connect/control burst, không chứng minh DDoS. Hai capture UDP/Uploading có 52 features hằng số; Uploading vẫn là pattern UDP legacy, chưa phải upload HTTP của môi trường ứng dụng. ICMP phản hồi cho thấy cần kiểm tra dịch vụ UDP thật thay vì chỉ gửi vào cổng của HTTP target. Tốc độ cao không thay thế bằng chứng attack hoặc độ đa dạng dữ liệu.

Để so Twin với thực tế, thu baseline Normal Wi-Fi riêng, giữ nguồn/interface/session và labels Unknown cho traffic chưa review; thu Normal trong lab bằng HTTP endpoint hoạt động. So sánh cùng loại dịch vụ, protocol, kích thước, request rate, IAT, payload TCP, tỷ lệ control/error; không so tổng pkt/s loopback của máy với tổng pkt/s Wi-Fi rồi kết luận Twin hợp lý. TLS/QUIC trên Wi-Fi không cho cùng nội dung HTTP plaintext như lab. Giữ test theo phiên/môi trường; chưa retrain trên snapshot này.

## Sửa `--lab-capture` và cách chạy

`.env` cũ đặt `LAB_CAPTURE_INTERFACES=8`; số adapter có thể đổi và trỏ sang Ethernet. Đã chuyển duy nhất khóa này thành `auto-loopback`; `.env.example` dùng cùng giá trị. Launcher lab nay resolve tên ổn định và từ chối interface không phải loopback. Kiểm tra TShark trên máy chọn lab `\Device\NPF_Loopback`, còn chế độ thường tự chọn Wi-Fi index 5 tại thời điểm kiểm tra.

**Quan sát Wi-Fi thực** — bỏ cả `--lab-capture` và `--twin-lab`:

```powershell
python run_system.py --probe host --broker-host 127.0.0.1 --broker-port 1883
```

`HOST_CAPTURE_INTERFACES` rỗng/unset thì máy hiện tự chọn Wi-Fi. Nếu muốn chỉ định, dùng tên thiết bị từ TShark, không dựa vào số NIC cũ. Máy phải đang kết nối Wi-Fi; mở trang web/tạo hoạt động sử dụng bình thường để có traffic. Capture host ở đây thấy traffic của máy, không phải toàn bộ Wi-Fi của mọi thiết bị.

**Quan sát loopback**:

```powershell
python run_system.py --probe host --broker-host 127.0.0.1 --broker-port 1883 --lab-capture
```

Flag này chỉ chọn interface; không tự chạy workload. Dashboard/MQTT của chính hệ thống bị filter loại, nên có thể không có packet nếu không có ứng dụng localhost khác hoạt động. Muốn workload và PCAP có nhãn, dùng `--twin-lab`, bấm Normal và chờ COMPLETED. Wi-Fi đi Internet không xuất hiện trên loopback.

Validation: 11 tests pass, một native capture opt-in được skip; kiểm thử UDP một datagram benign và TCP một connect bị từ chối trên localhost. Đã xác minh adapter với TShark thực, kiểm tra syntax; chưa chạy lại các burst attack hoặc khảo sát Wi-Fi dài hạn sau sửa.
