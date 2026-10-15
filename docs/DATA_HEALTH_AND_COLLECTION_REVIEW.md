# Kiểm tra dữ liệu, preprocessing và thu thập mạng

Ngày kiểm tra: 2026-10-11. Dựa trên mã nguồn và toàn bộ hai CSV/31 Parquet cục bộ. Không chạy tấn công, flash firmware hoặc train lại model triển khai.

## Kết luận về dữ liệu

**Lake hiện tại không đủ điều kiện concat vào Edge-IIoTset để train model 56 đặc trưng: 0/79.483 bản ghi được chấp nhận.** File đọc được và các cột số cũ không có NaN/Inf, nhưng đơn vị quan sát, schema, nguồn đo và nhãn không tương thích.

| Nguồn | Dòng | Cột | Đặc trưng canonical trong code |
|---|---:|---:|---:|
| ML-EdgeIIoT-dataset.csv | 157.800 | 63 | 56 |
| DNN-EdgeIIoT-dataset.csv | 2.219.201 | 63 | 56 |
| Lake: 31 Parquet | 79.483 | 36 | 0 |

CSV có 61 cột nguồn và 2 nhãn. Code loại 5 trường thời gian/địa chỉ, giữ 56 đặc trưng và không dùng nhãn làm X. Lake chỉ lưu window metrics như packet/byte rate, tỷ lệ và số lượng; không có vector packet canonical.

- Tất cả lake ghi `probe_type=esp32` do collector trước đây dùng default, không được launcher truyền probe thật. Không thể xác nhận nguồn từ cột này.
- 1.321 bản ghi trùng `(session_id, timestamp)`: dấu hiệu cần điều tra, chưa đủ chứng cứ xóa vì thiếu device/packet ID.
- 2.645 timestamp không phải epoch milliseconds. Uptime ESP32 từng bị dùng như UTC.
- 54.322 nhãn Normal không được xem là verified Normal: nhãn cũ lấy từ simulator status toàn cục, không quy thuộc flow/thiết bị.
- Không có schema/measurement provenance và verification của nhãn. Số baseline/ước lượng từng được lưu như phép đo.

Giữ nguyên dữ liệu gốc; quality gate loại khỏi training, không xóa hoặc sửa file cũ. Xem thống kê đầy đủ trong `scratch/data_health_audit.json`.

## So với paper và notebook tác giả

[Paper Edge-IIoTset](https://doi.org/10.1109/ACCESS.2022.3165809) mô tả 61 đặc trưng chọn từ 1.176 đặc trưng và tách train/test trước encoding/standardization trong quy trình thí nghiệm. Không có cơ sở thay từng trường Wireshark bằng thống kê radio ESP32.

[Notebook của tác giả](https://www.kaggle.com/code/mohamedamineferrag/edge-iiotset-pre-processing/input) loại thêm TCP ports/options/payload, HTTP body/URI và MQTT message; dùng dummy encoding, kể cả `dns.qry.name.len`. Code dự án giữ 56 cột và ordinal mappings, **không tái lập nguyên xi preprocessing hoặc kết quả paper**.

| Giá trị không tương thích với trường số của dự án | ML CSV | DNN CSV |
|---|---:|---:|
| `tcp.srcport` | 367 | 367 |
| `dns.qry.name.len` | 29 | 1.845 |

Có tên host trong trường port và tên DNS trong trường chiều dài. Notebook tác giả xử lý chiều dài DNS như category có thể giữ giá trị này, nhưng không làm nó thành độ dài DNS thực đo. Với hợp đồng numeric của dự án, không tự đổi chỗ/sửa giá trị vì thiếu PCAP gốc. Số lỗi theo cột có thể giao nhau; audit kiểm tra theo dòng xác nhận 396 dòng ML và 2.212 dòng DNN không tương thích numeric contract.

Mặc định loader báo lỗi. Chọn `--invalid-rows drop` để chủ động loại các dòng không tương thích trước sampling/split, có thống kê trong `dataset_quality` metadata. CSV gốc không bị sửa. Đây chưa phải bằng chứng rằng các dòng còn lại tổng quát hóa tốt ngoài thực địa.

Theo ghi chú `Literature/papers.txt`, WAMM dùng HTTP text/payload; encrypted/ML_Trans_LLM phân loại ứng dụng hoặc luồng; SDN còn điều khiển switch. Các đơn vị quan sát/nhãn này không được concat chỉ vì đều là network data. Phần này đối chiếu ghi chú cục bộ, không tái lập các thí nghiệm PDF.

## Các lỗi đã sửa

- Split raw trước fit; preprocessing được fit độc lập trong từng fold CV/HPO. Anomaly HPO có validation nội bộ riêng, không chấm trên Normal đã fit.
- Loại exact feature/label duplicates trước sampling/split. Benchmark thiếu flow/session ID đáng tin nên random stratified holdout chưa chứng minh khả năng tổng quát hóa giữa môi trường.
- Raw HTTP/DNS/MQTT categories chỉ encode một lần. TCP payload/options giữ category; chuỗi payload giữ leading zeroes. Numeric `0x...` được parse đúng.
- Bỏ giả lập stream ID bằng packet rate, checksum bằng boolean, content length bằng byte rate và TCP ports/flags bằng tỷ lệ window. Bỏ clipping cứng 1e9 làm sai sequence/ack lớn.
- Dataset thiếu không tự fallback synthetic; nhãn thiếu không mặc định Normal. Evaluation lỗi trả null kèm lý do; F1=0 giữ nguyên. CV không được giả thành test score khi thiếu holdout.
- Metadata có preprocessing version 2, quality policy, semantics và cờ refit sử dụng holdout. Tạm chặn `--timeseries` cho tới khi có session grouping và runtime/export parity.
- Collector lưu đúng probe/backend/clock/schema; simulator status chỉ là ngữ cảnh. Nhãn chưa xác minh là Unknown. Giữ raw canonical fields khi producer cung cấp; thiếu phép đo không thành zero/baseline.
- ESP uptime lưu riêng, lake dùng receipt epoch milliseconds. Receipt time chưa phải capture time đồng bộ NTP.
- Kiểm tra JSON/finite numbers, chống duplicate USB/MQTT bằng cache giới hạn. Parquet ghi file tạm rồi replace; flush lỗi không báo đóng phiên thành công.
- Psutil chỉ giữ aggregate I/O thực đo; bỏ tỷ lệ giao thức, IAT/std dựng từ hệ số. OS offload/multiple interfaces vẫn khiến counters không tương đương packet capture.
- ESP32 không parse protected Wi-Fi như plaintext; kiểm tra IP header/fragment; FreeRTOS lock bảo vệ counters/snapshot và copy Wi-Fi records. Port bitmap chỉ là hashed estimate. JSON overflow và publish failure được kiểm tra; buffer MQTT phù hợp payload.

**Thay đổi suy luận:** window/packet không tương thích hoặc artifact cũ trả `inference_status=unavailable`, `threat_type=Unknown`, `anomaly_score=null`, `is_anomaly=null`; dashboard hiển thị N/A/UNKNOWN. Firmware không còn dựng 56 packet features từ radio window để gọi TinyML. Edge prediction hiện Unknown/unavailable cho model packet.

Hai probe hiện tại chưa phát đủ packet 56 trường; bản sửa không tự tạo model window hoặc retrain artifact cũ. Để inference hợp lệ cần producer packet tương thích hoặc model riêng học trên window mà probe thực đo được, kèm kiểm chứng Python/C parity.

## Cấu hình mạng khảo sát

Copy `.env.example` thành `.env` ở root, điền `WIFI_SSID`, `WIFI_PASSWORD`, `MQTT_BROKER_HOST`, `MQTT_BROKER_PORT`, `MQTT_CLIENT_ID`. Giá trị process environment ưu tiên hơn `.env`; CLI broker host/port ưu tiên hơn environment. `AUTO_DETECT_WIFI=false` và `MQTT_AUTO_DISCOVERY=false` mặc định; không tự ghi đè cấu hình thủ công.

| Chế độ | Cách nạp và giới hạn |
|---|---|
| `python run_system.py --probe host` | OS phải kết nối mạng khảo sát trước; không dùng SSID/password để tự join Wi-Fi. Chọn `HOST_CAPTURE_INTERFACES` theo `tshark -D`, ví dụ `"2"` hoặc danh sách comma-separated. Không có TShark có thể fallback raw socket/psutil: xem `capture_backend`. |
| `python run_system.py --probe esp32` | Launcher tạo ignored `firmware/esp32_probe/credentials.h` từ `.env`; firmware include khi compile. **Đổi credentials phải build/flash lại**; chạy Python không cập nhật chip đã nạp. Broker address phải truy cập được từ board, không dùng localhost. |
| `SNIFFER_MODE_ALL_NETWORKS=false` | Nối AP cấu hình và MQTT Wi-Fi; radio khóa kênh AP, chưa filter BSSID, có thể thấy mạng khác cùng kênh. |
| `SNIFFER_MODE_ALL_NETWORKS=true` | Ngắt AP, nhảy kênh; JSON qua USB Serial -> bridge -> MQTT, không MQTT Wi-Fi trực tiếp. |

WPA payload không tự giải mã bởi promiscuous mode. Host chỉ thấy lưu lượng đi qua interface của mình. Khảo sát toàn LAN cần điểm quan sát gateway/SPAN/TAP; tên SSID không chứng minh đã bắt toàn mạng.

## Mosquitto

Profile hiện tại **anonymous/plaintext cho development**, chưa đủ cho deployment với client không tin cậy: 1883 và WebSocket 9001 bind mọi interface. [Mosquitto documentation](https://mosquitto.org/man/mosquitto-conf-5.html) mô tả password authentication, ACL và TLS; các client dự án chưa hỗ trợ cấu hình auth/TLS thống nhất.

Đã sửa vận hành:

- Native runtime config dùng TCP port CLI và persistence path tuyệt đối; log ra `broker/data/mosquitto.log`, không giữ stderr pipe không drain.
- Readiness kiểm tra MQTT CONNECT/CONNACK; TCP listener bất kỳ không được coi là MQTT.
- Dừng broker con khi startup timeout trước fallback.
- Docker dùng `broker/mosquitto.docker.conf`, persistence `/mosquitto/data/` khớp volume. Native có config riêng.
- Broker host/port truyền thống nhất tới inference/dashboard/probe/collector/USB bridge; remote broker phải chạy sẵn.
- Embedded Python là fallback lab QoS 0, không tương đương persistence/auth/ACL/TLS của Mosquitto.

Ngoài lab cần auth/TLS trên mọi client, ACL theo vai trò, xác thực quy trình gán nhãn và bảo vệ topics điều khiển. Một JSON anonymous tự khai `label_verified=true` không chứng minh provenance đáng tin.

## Format và pipeline

Xem `docs/MQTT_API_SPEC.md` cho JSON minh họa. Host/ESP32 hiện gửi `record_kind=window`, `feature_semantics=window-v1` qua `edge/telemetry/traffic`. Host TShark/raw có một số packet/text clues; psutil chỉ I/O; ESP radio có plaintext counts không đầy đủ. Cùng window-v1 không đảm bảo cùng measurement scope.

Traffic fan-out tới collector và inference. Collector lưu raw + provenance vào Parquet. Với packet tương thích: raw extract -> transform một lần bằng saved preprocessor -> classifier/anomaly detector -> `edge/telemetry/prediction` -> FastAPI MQTT bridge -> WebSocket/dashboard. Với window hiện có, prediction unavailable vẫn được gửi để UI thấy trạng thái; lỗi inference không thành alert tấn công.

Trước concat field data: đủ canonical packet fields đúng nghĩa/đơn vị, unique packet/device ID, epoch time, missing-fields declaration và verified flow labels; giữ holdout khác session/môi trường. Cho ESP32, cần PCAP để aggregate benchmark theo đúng window/features đo được hoặc dataset window riêng. Không khôi phục được packet fields đã mất từ Parquet windows cũ.

## Kiểm chứng và giới hạn

- `python -m unittest discover -s tests -v`: **18 tests passed**; kiểm tra encoding/split/eligibility/Unknown/config/MQTT/Parquet, bỏ qua defense khi inference unavailable và smoke training bằng fixture tạm. Exporter được mock, không ghi đè model/header triển khai.
- Audit: `python -m ml_engine.eda.audit_data_health --output scratch/data_health_audit.json`; quét toàn bộ hai CSV và Parquet, chỉ xuất counts.
- Python syntax/CLI và JavaScript syntax được kiểm tra riêng.
- Chưa có Arduino CLI/Mosquitto native trên PATH môi trường kiểm tra; không xác nhận firmware compile/RAM/flash, radio capture, Docker startup hay MQTT qua board.
- Không train lại benchmark hoặc đo độ chính xác thực địa. Artifacts cũ cần retrain với preprocessing version 2 trước inference packet hợp lệ.
