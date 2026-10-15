# Digital Twin: thí nghiệm có capture và nhãn theo flow

**Cập nhật v4 (12/10/2026):** Fingerprinting, MITM, Backdoor và Ransomware đã có
surrogate container kiểm chứng effect và đủ điều kiện supervised training theo flow.
Xem [hướng dẫn v4](TWIN_SURROGATES_V4.md). Các mô tả v3 về loại bốn surrogate
bên dưới áp dụng cho dữ liệu cũ; không sửa eligibility của phiên cũ.
Trên Windows, `--twin-lab` tự mở Docker Desktop nếu cần và chờ Linux engine tối đa
120 giây; không cần mở Desktop trước bằng tay. Cài đặt/WSL2 setup vẫn phải hoàn tất.

## Chạy Normal ngay trên Windows

Phiên Twin chạy workload thật tới HTTP lab trên loopback. Không sinh vector đặc trưng từ mô hình vật lý Twin. Backend sở hữu worker capture/workload/import; Live Digital Twin nhận trạng thái thí nghiệm qua MQTT và đưa vào summary của Twin.

1. Dừng phiên launcher cũ bằng Ctrl+C. Nếu còn terminal `lab_http_service` cũ, dừng nó để giải phóng cổng 8088; chế độ native mới tự tạo và đóng dịch vụ HTTP.
2. Chạy:

```powershell
python run_system.py --probe host --twin-lab --broker-host 127.0.0.1 --broker-port 1883
```

3. Ctrl+F5 dashboard. Chọn thời lượng 1–60 giây (mặc định 15), bấm **Normal — Thu HTTP GET/POST**. Có thể để hết thời lượng hoặc bấm **Dừng & lưu**. Chờ `COMPLETED` trước phiên kế tiếp; các nút lớp bị khóa khi capture/import đang chạy.

`--twin-lab` chọn loopback theo tên thiết bị, không dùng số NIC cố định. Trên máy đã kiểm tra, cài WSL/Hyper-V làm số loopback đổi 8 → 9. Flag chỉ đổi capture của lần chạy; không sửa `HOST_CAPTURE_INTERFACES` hoặc `LAB_CAPTURE_INTERFACES` trong `.env`. Không kết hợp `--attack-sim` hoặc `--lab-capture`: các nút UI mới dùng worker thí nghiệm, không cần generator legacy chạy nền.

Cấu hình trong `.env` nếu muốn đổi mặc định:

```dotenv
TWIN_LAB_BACKEND="native"
TWIN_CAPTURE_INTERFACE="auto-loopback"
LAB_HTTP_PORT=8088
```

Target thí nghiệm hiện cố định `127.0.0.1`. Cổng HTTP lab phải khác dashboard/MQTT. Native bind chỉ loopback và fail rõ nếu cổng đang bị chiếm.

`--lab-capture` hiện dùng `LAB_CAPTURE_INTERFACES=auto-loopback` (tên thiết bị ổn định), chỉ quan sát loopback và không tự sinh workload. Muốn quan sát Wi-Fi của máy, bỏ `--lab-capture`/`--twin-lab` và để `HOST_CAPTURE_INTERFACES` rỗng hoặc chỉ định đúng interface Wi-Fi. Capture loại MQTT/dashboard của hệ thống nên loopback không có ứng dụng khác hoạt động có thể không có packet.

TShark chạy ngầm khi launcher khởi động host probe; không cần mở Wireshark thủ công. Launcher kiểm tra adapter trước khi chạy. Discovery chờ tối đa 15 giây và báo nguyên nhân timeout/exit/Npcap thay vì biến lỗi thành danh sách rỗng. Nếu cấu hình interface sai, đặt `TWIN_CAPTURE_INTERFACE="auto-loopback"`; giá trị rỗng cũng dùng mặc định này. Có thể kiểm tra bằng `& 'C:\Program Files\Wireshark\tshark.exe' -D` trong PowerShell. Không thấy loopback thì kiểm tra Npcap; không tự chuyển sang Wi-Fi vì workload Twin đang dùng localhost.

## Normal làm gì và gán nhãn như thế nào?

Workload Normal tạo kết nối HTTP mới, chọn GET/POST, kích thước 64/512/4096/16384 byte, khoảng nghỉ 50–200 ms, seed 42. Đây là baseline **Normal HTTP**, chưa phải baseline đủ HTTP/MQTT/DNS của một mạng IoT.

Mỗi socket được ghi nguồn/đích/port/protocol và khoảng thời gian. Flow Normal được xác minh khi trả HTTP 200, header `X-AERO-Lab: normal-http-v1` và nội dung đúng kích thước/byte đã yêu cầu. Packet hai chiều khớp flow này được lưu:

```json
{
  "requested_attack_label": "Normal",
  "ground_truth_scenario": "Normal",
  "label_method": "automatic_flow",
  "label_source": "controlled_flow",
  "scenario_label_scope": "bidirectional_flow",
  "data_provenance": "twin-controlled-lab"
}
```

Traffic không khớp endpoint, transport hoặc khoảng thời gian giữ `Unknown`. Không bấm nút không tự gán nhãn Normal cho traffic nền. Model prediction không tham gia quyết định nhãn.

## Capture và lưu trữ

Badge workload lấy trạng thái worker, độc lập với kết quả model: vàng khi đang chuẩn bị/chạy/lưu, xanh khi đã hoàn tất, đỏ khi lỗi. API status được đọc mỗi 5 giây để bổ sung cho WebSocket. `Normal` trên thẻ ML là dự đoán, không xác nhận workload đã dừng.

Ngày 12/10/2026: static server gắn fingerprint chung cho entrypoint và toàn bộ import JS tương đối, trả module với `no-store`, tránh dùng lẫn module cũ sau reload. Cần restart backend để kích hoạt static server mới. Biểu đồ bổ sung đọc `/api/status` mỗi 2 giây; cửa sổ đo trùng timestamp/device/capture ID chỉ được thêm một lần dù đến qua cả WebSocket và API.

Log `[Host] captured=... published=... dropped=... failed=...` thuộc đường MQTT realtime. `published` đếm PUBACK, `dropped` gồm packet bị bỏ do queue đầy; `failed=0` không loại trừ queue drop. Ví dụ 70.527/84.617 = 83,4% drop, không phù hợp để coi MQTT collector là bản lưu đầy đủ. Capture thí nghiệm Twin dùng PCAP riêng; cần xem COMPLETED và các số `pcap_packets`, `parsed_packets`, `rejected_packets`, `saved_rows` trong manifest để kiểm tra nhập dữ liệu. Log realtime không chứng minh PCAP mất hay giữ đủ packet ở driver.

```text
UI → POST /api/experiments/start
   → Twin worker sở hữu HTTP target/workload/dumpcap
   → PCAPNG trên đĩa
   → TShark hai lượt, 56 canonical features
   → đối chiếu manifest flow
   → Parquet batch trực tiếp, không qua queue MQTT từng packet
```

- PCAP/manifest/log: `data_lake/experiments/<experiment_id>/`; thư mục này bị Git ignore vì có thể chứa payload/IP/port.
- Parquet: `data_lake/raw/date=.../`, session có `sniffer_mode=twin-experiment-pcap`, cùng experiment ID và provenance trong từng dòng.
- Manifest lưu scenario, seed, flow, tham số capture, fingerprint PCAP và bộ đếm. Ghi manifest bằng temporary file rồi replace.
- Capture tối đa khoảng 64 MiB và 65 giây; không dùng ring buffer ghi đè dữ liệu chưa xử lý. Nếu capture kết thúc sớm hoặc import lỗi thì phase ERROR và giữ dữ liệu gốc.
- Nếu có capinfos, đối chiếu `pcap_packets = parsed_packets + rejected_packets`. Import tối đa 120 giây. Không cam kết zero kernel/Npcap drop; PCAP và capture log là nguồn kiểm tra.
- UI hiện phase, số đã lưu, gán nhãn, xác minh và Unknown. Số chỉ tăng sau bước import; capture đang RUNNING chưa có nghĩa đã ghi các dòng Parquet.
- Header Capture/Drop của probe realtime vẫn là đường MQTT riêng. Nó có thể drop trong khi thí nghiệm Twin đã lưu đầy đủ các frame trong PCAP. Collector realtime có thể lưu thêm Unknown từ cùng hoạt động; các dòng đó không tự được training gate chấp nhận.

API:

```json
POST /api/experiments/start
{"scenario": "Normal", "duration_sec": 15}
```

`POST /api/experiments/stop` yêu cầu dừng cooperative rồi import; response accepted chưa đồng nghĩa đã lưu xong. `GET /api/experiments/status` và WebSocket `EXPERIMENT_STATUS_UPDATE` cung cấp trạng thái cuối. Chỉ một phiên được chạy/import tại một thời điểm.

## Các nút attack

SQLi/XSS dùng [grammar generator](SQLI_XSS_VARIANTS.md), 8 family mỗi lớp và GET query/POST form/POST JSON. Một instance/seed tồn tại xuyên suốt experiment; không reset biến thể mỗi burst. Manifest lưu request_generator (version, seed, generated_requests, families, placements); packet khớp flow lưu request_variant_id/request_template_family/request_placement/request_method. Các trường này bị loại khỏi model inputs canonical.

Các nút hiện có chạy pattern đã triển khai trong lab và tự lưu nhãn cho packet khớp socket thực:

- HTTP workload, SQLi/XSS request, TCP connect workload và UDP legacy đều giới hạn ở endpoint lab loopback; không gửi broadcast hoặc chọn gateway.
- Từ workload v3, Port Scanning quét nhiều cổng lab đã reserve; Vulnerability_scanner gửi HTTP endpoint probes. Không quét dịch vụ khác của Windows.
- Mỗi phiên dùng burst hữu hạn và nghỉ giữa burst, không phải mô phỏng DDoS phân tán đã được xác minh.
- Từ v3, Uploading là multipart HTTP fixture; SQLi nhắm SQLite chỉ SELECT trên DB mới trong RAM, XSS nhắm reflection endpoint. Chưa test browser execution hay webshell execution.
- SQLi/XSS đọc HTTP response trước khi đóng socket (timeout 2 giây, body tối đa 64 KiB) để tránh abort khi server đang ghi. Một request đang chạy hoàn tất/fail theo timeout trước khi hủy lượt tiếp theo. Server đếm disconnect dự kiến ở `client_disconnects`, log debug không ghi payload; không spam traceback cho ConnectionAborted/Reset/BrokenPipe. Lỗi khác vẫn được báo.
- Packet attributable tự lưu `ground_truth_scenario=<lớp chọn>`, `requested_attack_label=<lớp chọn>`, `label_method=automatic_flow`, `label_source=controlled_flow`. Training không yêu cầu `label_verified`; vẫn kiểm tra canonical label, source, packet schema, feature/identity. Nhãn là attribution workload, không chứng minh attack đạt tiêu chí benchmark.
- Twin v3 có dispatch cho 15 labels; legacy generator có registry riêng. Surrogates lưu nhãn với fidelity nhưng không vào supervised training. `Adversarial` không được thu như một lớp benchmark.

Normal giữ kiểm tra HTTP response cho hoạt động dịch vụ, không dùng nó làm verified gate cho nhãn. Native workload v3 và raw container được mô tả trong [audit](TWIN_ATTACK_AUDIT_20261012.md). Chưa tái hiện đủ benchmark 14 attacks, MQTT Normal hoặc tự retrain model.

### Policy tự động và filter từ 12/10/2026

Filter v2 chỉ cổng chính là policy của các capture cũ. Workload v3: scan dùng range
đã reserve, HTTP/UDP dùng cổng chính, DNS tampering thêm UDP chính+2, ICMP echo dùng
identifier riêng. Manifest lưu capture_filter thực, scenario_version/fidelity và
supervised_training_eligible. Import version 3 giữ 56 canonical fields và thêm ICMP
identifier/type làm metadata attribution.

Phiên mới bỏ `label_verified`/`verified_rows`; UI hiện Lưu / Nhãn tự động / Unknown.
Training loại surrogate và attack Twin trước manifest v3 (workload legacy có sai
ngữ nghĩa); giữ nguyên Parquet/nhãn cũ để audit. Native Normal cũ và field captures
manual_review vẫn dùng schema gate bình thường. Projection training luôn đọc thêm
metadata eligibility nên không bỏ qua exclusion. Không tự train hoặc đổi artifacts.

Pilot policy mới: native Normal localhost 1 giây thu/parse/lưu 105 packet, 105 nhãn tự động, Unknown 0; Parquet không có cột label_verified và training eligibility nhận đủ 105 dòng. Đây là kiểm tra pipeline nhỏ, không xác minh tính đại diện của workload hoặc throughput dài hạn.

## Docker backend tùy chọn

Đã cung cấp `digital_twin/lab/compose.yaml` với HTTP target trên network nội bộ, chỉ publish cổng tới `127.0.0.1`, không mount `.env` hay toàn bộ repository. Khi Docker Desktop Engine đã chạy:

```powershell
docker compose --env-file .env -f digital_twin/lab/compose.yaml up -d
```

Đặt `TWIN_LAB_BACKEND="docker"` rồi restart launcher. Worker dùng HTTP qua cổng publish localhost và capture loopback **phía Windows**. Đây không phải capture toàn bộ traffic giữa container trong bridge network. Compose không được tự bật từ import hoặc khi mở UI.

Dừng lab do compose này sở hữu:

```powershell
docker compose -f digital_twin/lab/compose.yaml down
```

## Validation đã thực hiện

- Bộ regression: 50 tests, pass với 1 native capture opt-in bị skip ở lần full suite. Test chọn loopback ổn định được bổ sung và kiểm tra trong lượt focused tiếp theo.
- Lượt focused cuối: 7 tests pass, bao gồm **capture native Normal thực 1 giây tại cổng tạm 18088**. PCAP/import đối chiếu, 107 dòng đã lưu, 107 dòng Normal xác minh, 0 Unknown, 0 rejected; cả 107 được training gate chấp nhận. Tất cả artifact test ở thư mục tạm, không overwrite dataset/model hiện có.
- Hai regression JavaScript pass, gồm map nút → API, ACK, lỗi/timeout, khóa nút khi RUNNING và Dừng & lưu.
- Python syntax checks và `docker compose ... config --quiet` pass. Chưa chạy container lab vì Docker Engine chưa khả dụng ở lần kiểm tra ban đầu; chưa xác minh attack thực, ESP32 hoặc chất lượng model sau training.
