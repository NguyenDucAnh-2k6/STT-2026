# Audit attack Twin, 12/10/2026

Ghi chú cập nhật: implementation v4 của bốn surrogate và quy tắc training mới
được trình bày trong [TWIN_SURROGATES_V4.md](TWIN_SURROGATES_V4.md). Báo cáo v3
dưới đây giữ nguyên kết quả lịch sử, không áp dụng eligibility mới cho dữ liệu cũ.

Snapshot được freeze từ 16 experiment liền nhau, bắt đầu 21:02:34 đến 21:08:31
(Asia/Bangkok). Không sửa nhãn hoặc packet của phiên đã collect. Báo cáo máy đọc:
`scratch/twin_latest_paper_audit_20261012.json`. Đối chiếu dùng CSV selected ML local,
không phải toàn bộ PCAP gốc của tác giả.

## Kết quả phiên vừa chạy

| Nhãn | Dòng Parquet | Chẩn đoán hành vi cũ |
| --- | ---: | --- |
| Port_Scanning | 413 | 59 flow tới duy nhất 8088; cổng mở, SYN/ACK và handshake đầy đủ. |
| Vulnerability_scanner | 1.624 | Chỉ TCP connect; không có HTTP method/scan payload. |
| DDoS_TCP | 10.399 | TCP connect workload, không phải crafted SYN-only generator. |
| DDoS_UDP | 3.648 | UDP burst; một nguồn loopback, chưa đo DoS impact. |
| Uploading | 2.784 | Hoàn toàn UDP; sai giao thức so với web upload. |
| SQL_injection, XSS, DDoS_HTTP | 0 | Bốn experiment ERROR: allowlist không chứa loopback. |

18.868 dòng đã lưu đều khớp flow khi chạy lại attribution; Unknown=0 và không có
sai lệch nhãn/flow. Đây là tính đúng của attribution, **không phải xác nhận đúng attack**.
Feature/schema gate cũ nhận các packet này; policy mới loại attack Twin manifest
trước v3 để tránh tiếp tục train trên generator sai ngữ nghĩa. Parquet và nhãn cũ
giữ nguyên cho audit. Normal Twin cũ/Normal thực địa đã manual review không bị loại
bởi điều kiện legacy attack này.

### So với benchmark local

- Port_Scanning: 10.071 dòng; SYN-only 4.394, SYN/ACK 0, RST-bit 4.524. Các SYN trong
  selected CSV chỉ tới 80. Nhiều `tcp.dstport` ở toàn bảng là cổng client ở chiều
  phản hồi; không thể gọi đó là số cổng bị scan. Twin cũ khác ở response/handshake.
- Vulnerability_scanner: benchmark có 4.286 GET, 25 POST và một OPTIONS; Twin cũ
  không có HTTP request nào.
- Uploading: benchmark có 10.259/10.269 dòng có tcp.srcport khác 0 và không có
  udp.port khác 0; Twin cũ hoàn toàn UDP. Packet mang nhãn không đủ chứng minh upload.
- DDoS_TCP: benchmark SYN-only 6.009, SYN/ACK 0, RST-bit 4.238; generator cũ gọi
  connect_ex, không tạo SYN headers trực tiếp.
- DDoS_UDP trong CSV local: cả 14.498 dòng udp.port=0, nhưng udp.stream có giá trị
  và tcp.srcport nhiều dòng khác 0. Đây là dấu hiệu cần đối chiếu PCAP gốc và cách
  trích xuất của tác giả; không suy ra protocol thật chỉ từ feature khác 0, không
  thay đổi số đo TShark để ép distribution giống CSV. Cùng tên 56 cột chưa bảo đảm
  cùng semantics. Vì vậy generator mới vẫn cần evaluation theo domain/sessions.

## Cơ sở paper và mức độ tái hiện

Paper mô tả SYN/UDP/HTTP/ICMP floods; Nmap/Netcat port discovery, xprobe2 fingerprint,
Nikto web scanning; SQLmap, XSS và upload trong web application; Ettercap MITM;
Metasploit backdoor, CeWL/password trials và OpenSSL encryption sau backdoor.
[Ferrag et al., IEEE Access 2022, “Attacks in Edge-IIoTset Dataset”](https://doi.org/10.1109/ACCESS.2022.3165809).

Implementation dưới đây là workload lab dựa trên loại hành vi, không phải chạy đúng
tool/testbed/dataset của paper. Benchmark gồm Normal + 14 attacks, không phải 15 attacks.

| Mode mới | Implementation v3 | Giới hạn |
| --- | --- | --- |
| Port_Scanning | TCP scan dải cổng reserve, hai open và còn lại closed; thứ tự shuffle. | TCP connect scan, không tuyên bố tương đương toàn trace Nmap. |
| Vulnerability_scanner | Probe robots/admin/config/backup qua HTTP. | Không chạy toàn bộ Nikto, không chứng minh exploit. |
| SQL_injection | Grammar 8 families/query/form/JSON; SELECT injection trên SQLite mới trong RAM. | Chỉ read/query; không PHP/MySQL, DDL/files/extensions bị chặn. |
| XSS | Grammar đa family vào endpoint phản chiếu HTML, CSP sandbox. | Có reflection, chưa kiểm tra execution bằng browser. |
| Uploading | Multipart HTTP file fixture, hash/count trong RAM. | Không execute PHP/webshell; nhãn biểu thị upload attempt. |
| DDoS_HTTP | GET/POST bursts, concurrency 4, nhiều path/size. | Bounded load, chưa distributed DoS/slowhttptest equivalence. |
| DDoS_UDP | UDP receiver thực, payload nhiều size, counter receive. | Một nguồn; không đủ chứng minh quá tải dịch vụ. |
| DDoS_TCP | Crafted IPv4/TCP SYN, checksum thật, loopback Linux. | Có thể có kernel RST trả về; không sửa firewall hay giả DoS impact. |
| DDoS_ICMP | Echo packets, checksum/ID; attribution chỉ echo type + ID + time. | Không lấy ICMP Port Unreachable làm nhãn attack. |
| Password | Failed/success login attempts vào account fixture. | Không dùng credentials thật; cần Normal login controls đa dạng hơn. |
| Fingerprinting | HEAD/OPTIONS/banner probes. | Service fingerprint surrogate, chưa xprobe2 OS probes; không train. |
| MITM | Resolver lab + relay thay answer DNS 127.0.0.1 thành 127.0.0.2. | Không sửa DNS OS hoặc poison ARP; surrogate tách training. |
| Backdoor | Allowlisted RPC status/list/read fixture. | Không shell/persistence/Metasploit; surrogate không train. |
| Ransomware | Reversible byte encryption của fixture trong RAM. | XOR surrogate, không RSA/OpenSSL hay host-file malware; không train. |

## Allowlist và cách chạy

Đã bổ sung riêng 127.0.0.1/32 vào LAB_ALLOWED_TARGETS thực tế; startup --twin-lab
cũng tự bảo đảm và persist khóa này. Không thay các CIDR đã có, không mở rộng
allowlist ra toàn LAN. Twin target vẫn cố định localhost và services được sở hữu.

```powershell
python run_system.py --probe host --twin-lab --broker-host 127.0.0.1 --broker-port 1883 --classifier random_forest --anomaly-model isolation_forest
```

Restart launcher để nhận code/asset mới. Native mặc định sở hữu TCP 8088–8099,
hai HTTP listeners và các TCP reservation không listen; UDP receiver 8088. `.env`
LAB_HTTP_PORT và TWIN_SCAN_PORT_COUNT thay được dải này, count 3..32. Nếu có service
khác chiếm cổng, startup experiment báo lỗi thay vì scan nhầm ứng dụng khác.

Capture scan chỉ dải reserve; HTTP/UDP cổng chính; DNS fixture thêm UDP chính+2;
ICMP chỉ identifier của experiment. Live host dùng hợp scope lab và vẫn có queue
capacity riêng. Canonical feature order/count không đổi; ICMP identifier/type,
scenario_version/fidelity và eligibility là metadata, không đưa vào model.

Windows dùng Docker Linux cho SYN/ICMP. Image `aero-twin-raw:v3` tự build lần đầu
nếu thiếu; có thể chuẩn bị trước bằng:

```powershell
docker build -t aero-twin-raw:v3 -f digital_twin/lab/raw_lab.Dockerfile .
```

Container `--network none`, không mount credentials/repository, chỉ mount thư mục
experiment và tmpfs; raw capabilities chỉ ở namespace container. PCAP/flow manifest
được import về lake host. Host realtime không thấy container loopback; raw experiment
trong container hiện là luồng collect/import, không đồng nghĩa live inference UI.
Image chứa source tại thời điểm build: rebuild khi sửa code raw lab.

## Validation và training

13 native experiments, mỗi mode một giây, trong thư mục tạm: 3.702 packet, 3.702
nhãn attributable, Unknown 0. Quality gate nhận 3.236 dòng, loại 466 surrogate;
duplicate identity/malformed numeric 0. SQLi 414, XSS 416 và DDoS_HTTP 1.175 dòng
hoàn tất, không còn lỗi allowlist. Kết quả này chứng minh pipeline nhỏ chạy được,
không chứng minh độ đa dạng, benchmark equivalence hay sức chịu tải.
JSON: `scratch/twin_v3_native_validation_20261012.json`.

Regression: 8 workload/fixture/gate, 12 Twin (một integration opt-in skipped),
4 PCAP/MQTT, 19 data contract và 5 window/UI tests pass. Raw container validation
đã chạy: DDoS_TCP 288 packet (96 SYN, 96 SYN/ACK, 96 RST); DDoS_ICMP 192 packet
(96 echo request, 96 reply). Cả 480 packet đều có nhãn, eligible, Unknown 0,
malformed/duplicate identity 0. SYN generator không hoàn tất ACK handshake; kernel
có gửi RST về SYN/ACK, nên đây chưa phải đo tác động half-open DoS. JSON:
`scratch/twin_v3_raw_validation_20261012.json`. Image đã được build trên Docker Linux
engine và giữ lại để chạy từ UI; container test dùng --rm đã kết thúc.
Nút Dừng & lưu raw dùng stop request trong thư mục experiment; worker kết thúc
dumpcap/import trước khi thoát. Đã kiểm tra dừng sớm ICMP và vẫn COMPLETED, có nhãn.

Chưa retrain/ghi đè artifacts model hoặc xóa capture cũ. Hãy collect lại những
attack legacy bằng workload mới; giữ session/domain/seed/flow riêng trong evaluation.
Normal hiện chủ yếu HTTP bytes và chưa bao phủ đầy đủ login/upload/DNS/IoT controls;
thiếu controls có thể khiến model học endpoint/tool thay vì hành vi attack.
