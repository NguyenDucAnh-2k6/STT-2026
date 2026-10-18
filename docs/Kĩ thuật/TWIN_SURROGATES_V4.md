# Surrogate v4: thu dữ liệu có nhãn cho supervised training

Chạy lại launcher để nạp source mới. Trên Windows, `--twin-lab` tự mở Docker Desktop
ngầm nếu cần và chờ Linux engine tối đa 120 giây:

```powershell
python run_system.py --probe host --twin-lab --broker-host 127.0.0.1 --broker-port 1883 --classifier random_forest --anomaly-model isolation_forest
```

Ctrl+F5 dashboard, chọn thời lượng và bấm lớp muốn collect. Bốn lớp dưới đây tự chạy
trong image `aero-twin-raw:v4`, không cần thêm flag hay đổi interface trong `.env`.
Nếu thiếu image, worker build từ `digital_twin/lab/raw_lab.Dockerfile`. Worker cũng
tự mở lại Docker Desktop nếu engine bị đóng giữa phiên. Docker lỗi
thì thí nghiệm báo ERROR, không dùng hành vi cũ thay thế rồi gán nhãn thành công.
`TWIN_LAB_BACKEND=native` vẫn dùng cho các lớp native; bốn surrogate tự chọn container.
`LAB_HTTP_PORT` và `TWIN_SCAN_PORT_COUNT` được chuyển vào container, không chuyển credentials.

Auto-start cần Docker Desktop đã cài và hoàn tất WSL2/virtualization setup. Hệ thống
không tự đổi Windows containers sang Linux containers hoặc sửa WSL/BIOS. Khi engine
chưa sẵn sàng sau 120 giây, báo lỗi với hướng dẫn kiểm tra Docker Desktop. Dừng AERO
không tắt Docker Desktop; chỉ container thí nghiệm do AERO sở hữu được cleanup.

| Nhãn | Hành vi v4 | Điều kiện nhận vào training |
| --- | --- | --- |
| Fingerprinting | Probe TCP SYN/ACK/SYN-ACK, nhiều window size, cổng open/closed; ICMP echo và HEAD/OPTIONS/GET banner. | Có đáp ứng TCP khớp tuple và ICMP echo reply khớp ID/body. |
| MITM | Resolver trả 127.0.0.1; relay sửa thành 127.0.0.2; client truy cập dịch vụ theo đáp án DNS. | Resolver baseline đúng, DNS transaction ID đúng và client nhận sensor value 21 thay baseline 20. |
| Backdoor | Fixture agent mở kết nối ngược tới listener; inventory/read commands và phản hồi bytes thật. | Handshake của agent đúng, tất cả lệnh fixture hoàn tất, tuple được recorder ghi nhận. |
| Ransomware | Qua kênh ngược: inventory → AES-256-GCM file fixture → truyền ciphertext → restore. | Ba file tự tạo bị thay bytes, authenticated decryption thành công và bytes khôi phục khớp ban đầu. |

Listener/agent không nhận địa chỉ, đường dẫn hoặc lệnh shell từ UI. Chỉ các command
fixture cố định được chấp nhận. File sinh trong thư mục tạm `/tmp` riêng; không mount
file người dùng. Container `--network none`, read-only root, tmpfs giới hạn 64 MB;
chỉ mount thư mục experiment để trả PCAP/manifest. Worker đóng socket, join agent
và xóa fixture sau mỗi exchange. AES-GCM dùng `cryptography` cài trong Dockerfile;
runtime host không phải cài thư viện này để chạy bốn nút.

## Nhãn và bộ lọc training

Raw PCAP được lưu trước, sau đó TShark đọc hai pass và import về `data_lake/raw/`.
Packet được gán nhãn theo tuple hai chiều/protocol/time; ICMP theo echo ID/type/time.
Unknown không được tự biến thành attack hoặc Normal. Nhãn thể hiện **flow của
thí nghiệm**, kể cả ACK/response trong flow đó; không có nghĩa từng packet là exploit.

Parquet mới có `experiment_manifest_version=4`, `scenario_version=twin-workloads-v4`,
`data_provenance=twin-controlled-lab`, `training_domain=controlled-surrogate-lab`,
`scenario_fidelity`, `evidence_contract`, `fixture_effect_ok` và
`supervised_training_eligible`. Bằng chứng được ghi sau exchange thành công;
flow thất bại/chưa có effect không nhận eligibility. Metadata chỉ phục vụ audit,
không được thêm vào 56 feature của model.

`data_lake/quality.py` kiểm tra cả contract đúng với nhãn, effect, manifest >=4 và
schema/numeric/attribution hiện có. Chỉ sửa flag thành true không đủ. Projection
khi train vẫn đọc các cột kiểm chứng. Bốn surrogate v3/v2 vẫn bị loại; cần collect
lại bằng v4, không sửa nhãn/flag của dữ liệu cũ.

Sau khi collect thêm Normal và các lớp khác, lệnh hiện có sẽ nhận các hàng v4 hợp lệ:

```powershell
python ml_engine/train.py --classifier random_forest --anomaly-model isolation_forest --data-source hybrid --invalid-rows drop
```

Đọc log `Eligibility` và số hàng từng nhãn trước khi đánh giá mô hình. Chưa chạy
retraining trong đợt triển khai này; artifacts đang dùng không tự học các phiên mới.

## Giới hạn về tính thực tế và đánh giá

Đây là dữ liệu supervised của **surrogate lab**, không bằng chứng tái hiện attack
thực địa. Paper dùng xprobe2, Ettercap ARP/DNS, Metasploit và OpenSSL/RSA; v4 dùng
probe giới hạn, DNS relay, kênh fixture và AES-GCM có phục hồi. Tham khảo
[paper Edge-IIoTset](https://doi.org/10.1109/ACCESS.2022.3165809).

Không suy luận tính thực tế từ packet rate hoặc từ việc bộ lọc chấp nhận dữ liệu.
Network trace của fixture encryption có thể giống tác vụ backup hợp lệ. Muốn giảm
shortcut cần Normal controls có DNS resolve, reverse RPC hợp lệ, truyền dữ liệu
opaque và mã hóa backup; thay đổi size/timing/service giữa nhiều phiên. Hiện Normal
vẫn chủ yếu HTTP GET/POST, chưa cung cấp đủ các controls này.

Trainer hybrid hiện đưa lake vào tập train, holdout benchmark không kiểm chứng khả
năng tổng quát trên lab mới. Phải đánh giá thêm trên phiên lab độc lập và môi trường
thực được phép; đừng dùng random split các packet cùng flow làm bằng chứng tổng quát.
Payload/command text đặc trưng fixture cần audit trước NLP training để tránh học
tên command thay vì hành vi. Không thêm evidence/label/source IDs vào inputs.

## Kiểm chứng

Regression: `python -m unittest discover -s tests -p test_controlled_surrogates.py`.
Các test native fixture cần `cryptography`; socket loopback cần được môi trường cho phép.
Integration ngắn: `python scratch/validate_twin_surrogates.py` chạy mỗi mode 1 giây
trong container rồi import/kiểm tra Parquet tạm, không sửa lake/model hiện có.
Kết quả lưu aggregate trong `scratch/twin_v4_surrogate_validation_20261012.json`.

Lần kiểm thử 12/10/2026: Fingerprinting 98, MITM 80, Backdoor 70, Ransomware 90
packet; 338 accepted, 0 rejected, 0 Unknown. Đây là thử nghiệm smoke một giây mỗi
mode, không phải đo độ chính xác model, tính thực tế hay độ bền capture dài hạn.
