# Normal review và kiểm tra inference, 12/10/2026

Theo xác nhận của người vận hành rằng nơi thu thực địa không có attack, đã chuyển
304.685 packet Unknown ngoài dấu hiệu lab sang Normal. Giữ nguyên known attack
labels và 4.475 Unknown có dấu hiệu lab. Không sửa canonical measurements,
payload/query/body. Đây là nhãn do người vận hành xác nhận, không phải kết luận model.

Mỗi dòng sửa giữ previous_ground_truth_scenario/previous_label_source, ghi
label_source=manual_review, label_method=operator_assertion,
label_reason=operator_report_no_attacks và annotation ID. Backup Parquet nguyên bản
và manifest nằm ở `data_lake/label_backups/de40eb6fb3d6419b8b4d5150c6057935/`.
Catalog counts/size đã cập nhật. Future Unknown không tự đổi thành Normal.

Đọc lại snapshot qua quality gate training:

| Nhãn đủ điều kiện | Số dòng |
| --- | ---: |
| Normal | 310.091 |
| DDoS_TCP | 6.121 |
| DDoS_UDP | 3.392 |
| DDoS_HTTP | 2.718 |
| XSS | 2.711 |
| SQL_injection | 2.608 |
| Uploading | 928 |

Tổng accepted 328.569; rejected 4.475; duplicate identity và malformed numeric đều
0 trong snapshot này. Relabel không tự retrain hay thay artifacts đang nạp.

## Model có suy luận Twin không?

Có trên đường live host TShark → MQTT edge/telemetry/traffic → inference service
→ dashboard. Importer Twin PCAP → Parquet chỉ lưu dữ liệu, không suy luận mọi dòng.
Đã giới hạn host live capture của --twin-lab vào loopback TCP/UDP LAB_HTTP_PORT
(mặc định 8088), cùng phạm vi importer, giảm traffic nền và áp lực queue. Wi-Fi và
--lab-capture ngoài Twin giữ phạm vi capture riêng. Queue vẫn có thể drop nếu quá tải.

UI trước chỉ hiện top 5 lớp; giờ thêm xác suất lớp Twin đang chọn từ full probability
map nếu có, kể cả 0. Nhãn collect không điều chỉnh xác suất của model.

Kiểm tra offline **một packet DDoS_UDP đủ điều kiện** với bundle hiện có
`ml_engine/models/random_forest_isolation_forest`:

- Inference status: ok; classifier DDoS_UDP 54,32%, Uploading 45,64%, Normal 0,04%.
- Isolation Forest score 0,3989 < threshold 0,55; final threat Normal.

Anomaly gate đang chặn cảnh báo cuối dù classifier ưu tiên DDoS_UDP. Đây không phải
đánh giá cả phiên hay bằng chứng workload đạt thực tế. Không hạ threshold tùy tiện:
cần đánh giá false alarms và recall trên sessions Normal/attack giữ riêng để hiệu chỉnh.
Accuracy training không đảm bảo phát hiện lab mới; 56 canonical features không chứa
packet rate, UDP chỉ có port/stream/time delta trong nhóm UDP.

Chọn đúng bundle sau khi train và restart:

```powershell
python run_system.py --probe host --twin-lab --broker-host 127.0.0.1 --broker-port 1883 --classifier random_forest --anomaly-model isolation_forest
```

Regression sửa nhãn/backup/catalog, filter capture lab, và hiển thị xác suất đã pass;
kiểm tra inference phía trên là offline. Chưa chạy lại cả phiên Twin/UI trực tiếp.
Kết quả máy đọc ở `scratch/operator_normal_inference_audit.json`.
