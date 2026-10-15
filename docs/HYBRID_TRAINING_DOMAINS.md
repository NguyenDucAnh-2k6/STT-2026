# Hybrid training: không có Normal lake khác với lake rỗng

Kiểm tra snapshot ngày 12/10/2026: lake có 117.411 dòng, 103.069 Unknown và **14.342 attack đủ điều kiện**: DDoS_TCP 3.585; DDoS_HTTP 2.718; XSS 2.711; SQL_injection 2.608; DDoS_UDP 1.792; Uploading 928. **Normal: 0** ở cả dữ liệu gốc và eligible subset. Counts sẽ đổi nếu tiếp tục collect hoặc xóa batch.

Log cũ “Kho du lieu chua co ban ghi thuc te” nằm trong nhánh lấy Normal cho anomaly detector, không phải nhánh classifier. Nó gây hiểu nhầm: Isolation Forest fallback Normal TRAIN benchmark, còn Random Forest vẫn concat attack eligible từ lake. Các startup messages oneDNN là log dependency, không phải lỗi đọc nhãn/concat.

Đã đổi log thành không có Normal hợp lệ trong 30 ngày, nêu rõ attack vẫn được nạp; thêm path, eligibility và counts theo lớp. Hybrid chỉ load lake một lần và project các cột training; không đọc các cột NLP/raw content không dùng để giảm memory/I/O. API load đầy đủ vẫn giữ metadata khi caller không yêu cầu projection.

Warning pandas do schema cũ/mới có cột metadata all-null: loader bỏ block all-null trước concat rồi khôi phục union columns, giữ row identities. Regression kiểm tra schema khác nhau không mất dòng/cột, training projected không mang raw content, hybrid không có Normal vẫn concat attack và load một lần. Không retrain/ghi đè models dự án trong validation.

## Wi-Fi và loopback

Không gộp mù chỉ vì cùng 56 features. Wi-Fi traffic của host thường có TLS/QUIC, link/interface vật lý và các dịch vụ khác; loopback lab có HTTP plaintext/control traffic, RTT/baseline khác. Model học môi trường/tool/port có thể bị nhầm là học attack. Cần provenance và evaluation theo domain.

Hướng hiện tại:

- **Anomaly detector:** Normal baseline/threshold riêng cho Wi-Fi và loopback. Normal lab có thể thu bằng nút Normal trong --twin-lab; traffic Wi-Fi chưa review không tự đổi từ Unknown sang Normal. Hiện snapshot thiếu Normal lake nên chưa có cơ sở cho baseline riêng từ lake.
- **Classifier:** giữ artifact benchmark-only làm đối chứng; model lab riêng dùng để kiểm tra generator; mixed classifier là thí nghiệm có kiểm soát, không mặc định tốt hơn. Chọn theo macro F1/per-class recall/false alarms trên held-out lab và held-out Wi-Fi riêng.
- Tách train/validation/test theo session/flow/device; giữ request template mới và môi trường mới cho test. CV random packet hiện tại có thể có packet cùng flow ở hai fold; không lấy CV đó làm chứng minh hiệu quả trên môi trường mới.
- Lake hiện được thêm vào train; holdout benchmark không đo riêng lab/Wi-Fi. Độ chính xác benchmark không chứng minh đã cải thiện domain mới sau concat.

Có thể giữ bundle ở các thư mục riêng bằng --output-dir và chọn runtime bằng --models-dir. **Hai flags không lọc domain**. Implementation hiện chưa có --data-domain hay tự route model theo interface; hybrid đọc toàn bộ eligible lake. Muốn train hai domain đúng phải chuẩn bị subset/split riêng và thêm config lọc domain tường minh, không chỉ đổi tên output folder.

Trước khi tiếp tục hybrid, thu đủ Normal đại diện và gắn nhãn theo provenance. Không dùng “không bấm attack” làm bằng chứng toàn traffic là Normal, không dùng model prediction làm ground truth. Nhãn attack tự động trong lake là workload attribution, vẫn cần đánh giá tính đúng của generator và độ đa dạng dữ liệu.

## Review Normal theo xác nhận người vận hành, 12/10/2026

Snapshot phía trên là trước review, không còn là counts hiện tại. Người vận hành
xác nhận không có attack ở nơi thu thực địa và yêu cầu gán Normal: 304.685 Unknown
packet ngoài dấu hiệu lab đã chuyển thành Normal, label_source=manual_review,
label_method=operator_assertion. 4.475 Unknown có experiment/requested attack,
provenance Twin hoặc endpoint cổng lab được giữ lại để không trộn vào baseline.
Known attack labels không thay đổi. Payload/query/body và canonical features giữ nguyên.

Backup và manifest review nằm ở
`data_lake/label_backups/de40eb6fb3d6419b8b4d5150c6057935/`; metadata trong mỗi dòng
giữ previous_ground_truth_scenario, previous_label_source và label_annotation_id.
Thao tác này không chứng minh Normal bằng sensor và không tự gán nhãn dữ liệu mới.
Quality gate vẫn loại dòng malformed/missing/schema không tương thích dù nhãn Normal.
Artifacts đang chạy không thay đổi sau review: cần train và khởi động lại riêng.
