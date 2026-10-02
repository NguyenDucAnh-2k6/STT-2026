# Rà soát repo AERO — 02/10/2026

Repo có những lỗi ảnh hưởng trực tiếp đến tính đúng của dữ liệu, suy luận và kết quả nghiên cứu. Cần sửa hợp đồng dữ liệu và quy trình đánh giá trước khi tối ưu thêm mô hình hoặc dùng các chỉ số hiện có để chứng minh chất lượng sản phẩm.

## Phạm vi và cách kiểm tra

- Đối chiếu mã nguồn launcher, broker, probe Host/ESP32, preprocessing, training/HPO, exporter, inference, lakehouse và dashboard với README/tài liệu.
- Đọc toàn bộ 32 file Parquet hiện có, 9 metadata mô hình, header sinh sẵn và CSV synthetic; trích xuất nội dung hai Word và các sheet Excel.
- Parse cú pháp 70 file Python: không gặp lỗi cú pháp. Kiểm tra C++ syntax của 8 header mô hình hiện có: đều qua. Hai kiểm tra này không chứng minh logic đúng hay firmware chạy đúng trên ESP32.
- Tái hiện độc lập lỗi categorical encoding, dữ liệu 8D, synthetic generator, ghép prediction, deadlock, lỗi suy luận bị báo Normal, chênh lệch Isolation Forest Python/C và một số lỗi export. Môi trường kiểm tra riêng ở `/tmp/stt-repo-audit-env`, không sửa môi trường dự án.
- Không chạy bộ phát sinh lưu lượng tấn công; không thay đổi model, firmware, Word, Excel hay dữ liệu gốc.
- Checkout thiếu benchmark Edge-IIoTset và toàn bộ trọng số Joblib; không thể tái tính chất lượng của 9 mô hình đã lưu metadata, chạy E2E với model thật hoặc kiểm chứng hiệu năng phần cứng. Catalog SQLite cũng không có trong checkout để đối chiếu với Parquet.
- Chưa thẩm định toàn văn các PDF Literature, nội dung ảnh/biểu đồ hoặc xác minh nguồn thống kê thị trường, giá đối thủ và các trích dẫn nghiên cứu bên ngoài. Đây là phần kiểm tra bổ sung, không phải bằng chứng đã xác nhận.

Mức ưu tiên: **P0** = kết quả có thể sai hoặc tạo minh chứng không hợp lệ; **P1** = lỗi lớn cần sửa trước demo/thu thập lại; **P2** = độ tin cậy vận hành, tài liệu và khả năng tái lập.

## 1. Dữ liệu đang có

| Hạng mục | Kết quả |
|---|---:|
| File Parquet đọc được / lỗi đọc | 32 / 0 |
| Tổng bản ghi | 5.810 |
| Normal | 5.445 |
| DDoS_UDP | 182 |
| DDoS_TCP | 79 |
| Uploading | 56 |
| Vulnerability_scanner | 30 |
| Port_Scanning | 18 |
| Timestamp dạng uptime, không phải Unix epoch | 2.833 |
| Bản ghi dư nếu lấy khóa session_id + timestamp | 19 |
| Nhãn is_attack mâu thuẫn ground_truth_scenario | 0 |
| Normal nhưng edge_flag = 1 | 1.972 |
| Normal nhưng predicted_threat khác Normal | 3.578 |
| Sai lệch byte_rate so với packet_rate × avg_packet_size > 10%, sai lệch tuyệt đối > 1 | 23 |

Tất cả file có cùng schema 24 cột, không có null trong các cột đang lưu; các chỉ số tốc độ/kích thước/số cổng không âm. Đây là các điểm nhất quán đã kiểm tra được.

Hai số 1.972/3.578 **không được dùng ngay làm false-positive rate**: ground truth hiện chỉ dựa vào kịch bản generator, prediction bị ghép thiếu khóa, model/firmware qua nhiều phiên có thể khác nhau. Chúng đủ cho thấy dữ liệu cần được điều tra, chưa đủ xác định lỗi của model nào.

19 bản ghi trùng khóa nằm trong phiên `sess_20260915_174444_1388`: nhiều dòng dùng một timestamp, trong khi packet_rate tăng 20, 21, 22… Đây có dấu hiệu là dữ liệu thử; không nên tự động coi chúng là bản sao cùng gói hoặc bằng chứng lỗi dual transport. Cần gắn nguồn dữ liệu thử và loại khỏi benchmark thực địa.

Thống kê máy đọc được: [REPO_AUDIT_DATA_2026-10-02.json](REPO_AUDIT_DATA_2026-10-02.json).

## 2. Các lỗi dữ liệu và mô hình ưu tiên cao

### F01 — P0: Thiếu benchmark nhưng training vẫn chạy trên dữ liệu ngẫu nhiên

Vị trí: `ml_engine/preprocessing/edge_iiotset_preprocessor.py:243`, `:267`; `ml_engine/datasets/get_kaggle_data.py`.

Checkout chỉ có `synthetic_traffic_dataset.csv`, không có ML/DNN-EdgeIIoT CSV. Khi không tìm thấy benchmark, loader tạo 56 feature ngẫu nhiên và nhãn tấn công ngẫu nhiên rồi tiếp tục train/export. Đặc trưng không được sinh theo nhãn nên kết quả không đại diện cho Edge-IIoTset. Đường dẫn `--dataset` gõ sai cũng bị thay bằng đường dẫn mặc định thay vì báo lỗi. Script Kaggle chỉ tải về cache và in path, không đưa file vào vị trí loader chờ.

**Cần làm:** thiếu/sai dataset phải dừng; chế độ synthetic phải được bật rõ ràng và ghi provenance riêng. Metadata cần lưu path/hash dataset, số mẫu từng lớp, phiên bản preprocessing và seed.

### F02 — P0: Scaler, vocabulary và baseline học từ test trước khi chia dữ liệu

Vị trí: `edge_iiotset_preprocessor.py:293`; `ml_engine/train.py:222`, `:235`; `ml_engine/tuning/optuna_tuner.py:234`.

`load_full_dataset()` fit encoder, baseline Normal và scaler trên toàn bộ dữ liệu. `train.py` sau đó mới chia holdout và chạy CV trên ma trận đã xử lý. Cả test và validation fold đã ảnh hưởng vào preprocessing; baseline Normal còn được học từ nhãn của các mẫu test. Vì vậy không thể mô tả holdout là hoàn toàn chưa thấy.

**Cần làm:** chia dữ liệu thô trước; fit preprocessing chỉ trên train và riêng từng CV fold. Tách theo session/flow/nguồn khi phù hợp; không chỉ stratify từng dòng mạng có quan hệ gần nhau.

### F03 — P0: Categorical feature bị mã hóa hai lần ở runtime và hybrid training

Vị trí: `ml_engine/preprocessing/modules/http_application.py:85`; `modules/iot_protocols.py:97`; `edge_iiotset_preprocessor.py:142`; `inference_service.py:213`; `train.py:119`.

`extract_from_telemetry()` đổi chuỗi GET/topic thành index số. `extract_features()` trả các index trong DataFrame. `transform()` lại coi số đó là category thô và tìm trong vocabulary chuỗi, thường rơi về category `0`.

**Đã tái hiện:** vocabulary GET=1, topic beta=2; extraction trả `[1, 2]`, nhưng sau transform cả hai trở thành mã cho category 0. Vector chuẩn hóa khi xử lý chuỗi thô là `[0, 1.2247448]`; luồng runtime thành `[-1.2247448, -1.2247448]`.

**Cần làm:** extraction trả giá trị thô; encoding/scaling chỉ thực hiện một lần. Kiểm tra cùng một bản ghi phải cho cùng vector ở training, runtime và replay lake.

### F04 — P0: Training, Host và ESP32 không đo cùng loại đặc trưng

Vị trí: `firmware/host_probe/host_sniffer.py` (`compute_features`, `sample_features`); `firmware/esp32_probe/edge_inference.cpp:30`; `modules/tcp_transport.py:99`; `modules/udp_transport.py:64`; `modules/http_application.py:103`.

Schema model gồm trường phân tích giao thức theo gói; probe chủ yếu xuất thống kê cửa sổ. Các phép ánh xạ đổi nghĩa/đơn vị: `udp.stream` được gán packet_rate; `tcp.len` dùng kích thước cả gói/khung hoặc trung bình; `http.content_length` có thể dùng byte_rate; cổng TCP thiếu được gán 80/49152. Các trường này không tương đương chỉ vì đều là số.

ESP32 chỉ gán 8 vị trí trong vector 56 chiều, phần còn lại bằng 0; Host dùng baseline và heuristic khác. Các index cố định hiện khớp schema canonical, nhưng không có kiểm tra schema khi model thay thứ tự. Có SYN bất kỳ trên ESP32 cũng đặt flag SYN, trong khi Host dùng tỷ lệ > 0,5.

**Cần làm:** định nghĩa mỗi feature gồm nghĩa, đơn vị, độ dài cửa sổ và cách đo. Chọn pipeline window/flow thực sự đo được ở cả hai probe, hoặc tạo hai model riêng. Đo coverage feature; không coi 56 giá trị truyền vào là 56 đặc trưng đo được.

### F05 — P0: Nhánh psutil sử dụng tên kịch bản để sửa feature đầu vào

Vị trí: `firmware/host_probe/host_sniffer.py`, khối `if attack_context ... ATTACKING and pkt_rate > 30.0`.

Tên DDoS/Port/Uploading quyết định syn_ratio, ack_ratio, udp_ratio, số cổng, protocol và kích thước. Ví dụ Uploading đặt ack_ratio=0,96 và nâng avg_size lên ít nhất 1420. Đây là đầu vào được tạo từ nhãn mà hệ thống đang cố dự đoán. Không thể dùng demo đó để chứng minh phát hiện độc lập từ lưu lượng thật. Các tcp_count/udp_count của psutil là số socket, cũng không cùng nghĩa packet count của raw sniffer.

**Cần làm:** bỏ tác động của attack_context lên feature; chỉ lưu nó ở metadata ground truth. Tách rõ raw packet capture và thống kê socket. Thu lại baseline/tấn công sau khi sửa.

### F06 — P0: Lakehouse làm mất dữ liệu cần cho tái huấn luyện

Vị trí: `data_lake/lakehouse.py:151`; `collector.py:113`; `train.py:119`.

Lake không lưu device_id, IP/port/protocol, cửa sổ mẫu, các trường `tcp.*`, phiên bản model hay raw payload. Collector không truyền `extracted_features`; toàn bộ Parquet hiện có không có cột `feat_*`. Vì vậy hybrid training tái dựng feature từ 8 thống kê, không thể replay đúng đầu vào đã suy luận. Ngay cả khi `feat_*` được lưu sau này, helper training hiện không bóc prefix để sử dụng.

**Đã kiểm tra:** replay 5.810 dòng qua extractor với baseline cố định chỉ có 10/56 feature biến thiên; 46 còn lại hằng số. Con số này đo sự thiếu thông tin trong dữ liệu hiện có, không đo chất lượng model.

**Cần làm:** lưu raw telemetry + raw/processed features được phân biệt rõ, device/sample ID, window_start/end, schema/model version và nguồn nhãn. Migration không thể khôi phục các trường đã bị mất từ Parquet cũ.

### F07 — P0: Prediction bị ghép vào telemetry khác

Vị trí: `data_lake/collector.py:97`, `:116`.

Collector có một `latest_prediction` toàn cục. Khi telemetry mới đến, nó lấy prediction gần nhất, không kiểm tra device hay sample. Thường prediction thuộc mẫu trước; nhiều probe còn có thể bị ghép chéo thiết bị. Mẫu chưa có prediction được ghi confidence=1 và dự đoán mặc định từ edge.

**Đã tái hiện:** prediction của A/timestamp 1 được gắn vào telemetry B/timestamp 2.

**Cần làm:** correlation key theo device_id + boot_id + sequence/sample_id; buffer/join đúng khóa. Chưa có prediction phải lưu null/pending; không điền confidence=1.

### F08 — P0: Nhãn Normal không phải ground truth độc lập

Vị trí: `collector.py:46`, `:93`, `:100`; `lakehouse.py:389`.

Không có generator đang chạy thì toàn bộ traffic được gắn Normal, kể cả tấn công ngoài generator. Khi generator hoạt động, nhãn được gán toàn cục cho mọi probe/cửa sổ, không kiểm tra target, channel, gói thực sự quan sát hay phần cửa sổ trước/sau chuyển kịch bản. Dataset labeled còn đưa những dòng Normal mặc định này vào classifier như nhãn hợp lệ.

**Cần làm:** tách `scenario_active` khỏi `verified_label`; hỗ trợ Unknown và cửa sổ chuyển tiếp. Dùng môi trường lab/PCAP có nhãn, target và khoảng thời gian đối chiếu. Baseline thực địa cần được xác nhận sạch trước khi học.

### F09 — P0: Đánh giá lỗi được thay bằng chỉ số tốt cố định

Vị trí: `ml_engine/train.py:510`, `:595`.

Nếu score/AUC/F1 phát sinh exception, code gán ROC-AUC=0,95 và F1=0,92. Khi F1 bằng 0 hoặc chưa đo, metadata ghi 0,95. Điều này có thể tạo kết quả đẹp ngay cả khi đánh giá hỏng hoặc model có F1=0.

**Cần làm:** exception phải ghi lỗi và metric null; giữ giá trị 0 thực. Không công bố kết quả hiện có nếu chưa biết nhánh nào sinh metric. Đánh giá cả pipeline detector → classifier, không chỉ classifier độc lập.

### F10 — P0: Deep Learning trên ESP32 hiện là hàm stub

Vị trí: `ml_engine/exporter/tinyml_exporter.py:104`, `:154`; `models/pytorch_deep_deep_autoencoder/tinyml_model.h:150`, `:166`; `firmware/esp32_probe/edge_inference.cpp:43`.

Header DNN trả Normal và confidence=1; header Autoencoder trả score=0 và false. Firmware gọi các hàm này trực tiếp, không có TFLite interpreter/Invoke. Có mảng FlatBuffer không đồng nghĩa mô hình đang chạy trên chip.

**Cần làm:** triển khai interpreter, arena, preprocessing, Invoke và lỗi runtime; hoặc đánh dấu DL là Host-only. Benchmark từng mẫu Python/TFLite/ESP32 trước khi ghi trạng thái hoàn thành.

### F11 — P0: Lỗi suy luận được thông báo là mạng bình thường

Vị trí: `ml_engine/inference_service.py:305`.

Mọi exception extraction/prediction trả threat Normal, is_anomaly=false, score=0, confidence=0,5. Dashboard sẽ hiển thị bình thường, trong khi engine có thể không hoạt động.

**Đã tái hiện:** preprocessor chưa fit vẫn nhận kết quả Normal/false/0.

**Cần làm:** trạng thái `INFERENCE_ERROR`/Unknown, kèm lỗi, health và không dùng kết quả lỗi để học baseline. Launcher cần kiểm tra tiến trình thực sự sống và sẵn sàng thay vì chỉ sleep rồi báo đã hoạt động.

## 3. Firmware, exporter và vận hành

### F12 — P1: Edge/Host có score và threshold khác nhau

Vị trí: `tree_exporter.py:183`, `:208`; `tinyml_exporter.py:235`; `inference_service.py:284`; `esp32_probe/tinyml_model.h:18`.

Exporter chỉ lấy 10 cây IF/8 cây RF, top 64 support vectors OCSVM và 32 prototype LOF, trong khi Host dùng model đầy đủ. RF C chỉ cộng confidence vào lớp thắng mỗi cây, khác trung bình phân phối xác suất. IF C bắt đầu depth=1 nên path dài thêm 1; Host lại áp sigmoid theo phân vị Normal, C dùng raw IF score. Header mặc định threshold=0,5; Host mặc định 0,55.

**Đã tái hiện:** IF 10 cây, cùng model/cùng x=[0,0], raw anomaly Python=0,40043938 nhưng C=0,36687660, ngay cả khi chưa cắt bớt cây.

**Cần làm:** sửa depth, thống nhất score calibration và threshold; xem mô hình cắt giảm là mô hình riêng và đánh giá riêng, không gọi export 1:1. Refit detector phải tính lại calibration; code hiện giữ score_min/max của detector trước refit.

### F13 — P1: Tự ghép model từ các lần train khác nhau có thể dùng sai scaler/nhãn

Vị trí: `run_system.py:259`, `:279`, `:290`; `:336`.

Launcher lấy classifier và detector từ hai folder, nhưng preprocessor có thể từ folder đầu tiên bất kỳ. Model học trên các scaler/vocabulary khác nhau không thể tùy ý ghép. Export tổ hợp không truyền feature/label metadata; thứ tự LABEL_NAMES trong schema khác thứ tự LabelEncoder của metadata hiện có. Calibration detector cũng không được copy. Header firmware còn fallback sang header bất kỳ nếu không có đúng header.

**Cần làm:** triển khai nguyên bundle có cùng pipeline ID/hash; ghép chỉ khi chứng minh preprocessing/schema/label tương thích. Model/header không hỗ trợ phải báo rõ; không tự đổi model yêu cầu. Đồng bộ file header cũng không thay firmware đang chạy nếu chưa flash.

### F14 — P1: Time-series chưa được triển khai xuyên suốt

Vị trí: `train.py:306`, `:337`, `:536`; `preprocessing/timeseries.py`; `inference_service.py:213`; `classifiers/deep_learning.py` (`predict_proba`).

Training biến vector D thành 6D cho model bảng nhưng runtime vẫn đưa D. LSTM runtime lặp cùng một mẫu W lần thay vì dùng lịch sử thực. Detector luôn train feature 6D nhưng một số đường đánh giá đưa D hoặc tensor 3D. Refit lại dùng X/y gốc, làm mất biến đổi time-series và mẫu lake có nhãn. Sampling benchmark có thể xáo trộn thứ tự; frame.time bị bỏ trước tạo cửa sổ; dữ liệu Normal lọc rời nhau rồi ghép, dữ liệu các phiên/nguồn cũng chưa tách. TimeSeriesSplit không có gap để ngăn cửa sổ chồng lấn dùng chung quan sát giữa train/validation.

**Cần làm:** pipeline thời gian riêng với timestamp đã chuẩn hóa, group theo device/flow/session, giữ thứ tự, buffer runtime và gap theo window. Chặn mode chưa hỗ trợ thay vì xuất artifact có tên time-series nhưng không dùng đúng.

### F15 — P1: Synthetic generator và hỗ trợ 8D bị hỏng

Vị trí: `preprocessing/dataset_generator.py:89`, `:141`; `edge_iiotset_preprocessor.py:103`.

Generator dùng nhãn SYN_Flood/Port_Scan… nhưng LABEL_MAP hiện là bộ 15 lớp; đồng thời dựng mỗi dòng 8 feature nhưng columns lấy schema 56 feature. Đã tái hiện `KeyError: SYN_Flood`.

CSV synthetic hiện có 10.000 dòng × 9 cột. Loader nhận 8 feature đó nhưng các module chỉ xử lý tên Edge-IIoT rồi điền các cột 8D bằng baseline 0. **Đã tái hiện:** lấy 100 dòng phân tầng, X có shape (100,8) và toàn bộ giá trị bằng 0; label trở thành chuỗi 0–4, không có Normal.

**Cần làm:** tách schema, label map và preprocessor 8D/56D; hoặc bỏ hẳn API tương thích cũ. Bắt schema lỗi và feature coverage 0 trước training.

### F16 — P1: Một số lựa chọn classifier train xong vẫn lỗi export

Vị trí: `train.py:614`; `tinyml_exporter.py:93`, `:126`; `tree_exporter.py:120`; `ml_engine/export_tinyml.py:70`.

Train luôn export C dù `can_export_tinyml=false`; XGBoost/CatBoost không có exporter tương ứng. GradientBoosting bị đưa vào forest exporter, vừa sai kiểu thuật toán vừa lỗi boolean của ndarray. Helper export model đã lưu bỏ qua scaler, detector và label encoder đúng; load preprocessor trả bundle dict nhưng truyền như object. Header fallback anomaly gọi classifier trước khi classifier được khai báo.

**Đã tái hiện:** GradientBoosting export lỗi `ValueError: truth value of an array ... ambiguous`; export Decision Tree không detector tạo header C++ không compile vì `tinyml_predict_classifier` chưa khai báo. 8 header có sẵn compile được không phủ các đường lỗi này.

**Cần làm:** kiểm tra capability, tách Host artifact export và Edge export, dùng loader preprocessor chính thức và metadata của bundle; compile và đối chiếu số trước báo export thành công.

### F17 — P1: Timestamp, provenance probe và sample ID thiếu nhất quán

Vị trí: `mqtt_handler.cpp:169`; `lakehouse.py:153`; `run_system.py:605`.

ESP32 gửi millis(), Host gửi epoch milliseconds; lake lưu chung cột timestamp không phân biệt, dẫn tới 2.833 dòng không có thời gian UTC. Launcher không truyền probe_type/sniffer_mode cho collector nên mặc định mọi phiên là ESP32/all-networks, kể cả Host. Firmware hiện mặc định `SNIFFER_MODE_ALL_NETWORKS=false`; Parquet toàn bộ lại ghi all-networks. Không thể xác nhận nguồn lịch sử của từng dòng vì device_id không được lưu.

**Cần làm:** tách device_uptime và received_at/event_time; thêm boot_id/sequence, capture_engine, probe_type và sniffer_mode thực. Không sửa timestamp/provenance lịch sử bằng suy đoán.

### F18 — P1: Ngưỡng và trạng thái UI có thể khác engine/ESP32

Vị trí: `dashboard/backend/state.py:24`; `routers/api.py:153`; `run_system.py:711`; `launcher/workers.py:83`; `mqtt_handler.cpp:41`, `:123`.

Dashboard hardcode threshold 0,55, launcher chỉ truyền threshold cho inference. Đổi ngưỡng không retain/ACK nên service reconnect có thể bỏ lỡ. Chế độ all-networks không chạy MQTT loop; USB bridge chỉ truyền ESP32→MQTT, không có chiều config→ESP32. Vì vậy kéo slider không đổi threshold chip trong chế độ đó. UI/Backend còn tự quyết định lại anomaly thay vì lấy kết quả engine và version threshold.

Dashboard ban đầu đọc metadata folder mới nhất, launcher không truyền MODELS_DIR cho dashboard. Khi chưa có edge telemetry, inference có thể gán tên model/chỉ số Edge theo Host, gây hiểu nhầm Host probe đang có suy luận trên chip.

**Cần làm:** nguồn cấu hình duy nhất, config version/ACK, truyền đúng MODELS_DIR; Edge không đo được phải hiển thị unavailable. Các API publish cần kiểm tra kết quả MQTT, không trả success chỉ vì không có exception.

### F19 — P1: MQTT+Serial không có khử trùng; broker thiếu retained state

Vị trí: `mqtt_handler.cpp:222`; `launcher/workers.py:127`; `broker/embedded_broker.py:150`, `:172`.

Firmware AP-mode phát cả Serial và MQTT; bridge forward Serial bất kể MQTT đang hoạt động. Cùng mẫu có thể bị suy luận/lưu hai lần. Đây là nguy cơ xác định từ code, không phải nguyên nhân đã chứng minh của 19 dòng trùng lịch sử. Broker không lưu/khôi phục retained message dù generator publish status retain=true. Collector/dashboard khởi động muộn có thể không biết trạng thái tấn công. Broker ACK publisher QoS1 nhưng gửi subscriber QoS0.

**Cần làm:** sample key + dedup, chọn transport đang hoạt động hoặc nhận cả hai và khử trùng. Dùng broker có hành vi cần thiết hoặc triển khai retained/session/QoS rõ ràng; test reconnect và subscriber khởi động muộn.

### F20 — P1: Sniffer không xử lý điều kiện để đọc payload Wi-Fi mã hóa

Vị trí: `firmware/esp32_probe/sniffer.cpp:79`.

Parser luôn đọc LLC/SNAP ngay sau header 802.11 mà không kiểm tra Protected bit, xử lý crypto header hay giải mã. Vì vậy không có cơ sở từ mã hiện tại để nói luôn lấy được TCP/SYN/port của mọi AP; total_packets vẫn tăng khi protocol không đọc được. Management frame cũng vào tổng, làm tỷ lệ UDP/ICMP có mẫu số khác capture IP của Host. unique_dst_ports dùng bitmap hash 256 vị trí nên có collision và không thể biểu diễn số cổng duy nhất chính xác vượt 256.

**Cần làm:** đo tỷ lệ frame giải mã/phân tích được trong từng môi trường thực; báo missing/coverage, tách management/data/IP count và gọi số cổng là ước lượng nếu tiếp tục dùng hash. Muốn chứng minh packet-level cần đường capture có payload đọc được.

### F21 — P1: Kịch bản phát traffic không tương đương nhãn benchmark

Vị trí: `firmware/simulator/attack_traffic_generator.py` (`burst_tcp_syn_flood`, `burst_vulnerability_scan`, `burst_uploading`, `attack_worker_loop`).

Uploading dùng UDP gửi payload tới port 443, không phải TLS/TCP exfiltration. Vulnerability scanner chủ yếu connect cổng, không gửi HTTP vulnerability payload. TCP flood dùng connect_ex và còn trộn UDP broadcast. Không thể coi tên kịch bản là chứng minh đã sinh đúng lớp Edge-IIoTset. Comment tránh unicast ESP32 mâu thuẫn với code vẫn truyền esp32_ip vào hàm burst và gửi trực tiếp tới nó. Thread auto-cycle sleep dài nên lệnh Stop trong lúc sleep không ngăn thread kích hoạt vòng tấn công tiếp theo.

**Cần làm:** định nghĩa traffic generator theo hành vi thực, ghi số send thành công và PCAP đối chiếu; tách nhãn lab khỏi benchmark nếu khác nghĩa. Stop phải ngắt cycle qua event/cancel và kiểm tra lại trước mỗi lần set_scenario.

## 4. Lakehouse, dashboard và kiểm thử

### F22 — P1: Deadlock khi ghi trước start_session; flush chưa bảo đảm bền vững

Vị trí: `lakehouse.py:144`, `:146`, `:205`, `:284`; `remote_storage.py` (`sync_remote_to_lake`).

record_telemetry giữ threading.Lock rồi gọi start_session lấy cùng lock. **Đã tái hiện:** thread bị treo khi ghi trên manager mới. Flush đọc/nối/ghi lại toàn bộ file mỗi lần, giữ lock trong I/O và viết trực tiếp file đích. Flush lỗi thì close_session vẫn cập nhật số liệu, báo lưu an toàn và bỏ session; lần start kế tiếp có thể mất buffer. Remote sync có thể đụng file đang ghi; pull còn thay toàn bộ catalog thay vì merge/rebuild theo Parquet và bỏ qua file cùng size dù nội dung khác. API summary chỉ dựa catalog: clone repo có Parquet nhưng catalog mới sẽ báo kho rỗng.

**Cần làm:** sửa khóa, ghi file tạm+atomic replace hoặc chunk immutable; chỉ đóng sau flush thành công. Rebuild catalog từ file; merge catalog theo session; sync file hoàn tất với checksum. `days=30` của baseline loader hiện không được dùng để lọc ngày.

### F23 — P1/P2: Dashboard đang hiển thị dữ liệu mặc định như quan sát thật

Vị trí: `dashboard/backend/mqtt_bridge.py:108`, `:112`; `components/charts.js:235`; `components/header.js:117`; `backend/state.py:106`.

- Backend đặt IP `192.168.137.149`, port 5683 và protocol CoAP khi probe không cung cấp chúng. Frontend cũng có fallback IP/port. Packet inspector không nên trình bày các giá trị này như gói bắt thật; một dòng hiện là cửa sổ thống kê, không phải từng packet.
- `udp_ratio || 0.3`, `icmp_ratio || 0.05` đổi 0 hợp lệ thành 30% UDP/5% ICMP; chart khởi tạo [65,30,5] trước dữ liệu.
- Tổng packet cộng packet_rate mỗi message, thiếu thời lượng cửa sổ; với ESP32 2s sẽ sai đơn vị, thêm trùng transport càng lệch.
- Node count ép tối thiểu 1, không lọc offline/timeout; Host không publish nodes/status. WebSocket connected không chứng minh MQTT/inference đang khỏe. Mạng Wi-Fi cũ không bị hết hạn.
- `setInitialState()` không giữ system_models dù component lắng nghe nó; history cũng chưa được render lại đầy đủ sau reconnect.

**Cần làm:** unknown/null hiển thị N/A; dùng ?? cho default số, tích lũy packet_count; heartbeat/expiry cho node và health từng thành phần; tách UI cửa sổ/packet.

### F24 — P1: HTML injection từ dữ liệu mạng và API điều khiển không xác thực

Vị trí: `components/wifi_inspector.js:81`, `:97`; `components/packet_inspector.js:106`; `risk_assessment.js`; `backend/routers/api.py`; `backend/app.py` (`host=0.0.0.0`).

SSID/info/device/model/label được ghép vào innerHTML không escape. SSID có thể chứa markup/quote ngay cả khi parser firmware giới hạn ASCII; Host probe cũng đưa SSID vào. Các API phát traffic, đổi threshold và push remote không có auth, đang phục vụ trên mọi interface. Đây là đường dữ liệu không tin cậy và quyền điều khiển thực trong code, cần giải quyết trước mở dashboard cho mạng dùng chung.

**Cần làm:** textContent/DOM API cho dữ liệu; escape đúng context nếu phải dùng HTML. Xác thực và phân quyền endpoint điều khiển, cấu hình bind interface, giới hạn scenario/target hợp lệ. Không có thử khai thác trong lần rà soát này.

### F25 — P2: Cài đặt và kiểm thử chưa bảo đảm tái lập

Vị trí: `requirements.txt`; `test_pipeline.py`; `.gitignore`; `launcher/network.py:199`; `launcher/flasher.py`.

requirements thiếu pandas/pyarrow dùng ngay trong launcher/lake; matplotlib/seaborn/Optuna/KaggleHub và dependencies model tùy chọn chưa được mô tả thành nhóm. Checkout không có Joblib và benchmark do ignore, nên có metadata/header không có nghĩa runtime sẵn sàng. Môi trường Python mặc định và .venv hiện cũng không có pandas.

test_pipeline gọi inference trực tiếp rồi tự publish prediction/alert; không test telemetry→daemon→backend→WebSocket→lake, không test feature parity hay label join. test_traffic_generator là công cụ bắn traffic thật, không phải test assertion. Flash hardcode FQBN ESP32 thường trong khi Excel chọn ESP32-S3; sync credentials thoát sớm khi credentials.h chưa có nên fresh clone chưa đạt Zero-config. Firmware hardcode MQTT port 1883 dù launcher cho đổi broker port.

**Cần làm:** dependencies runtime/train/EDA/DL được tách rõ và khóa phiên bản cần tái lập; manifest bundle/dataset; smoke test môi trường sạch; test offline các contract lỗi và integration cục bộ; chọn board/port đúng. Không chạy file tên test có chức năng phát traffic như unit test.

## 5. Metadata, tài liệu và kế hoạch kinh tế

### D01 — P1: Chỉ số classifier tốt không chứng minh pipeline phát hiện tốt

Metadata `decision_tree_isolation_forest`: classifier Macro F1=0,8929, nhưng anomaly ROC-AUC=0,4816 và F1=0,5718. Metadata XGBoost: classifier Macro F1=0,9173, anomaly AUC=0,5612 và F1=0,5542. Runtime chỉ công bố attack khi detector vượt threshold; classifier tốt không cứu được các mẫu detector bỏ sót.

Đây là **số ghi trong metadata**, chưa được tái tính độc lập; có các lỗi đánh giá ở F02/F09/F12. Cần đo end-to-end per-class precision/recall/F1, confusion matrix, false alerts/hour, tỷ lệ Unknown/Error và latency gồm cả cửa sổ 2s, transport và UI. Thời gian hàm suy luận <50µs không đồng nghĩa cảnh báo end-to-end <50µs.

### D02 — P2: README và tài liệu không cùng phiên bản code

- README ghi 61 input/63 features và 15 nhãn tấn công; schema/9 metadata là **56 input và 15 lớp tổng cộng, gồm Normal + 14 attack**. Excel kỹ thuật C9 ghi 61 trong khi I9 ghi 56.
- README nói không chia test, fit 100%; code mặc định test=20%, refit_full=false.
- Lệnh `--samples 30000`, `--export-tinyml-only` trong README không có trong parser hiện tại.
- MQTT API spec dùng nhãn/topics/payload cũ (`SYN_Flood`, `INJECT_MODE`, edge_anomaly_score…), không phản ánh đầy đủ control/status hiện tại. Firmware không gửi edge_anomaly_score/confidence dù có kết quả nội bộ.
- Tuyên bố triệt tiêu hoàn toàn false positives, truyền không gián đoạn 100%, bắt mọi mạng và DL on-chip chưa được các kiểm tra hiện có chứng minh; nhiều chỗ code trái với tuyên bố.
- Header firmware hiện trùng decision_tree_isolation_forest; mảng TFLite riêng còn tồn tại không chứng minh cùng bundle đang hoạt động. Phải ghi phiên bản firmware thực sự đã flash.

**Cần làm:** cập nhật từ contract và capability đã kiểm thử; phân biệt tính năng đang chạy, mục tiêu và giới hạn.

### D03 — P1: Dự toán số bản ghi cloud nhầm ngày thành tháng

Excel sheet **Kinh Tế & Thương Mại**, C52:C54 ghi ~5,1 / 22,4 / 60,4 triệu bản ghi/tháng cho 60/260/700 thiết bị. Với giả định 1 bản ghi/giây, các số đó gần số **một ngày**. Một tháng 30 ngày tương ứng **155,52 / 673,92 / 1.814,4 triệu**. Firmware hiện 2s/mẫu thì vẫn là **77,76 / 336,96 / 907,2 triệu/tháng** nếu vận hành liên tục.

Cần chốt sampling interval, giờ hoạt động, retention và kích thước record đo thực; tính lại storage/I/O/ingestion trước kết luận ngân sách cloud. Lake flush viết lại toàn bộ phiên còn là hạn chế khi mở rộng.

### D04 — P1: SOM và TCO có phép tính không khớp

- Excel D10: SAM 180 tỷ × 2%–3% = 3,8–5,4 tỷ. Đầu dưới đúng là **3,6 tỷ**, không phải 3,8.
- Excel D18 đề xuất TCO AERO cho 10 điểm/3 năm là 80–95 triệu. Nếu mỗi điểm dùng một box 5,25 triệu và gói Pro 550.000/tháng, không có chiết khấu và dùng đủ 36 tháng thì riêng box+thuê bao đã là **250,5 triệu**. Với Basic 300.000 cũng là **160,5 triệu**. Cần nêu giả định khác nếu muốn dùng 80–95 triệu.
- SOM là doanh thu năm hay doanh thu lũy kế cần được dùng thống nhất; D10 đang trộn cách diễn đạt.

Đây là kiểm tra số học nội bộ, không phải xác minh giá thị trường hay tư vấn tài chính.

### D05 — P1: Word có mâu thuẫn cash flow và định nghĩa hòa vốn

Trong `Sáng tạo trẻ.docx`, đoạn ghi chú đầu file nói worst case tăng trưởng chậm 30%, dòng tiền âm lũy kế chỉ ~550 triệu; phần dự phóng cơ sở nói đáy âm ~900 triệu–1 tỷ. Excel D26 lại dùng worst case đạt 60% kế hoạch, không phải 70%. Cần giải thích cắt giảm chi phí hoặc thống nhất kịch bản.

Word nói lũy kế dòng tiền chuyển dương khoảng đầu năm 3. Excel B67:C68 mô tả -600 triệu năm 1, -290 triệu năm 2 và lũy kế -890 triệu cuối năm 2; +1.500 triệu cả năm 3. Nếu chỉ minh họa dòng tiền năm 3 phân bổ đều, cần khoảng **7,12 tháng** năm 3 để bù -890 triệu, không phải tháng đầu. Dòng tiền hoạt động theo tháng dương và hoàn vốn lũy kế là hai mốc khác nhau; cần bảng theo tháng/quý để khẳng định thời điểm.

Word còn giữ các đoạn hướng dẫn sửa bài/pitch ở đầu nội dung và placeholder trong phần nguồn lực; cần biên tập lại bản nộp cuối.

### D06 — P1/P2: Kế hoạch thương mại đang mô tả phần cứng/tính năng khác prototype

Excel BOM C35 chọn ESP32-S3 + LAN8720A, C39 yêu cầu SPAN/VLAN; repo firmware hiện là Wi-Fi promiscuous, flasher chọn board ESP32 thường và không có đường capture Ethernet/SPAN tương ứng. Bảng F35 mô tả trích xuất 56 đặc trưng thực địa nhưng F04/F06 cho thấy prototype chưa đạt coverage đó. Gói SaaS có webhook/email/phân tích nguyên nhân/SLA cần phân biệt roadmap với tính năng đã triển khai.

Không nên lấy chi phí/capability của sản phẩm dự kiến để mô tả prototype đã hoàn thành. Cần chốt kiến trúc phần cứng thương mại, kiểm chứng tương thích BOM riêng và lập tiêu chí nghiệm thu từng giai đoạn.

### D07 — P2: Số khảo sát và tài liệu sinh tự động cần provenance

Excel D11 đề xuất 85%/92%/78% nhưng repo không có phiếu/bảng dữ liệu khảo sát gốc đi kèm để kiểm chứng. Các tỷ lệ phải là số thực từ mẫu khảo sát có denominator/ngày/phương pháp; nếu chỉ là mục tiêu hoặc ví dụ phải ghi rõ.

`scratch/generate_sheets.py` còn giá cũ TAM/SAM/SOM và gói SaaS, trạng thái hoàn thành/100% khác workbook hiện tại. `scratch/build_economic_sheet.py` có nhiều số cứng và đường dẫn Windows. Chạy lại script cũ có thể đưa mâu thuẫn trở lại. Chưa xác minh nguồn các số thống kê bên ngoài và paper trong tài liệu; cần một lượt thẩm định nguồn riêng trước nộp.

## 6. Thứ tự xử lý và tiêu chí hoàn thành

1. **Chặn minh chứng sai:** thiếu dataset phải dừng; bỏ metric cố định; inference lỗi phải báo Unknown/Error; DL stub phải bị đánh dấu chưa hỗ trợ. Loại dữ liệu thử khỏi benchmark.
2. **Chốt hợp đồng dữ liệu:** feature đo thật cùng nghĩa/đơn vị; bỏ feature phụ thuộc nhãn; sửa categorical encoding và 8D; tạo sample ID, clock và provenance; lưu raw telemetry đủ replay.
3. **Thu dữ liệu có nhãn kiểm chứng được:** lab traffic/PCAP đối chiếu, baseline xác nhận sạch, session/device rõ; không tự biến Unknown thành Normal. Giữ Parquet cũ như dữ liệu lịch sử không đủ provenance.
4. **Sửa đánh giá:** split raw theo thời gian/group, preprocessing riêng fold, holdout thực địa, detector calibration đúng runtime và end-to-end report. Không dùng metadata cũ như kết quả đã tái xác nhận.
5. **Sửa triển khai:** bundle atomic, parity Python/C/TFLite, threshold ACK, dedup, retained state, durable lake/catalog và board đúng.
6. **Đồng bộ báo cáo và chi phí:** 56 feature/15 lớp tổng, capability thực, cloud records/month, TCO, SOM và dòng tiền theo quý/tháng; đánh dấu roadmap và số khảo sát chưa xác minh.

Các kiểm tra tối thiểu trước lần demo tiếp theo: một raw sample cho cùng vector ở train/runtime/replay; prediction join đúng device/sample; error không thành Normal; không có feature lấy từ attack_scenario; bundle/scaler/labels cùng version; cùng mẫu C và Python có sai số được công bố; restart/reconnect không nhân đôi mẫu hoặc mất trạng thái; UI hiển thị Unknown cho trường chưa đo.
