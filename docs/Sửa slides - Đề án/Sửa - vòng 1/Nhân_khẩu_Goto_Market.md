# TÀI LIỆU CHUẨN BỊ NỘI DUNG SLIDE: ĐỐI THỦ CẠNH TRANH, CHÂN DUNG KHÁCH HÀNG & CHIẾN LƯỢC GO-TO-MARKET (B2B & B2B2B)

> **Mục tiêu:** Cung cấp số liệu và nội dung cô đọng, sắc bén, đồng bộ 100% với Đề án Sáng tạo trẻ và Báo cáo tài chính `docs/Sửa - vòng 1/FIX_1.md` để điền trực tiếp vào 3 Slide thuyết trình:
> 1. **Slide 1: Bảng So sánh Đối thủ Cạnh tranh & Giá thành**
> 2. **Slide 2: Chân dung Khách hàng Lý tưởng (4 Khối Nhân khẩu học - Kỹ thuật - Hành vi - Tâm lý)**
> 3. **Slide 3: Chiến lược Go-to-Market Đa kênh (B2B Trực tiếp & B2B2B Đối tác)**

---

## PHẦN 1: BẢNG SO SÁNH ĐỐI THỦ CẠNH TRANH & GIÁ THÀNH (ĐIỀN SLIDE 1)

*Căn cứ thiết kế từ hình ảnh Slide 1: Bảng 4 cột $\times$ 5 hàng thuộc tính so sánh.*

```
┌─────────────────┬───────────────────┬─────────────────────┬─────────────────────┬─────────────────────┐
│    TIÊU CHÍ     │       AERO        │ DARKTRACE / VECTRA  │   SURICATA / ZEEK   │  FORTINET / SOPHOS  │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Độ trễ          │ 1-2 giây          │ Phút - giờ          │ Giây - phút         │ Giây - phút         │
│ phát hiện       │ Real-time         │ Gửi log về          │ Nếu khớp luật       │ Chặn IP/Port tĩnh   │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Vị trí          │ Tại biên          │ Tập trung           │ Tại máy chủ giám sát│ Tại chip ASIC của   │
│ xử lý           │                   │ Appliance/Cloud     │ mạng riêng biệt     │ Gateway trung tâm   │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Yêu cầu         │ Tối thiểu         │ Cần đội ngũ SOC     │ Cần chuyên gia      │ Cần quản trị viên   │
│ kĩ thuật        │ Cắm là chạy       │ chuyên nghiệp       │ viết luật           │ mạng                │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ Dịch vụ         │ Thiết bị phần     │ Thuê bao +          │ Mã nguồn mở +       │ Thiết bị Gateway +  │
│ (Mô hình bán)   │ cứng + License    │ Appliance           │ Tự bảo trì Server   │ Bundle hàng năm     │
├─────────────────┼───────────────────┼─────────────────────┼─────────────────────┼─────────────────────┤
│ GIÁ THÀNH       │ ~5,25 triệu VNĐ   │ 1,2 – 3,8 TỶ        │ Miễn phí phần mềm   │ 30 – 80 TRIỆU       │
│ (Chi phí        │ (Node) + 550k/th  │ VNĐ/năm             │ TCO: 150 – 300 tr/n │ VNĐ (Gốc) +         │
│ thực tế)        │ (~11,8 tr năm đầu)│ ($50.000 – $150.000)│ (Máy chủ + Kỹ sư)   │ 15 – 35 tr/năm      │
└─────────────────┴───────────────────┴─────────────────────┴─────────────────────┴─────────────────────┘
```

### 📋 Nội dung chi tiết chuẩn để điền vào 2 hàng còn trống trên Slide 1:

#### 1. Hàng "Dịch vụ" (Mô hình kinh doanh & Cung cấp sản phẩm):
* **AERO:** **Thiết bị phần cứng + License** *(Hardware-as-a-Gateway + Thuê bao SaaS định kỳ)*.
* **Darktrace / Vectra:** **Thuê bao + Appliance** *(Bán máy chủ phân tích chuyên dụng + Bản quyền phần mềm hàng năm đắt đỏ)*.
* **Suricata / Zeek:** **Mã nguồn mở + Tự bảo trì phần cứng** *(Phần mềm miễn phí, nhưng tự chịu trách nhiệm đầu tư máy chủ và mua tập luật thương mại)*.
* **Fortinet / Sophos:** **Thiết bị Gateway + Security Bundle** *(Bán thiết bị Tường lửa phần cứng + Gói bản quyền UTP/Enterprise gia hạn hàng năm)*.

#### 2. Hàng "Giá thành" (Chi phí tài chính quy đổi thực tế):
* **AERO:** **~5,25 triệu VNĐ (Thiết bị) + 550.000 VNĐ/tháng (License Pro)**  
  *(Chi phí năm đầu chỉ **~11,85 triệu VNĐ/điểm**; từ năm 2 chỉ còn **6,6 triệu VNĐ/năm**; cắt giảm hơn **90%** chi phí so với giải pháp ngoại).*
* **Darktrace / Vectra:** **1,2 – 3,8 tỷ VNĐ/năm** *(Tương đương $50.000 – $150.000 USD/năm cho doanh nghiệp vừa; hàng trăm nghìn USD cho doanh nghiệp lớn; chưa tính chi phí lưu trữ Cloud Ingestion).*
* **Suricata / Zeek:** **Miễn phí phần mềm — TCO thực tế ~150 – 300 triệu VNĐ/năm**  
  *(Cần máy chủ Server 1U/2U từ 40–80 triệu + Mua tập luật ET Pro ~$900/năm + **Lương kỹ sư quản trị mạng/SOC tối thiểu 15–20 triệu/tháng** để trực tiếp vận hành).*
* **Fortinet / Sophos:** **30 – 80 triệu VNĐ ban đầu + 15 – 35 triệu VNĐ/năm**  
  *(Giá thiết bị FortiGate 60F/70F Hardware Bundle ~$1.200 – $1.500 USD + Phí gia hạn license UTP/Enterprise ~$550 – $750 USD/năm cho mỗi văn phòng).*

---

## PHẦN 2: CHÂN DUNG KHÁCH HÀNG LÝ TƯỞNG (IDEAL CUSTOMER PROFILE - ICP) (ĐIỀN SLIDE 2)

*Căn cứ thiết kế từ hình ảnh Slide 2: Khung trung tâm bao quanh bởi 4 khối định vị khách hàng.*

```
┌───────────────────────────────────────┐         ┌───────────────────────────────────────┐
│           NHÂN KHẨU HỌC               │         │               HÀNH VI                 │
│ • Doanh nghiệp vừa và nhỏ (SME 20-300 │         │ • Thuê ngoài IT (Outsource) hoặc chỉ  │
│   nhân sự); Doanh thu 20 - 500 tỷ.    │         │   có 1-2 IT kiêm nhiệm toàn bộ mạng.  │
│ • Nhà máy thông minh (KCN Bắc Ninh,   │         │ • Mua sắm thận trọng: Ưa chuộng trả   │
│   Hải Phòng, Bình Dương, Đồng Nai).   │ ◄─────► │   trước ít (Low CAPEX), thuê bao theo │
│ • Chuỗi bán lẻ/F&B (10-50 chi nhánh). │         │   tháng (SaaS), ngại hợp đồng tiền tỷ.│
│ • Trường ĐH, Viện nghiên cứu, Lab IoT.│         │ • Phản ứng bị động: Chỉ biết bị đánh  │
│ • Ngân sách Security: < 50-100 tr/năm.│         │   khi mạng sập hoặc bị khóa dữ liệu.  │
└───────────────────────────────────────┘         └───────────────────────────────────────┘
                    ▲                                                 ▲
                    │        CHÂN DUNG KHÁCH HÀNG LÝ TƯỞNG            │
                    ▼           (DOANH NGHIỆP SME & IIOT)             ▼
┌───────────────────────────────────────┐         ┌───────────────────────────────────────┐
│          HIỆU QUẢ KỸ THUẬT            │         │               TÂM LÝ                  │
│ • Phát hiện Real-time (1-2 giây),     │         │ • Nỗi sợ: Gián đoạn sản xuất (thiệt   │
│   giảm MTTD gián đoạn mạng từ phút    │         │   hại 40-100 tr/giờ); mất uy tín dữ   │
│   xuống giây.                         │         │   liệu khách hàng (Nghị định 13/NĐ-CP)│
│ • Sống sót khi mất mạng (Offline      │ ◄─────► │ • Nỗi đau: Bất lực vì giải pháp ngoại │
│   Survival): Báo động còi/LED tại chỗ.│         │   quá đắt, còn Router thường thì mù.  │
│ • Cắm là chạy (Plug & Play), không làm│         │ • Kỳ vọng: Cần 1 "người gác cổng" tự  │
│   nghẽn mạng, không cần cấu hình IP.  │         │   động 24/7, dễ dùng với chi phí bình │
│ • Chặn bắt Zero-day & bất thường IoT. │         │   dân bằng tiền Internet hàng tháng.  │
└───────────────────────────────────────┘         └───────────────────────────────────────┘
```

### 1. Nhân khẩu học & Đặc tính Tổ chức (Firmographics):
* **Quy mô Doanh nghiệp:** Doanh nghiệp vừa và nhỏ (SME) quy mô từ **20 đến 300 nhân sự**; doanh thu bình quân từ **20 đến 500 tỷ VNĐ/năm**.
* **Lĩnh vực trọng tâm:**
  * **Sản xuất công nghiệp & Gia công thông minh (IIoT):** Các nhà máy tại khu công nghiệp (Bắc Ninh, Vĩnh Phúc, Hải Phòng, Bình Dương, Đồng Nai) ứng dụng cảm biến IoT, PLC, SCADA, cánh tay robot.
  * **Chuỗi bán lẻ & F&B (10 – 50 điểm bán):** Cần kết nối máy POS, camera giám sát IP về máy chủ trung tâm.
  * **Cơ sở Giáo dục & Nghiên cứu:** Trường Đại học, Viện nghiên cứu, các trung tâm đào tạo có phòng máy tính (Computer Lab) và phòng thí nghiệm mạng/IoT.
* **Đặc thù hạ tầng:** Mạng nội bộ kết hợp Wi-Fi và có dây phân tán; nhiều thiết bị thông minh không thể cài đặt phần mềm diệt virus (Agentless); **không có ngân sách xây dựng trung tâm SOC riêng** (ngân sách an ninh mạng dưới 50 – 100 triệu VNĐ/năm).

### 2. Hiệu quả Kỹ thuật mà Khách hàng Đòi hỏi (Technical Outcomes):
* **Rút ngắn độ trễ phát hiện (MTTD):** Phát hiện sự cố mạng chỉ trong **1 – 2 giây** thay vì 15 – 30 phút, bảo vệ hệ thống trước các đòn tấn công từ chối dịch vụ (DDoS) và quét lỗ hổng.
* **Hoạt động độc lập & Báo động tại chỗ (Offline Defense):** Khi đứt cáp quang hoặc tin tặc làm tê liệt Internet, thiết bị vẫn tự xử lý và hú còi/bật đèn LED cảnh báo ngay tại phòng kỹ thuật.
* **Cắm là chạy (Non-intrusive Plug & Play):** Lắp đặt giám sát thụ động (Passive Sniffing), hoàn toàn không làm gián đoạn đường truyền chính, không sợ thiết bị lỗi làm sập toàn bộ mạng văn phòng.
* **Khả năng nhận diện tấn công mới (Zero-day):** Nhờ cơ chế học máy phát hiện dị biệt (Anomaly Detection), phát hiện được các hành vi rò rỉ dữ liệu hoặc mã độc tống tiền (Ransomware) nội bộ mà tường lửa chữ ký tĩnh bỏ lọt.

### 3. Hành vi Mua sắm & Vận hành (Behaviors):
* **Nhân sự tinh gọn:** Đa phần thuê dịch vụ IT bên ngoài (Outsourced IT) hoặc chỉ có **1 đến 2 nhân sự IT tổng hợp** (phụ trách từ sửa mạng, cài máy in đến quản trị máy chủ). Không có kỹ sư chuyên trách an toàn thông tin.
* **Ưa chuộng mô hình thanh toán linh hoạt:** Ngại chi các khoản đầu tư ban đầu (CAPEX) lớn hàng trăm triệu. Thích mô hình **mua phần cứng ban đầu giá hợp lý (~5 triệu) và duy trì phí dịch vụ hàng tháng nhỏ (~550k/tháng)**.
* **Phản ứng sự cố bị động:** Thường chỉ hành động khi sự cố đã gây hậu quả nghiêm trọng (máy chủ kế toán bị mã hóa, hệ thống tính tiền POS bị tê liệt, khách hàng phàn nàn).

### 4. Tâm lý & Nỗi đau Thầm kín (Psychographics & Pain Points):
* **Nỗi sợ (Fears):**
  * Sợ dây chuyền nhà máy bị dừng (Downtime cost lên tới 40 – 100 triệu VNĐ/giờ).
  * Sợ lộ lọt dữ liệu khách hàng và bí mật kinh doanh, sợ chế tài xử phạt theo Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân.
* **Nỗi đau (Pain Points):**
  * Cảm giác "bị bỏ rơi": Các giải pháp an ninh mạng hàng đầu thế giới (Darktrace, Cisco) quá xa xỉ và phức tạp.
  * Mất niềm tin vào thiết bị định tuyến thông thường: Router/Firewall giá rẻ có sẵn không đủ thông minh, không phát hiện được tấn công từ bên trong mạng nội bộ.
* **Mong muốn & Động lực:** Mong muốn có một giải pháp **"Cài đặt một lần – An tâm mãi mãi"**, cảnh báo tức thời qua điện thoại/Web Dashboard với giao diện tiếng Việt trực quan, minh bạch chi phí.

---

## PHẦN 3: CHIẾN LƯỢC GO-TO-MARKET: B2B & B2B2B (ĐIỀN SLIDE 3)

*Căn cứ thiết kế từ hình ảnh Slide 3: Khung viền lớn để trình bày mô hình 2 động cơ phân phối và lộ trình 3 giai đoạn đồng bộ với `FIX_1.md`.*

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                CHIẾN LƯỢC GO-TO-MARKET ĐA KÊNH                                    │
│                 (KẾT HỢP BÁN TRỰC TIẾP B2B VÀ ĐÒN BẨY ĐỐI TÁC PHÂN PHỐI B2B2B)                     │
├─────────────────────────────────────────────────┬─────────────────────────────────────────────────┤
│          ĐỘNG CƠ 1: KÊNH B2B TRỰC TIẾP          │        ĐỘNG CƠ 2: KÊNH B2B2B ĐỐI TÁC KÊNH       │
│             (Direct Sales & Pilots)             │        (Channel Partners & Integrators)         │
├─────────────────────────────────────────────────┼─────────────────────────────────────────────────┤
│ • Khách hàng mục tiêu:                          │ • 3 Trục đối tác chiến lược:                    │
│   - Khoa CNTT, Lab ĐH Bách Khoa, Phenikaa,      │   1. Nhà Tích hợp Hệ thống (SI): FPT IS,        │
│     Công nghiệp, Bưu chính Viễn thông.          │      CMC TS, SV Tech, các đơn vị thầu camera.   │
│   - Doanh nghiệp SME & Nhà máy KCN miền Bắc.    │   2. Nhà cung cấp dịch vụ quản trị (MSP/MSSP):  │
│                                                 │      Đóng gói AERO thành dịch vụ an ninh mạng.  │
│ • Phương thức tiếp cận:                         │   3. Nhà mạng Viễn thông (Telcos / ISPs):       │
│   - Thử nghiệm 0 đồng (Proof-of-Concept 30 ngày)│      Bán kèm gói Internet Doanh nghiệp (VAS).   │
│   - Bán hàng qua tư vấn hiện trạng (Security    │                                                 │
│     Audit miễn phí) để chỉ ra lỗ hổng.          │ • Chính sách hợp tác:                           │
│   - Báo cáo định lượng trực quan hàng tuần.     │   - Chiết khấu phần cứng 10 - 15%.              │
│                                                 │   - Chia sẻ doanh thu thuê bao (Rev-Share       │
│ • Mục tiêu đóng góp:                            │     15 - 20% ARR định kỳ).                      │
│   Tạo doanh thu nền tảng và kiểm chứng sản      │ • Mục tiêu đóng góp:                            │
│   phẩm thực địa trong 12 - 18 tháng đầu.        │   Đòn bẩy nhân rộng quy mô đạt điểm hòa vốn     │
│                                                 │   (500 nodes) và bùng nổ đến 3.000 nodes.       │
├─────────────────────────────────────────────────┴─────────────────────────────────────────────────┤
│                     LỘ TRÌNH TRIỂN KHAI 3 GIAI ĐOẠN ĐỒNG BỘ VỚI TÀI CHÍNH                         │
├───────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [2026 - 2027: SEED & PILOT]   ──► [2027 - 2028: THÂM NHẬP SỚM]  ──► [2028 - 2030: SCALE-UP TOÀN QUỐC]   │
│ • 60 thiết bị thử nghiệm          • 260 thiết bị tích lũy           • 700 ──► 1.500 ──► 3.000 thiết bị  │
│ • Doanh thu: 380 triệu VNĐ        • Ký 2-3 đối tác SI / MSP         • Doanh thu: 5,36 tỷ ──► 24,5 tỷ    │
│ • Lợi nhuận ròng: -600 triệu      • Doanh thu: 1,94 tỷ VNĐ          • VƯỢT ĐIỂM HÒA VỐN TẠI ĐẦU NĂM 3   │
│ • Tập trung B2B giáo dục & lab    • Lỗ thu hẹp: -290 triệu          • ARR thuê bao chiếm 68% doanh thu  │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Động cơ 1: Chiến lược B2B Trực tiếp (Direct B2B Strategy)
* **Phân khúc thâm nhập ban đầu:**
  * **Trường Đại học & Viện nghiên cứu:** Triển khai trực tiếp cho các phòng thực hành an ninh mạng, khoa CNTT, khoa Điện tử Viễn thông (HUST, PTIT, Phenikaa, v.v.). Đây là môi trường có lưu lượng mạng đa dạng, tạo uy tín học thuật và bảo chứng chất lượng công nghệ.
  * **Doanh nghiệp SME hạt nhân & Nhà máy thân thiết:** Khai thác các mối quan hệ đối tác công nghiệp tại các KCN lân cận Hà Nội (Bắc Ninh, Hưng Yên).
* **Mô hình tiếp cận khách hàng (Sales Playbook):**
  * **Chương trình "Proof-of-Concept (PoC) 30 ngày":** Cho khách hàng mượn thiết bị cắm thử nghiệm 30 ngày miễn phí.
  * **Báo cáo kiểm toán an ninh mạng tự động (Automated Security Report):** Sau 7 ngày cắm thử, xuất báo cáo Dashboard chỉ rõ: *Chi nhánh có bao nhiêu thiết bị IoT lạ? Đã hứng chịu bao nhiêu đợt quét cổng? Nguy cơ rò rỉ dữ liệu ở đâu?* — Giúp chủ doanh nghiệp nhìn thấy rủi ro nhãn tiền và ra quyết định mua ngay.
  * **Chính sách giá minh bạch:** 5,25 triệu VNĐ/thiết bị + 550.000 VNĐ/tháng (Gói Pro).

---

### 2. Động cơ 2: Chiến lược B2B2B qua Kênh Đối tác (Channel Partner Strategy)
*Đây là đòn bẩy quan trọng nhất giúp AERO bứt phá số lượng mà không cần phình to bộ máy bán hàng:*

* **Trục 1: Các Công ty Tích hợp Hệ thống (System Integrators - SI):**
  * *Đối tác mục tiêu:* Các công ty chuyên thầu hạ tầng mạng, lắp đặt hệ thống Camera giám sát, nhà thông minh, hệ thống mạng nội bộ cho tòa nhà và nhà máy.
  * *Giá trị mang lại cho SI:* AERO trở thành **"Module An ninh mạng nhúng kèm"** giúp SI tăng giá trị gói thầu (Up-sell), biến một dự án bán phần cứng 1 lần thành nguồn thu thuê bao dịch vụ hàng tháng.
  * *Chính sách:* Chiết khấu trực tiếp **10 – 15%** giá thiết bị phần cứng + Chia sẻ **15 – 20%** doanh thu thuê bao hàng năm (ARR Sharing).

* **Trục 2: Các Nhà cung cấp dịch vụ quản trị CNTT & An ninh mạng (MSP / MSSP):**
  * *Đối tác mục tiêu:* Các doanh nghiệp dịch vụ IT chuyên nhận vận hành hạ tầng thuê ngoài cho các SME.
  * *Giá trị mang lại cho MSP:* Các giải pháp như Darktrace hay Splunk quá đắt để MSP bán cho khách hàng nhỏ. AERO đóng vai trò là **Edge Sensor giá rẻ**, gửi cảnh báo qua MQTT/API về trung tâm giám sát của MSP, giúp MSP cung cấp dịch vụ an ninh mạng trọn gói với giá chỉ vài triệu đồng/tháng.

* **Trục 3: Các Nhà mạng Viễn thông & Cung cấp Internet (Telcos / ISPs):**
  * *Đối tác mục tiêu:* Viettel Telecom, VNPT, FPT Telecom.
  * *Mô hình hợp tác:* Đóng gói AERO thành gói dịch vụ giá trị gia tăng (VAS - Value Added Service) mang tên *"Internet Doanh nghiệp An toàn"*. Khách hàng trả cước Internet hàng tháng kèm thêm 550.000 VNĐ để được trang bị sẵn 1 thiết bị AERO Edge AI bảo vệ đường truyền.

---

### 3. Lộ trình Triển khai 3 Giai đoạn Thống nhất Tuyệt đối với Báo cáo Tài chính `FIX_1.md`:

* **Giai đoạn 1 (Tháng 10/2026 – Tháng 9/2027) — Seed & Pilot (Thung lũng tử thần):**
  * *Kênh chủ lực:* **100% B2B Trực tiếp** (Đội ngũ sáng lập trực tiếp đi demo và lắp đặt).
  * *Quy mô:* **60 thiết bị** hoạt động tại 5–10 đơn vị trường học và SME hạt nhân.
  * *Tài chính:* Doanh thu **380 triệu VNĐ**, lợi nhuận ròng **–600 triệu VNĐ** (tập trung vốn R&D và khuôn vỏ sản phẩm thương mại).

* **Giai đoạn 2 (Tháng 10/2027 – Tháng 9/2028) — Thâm nhập & Thiết lập Kênh B2B2B:**
  * *Kênh chủ lực:* **50% B2B Trực tiếp + 50% Kênh SI/MSP** tại Hà Nội và các tỉnh kinh tế trọng điểm phía Bắc.
  * *Quy mô:* Bán mới 200 thiết bị, nâng lũy kế lên **260 thiết bị**.
  * *Tài chính:* Doanh thu tăng vọt lên **1,94 tỷ VNĐ**, lỗ ròng thu hẹp còn **–290 triệu VNĐ**, lỗ lũy kế chạm đáy ở mức **–890 triệu VNĐ**.

* **Giai đoạn 3 (Tháng 10/2028 – Năm 2030) — Bứt phá Quy mô (Scale-up Toàn quốc):**
  * *Kênh chủ lực:* **80% qua mạng lưới Đối tác B2B2B** (SI, MSP và Nhà mạng Telco mở rộng vào TP.HCM và Đà Nẵng).
  * *Cột mốc hòa vốn lịch sử:* 🟢 **CHÍNH THỨC VƯỢT ĐIỂM HÒA VỐN VÀO QUÝ 1 – QUÝ 2 NĂM 2028** khi quy mô đạt **500 – 550 thiết bị**.
  * *Tài chính:* 
    * Năm 3 (2028–2029): Đạt **700 thiết bị**, doanh thu **5,36 tỷ VNĐ**, lợi nhuận ròng **+1,5 tỷ VNĐ**, lũy kế dương **+610 triệu VNĐ**.
    * Năm 4 (2029–2030): Đạt **1.500 thiết bị**, doanh thu **11,8 tỷ VNĐ**, lợi nhuận ròng **+4,25 tỷ VNĐ**.
    * Năm 5 (2030–2031): Đạt **3.000 thiết bị**, doanh thu **24,5 tỷ VNĐ**, lợi nhuận ròng **+9,8 tỷ VNĐ** (doanh thu thuê bao định kỳ ARR chiếm gần 70% tổng doanh thu).

---

## PHẦN 4: HƯỚNG DẪN THAO TÁC COPY VÀO BỘ SLIDE CỦA THÀNH VIÊN TRONG NHÓM

1. **Với Slide 1 (Bảng Đối thủ Cạnh tranh):**
   * Copy trực tiếp 2 dòng text ngắn ở **Mục 1 & Mục 2** của **Phần 1** dán vào 2 hàng trống `Dịch vụ` và `Giá thành`.
   * Nhấn mạnh với ban giám khảo: *AERO không cạnh tranh thay thế hoàn toàn Firewall cổng ngoài, mà bổ trợ giám sát thông minh tại từng điểm biên với chi phí chỉ bằng 1/100 so với giải pháp ngoại nhập Darktrace.*

2. **Với Slide 2 (Chân dung Khách hàng Lý tưởng):**
   * Lấy 4 cụm gạch đầu dòng ngắn gọn tại **Mục 1, 2, 3, 4** của **Phần 2** dán lần lượt vào 4 góc: **Nhân khẩu học (Góc trên trái) - Hiệu quả kỹ thuật (Góc dưới trái) - Hành vi (Góc trên phải) - Tâm lý (Góc dưới phải)**.
   * Đặt icon đại diện ở giữa: Hình ảnh một nhà quản trị mạng SME hoặc Giám đốc nhà máy đang cầm điện thoại theo dõi an ninh mạng.

3. **Với Slide 3 (Chiến lược Go-to-Market):**
   * Chia layout thành 2 cột chính: **Bên trái là B2B Trực tiếp (Direct Sales & Pilot)**, **Bên phải là B2B2B Đối tác (SI, MSP & Telco)**.
   * Chân trang đặt thanh ngang (Progress Bar / Timeline): Thể hiện **Lộ trình 3 Giai đoạn (Seed 60 nodes $\rightarrow$ Early Traction 260 nodes $\rightarrow$ Hòa vốn 500 nodes $\rightarrow$ Bùng nổ 3.000 nodes)**, khớp 100% với biểu đồ tài chính ở Slide 4 và Slide 15.
