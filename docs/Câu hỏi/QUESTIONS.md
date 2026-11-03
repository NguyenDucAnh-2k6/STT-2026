# TỔNG HỢP CÂU HỎI XOÁY & KỊCH BẢN TRẢ LỜI PHẢN BIỆN (Q&A CHEAT SHEET)
### DỰ ÁN: AERO – AUTOMATED EDGE RESPONSE & OPTIMIZATION
**Cuộc thi Sáng tạo trẻ 2026 | Dành cho Đội thi Innovate Future (HUST)**

---

## MỤC LỤC
1. [Bộ Nguyên tắc Vàng khi Trả lời Phản biện Trước Ban Giám khảo](#1-bộ-nguyên-tắc-vàng-khi-trả-lời-phản-biện-trước-ban-giám-khảo)
2. [PHẦN I: CÁC CÂU HỎI XOÁY VỀ KỸ THUẬT & CÔNG NGHỆ (8 CÂU HỎI)](#phần-i-các-câu-hỏi-xoáy-về-kỹ-thuật--công-nghệ)
   - [Câu 1: Xung nhịp ESP32 yếu (240MHz) sao gánh nổi lưu lượng mạng lớn / Gbps?](#câu-1-xung-nhịp-esp32-yếu-240mhz-sao-gánh-nổi-lưu-lượng-mạng-lớn--gbps)
   - [Câu 2: Lưu lượng mã hóa TLS 1.3 / WPA3 không soi được payload thì AI bắt kiểu gì?](#câu-2-lưu-lượng-mã-hóa-tls-13--wpa3-không-soi-được-payload-thì-ai-bắt-kiểu-gì)
   - [Câu 3: Bị nghẽn do DDoS bão hòa hoặc bị tấn công trực tiếp vào Probe thì sao?](#câu-3-bị-nghẽn-do-ddos-bão-hòa-hoặc-bị-tấn-công-trực-tiếp-vào-probe-thì-sao)
   - [Câu 4: Cảnh báo giả (False Positive) và trôi dạt dữ liệu (Concept Drift) giải quyết thế nào?](#câu-4-cảnh-báo-giả-false-positive-và-trôi-dạt-dữ-liệu-concept-drift-giải-quyết-thế-nào)
   - [Câu 5: Vị trí đặt thiết bị (Placement) và khả năng bao quát toàn bộ mạng LAN?](#câu-5-vị-trí-đặt-thiết-bị-placement-và-khả-năng-bao-quát-toàn-bộ-mạng-lan)
   - [Câu 6: Thiết bị chỉ cảnh báo (Alert) hay có thể tự động chặn (Block/Mitigate)?](#câu-6-thiết-bị-chỉ-cảnh-báo-alert-hay-có-thể-tự-động-chặn-blockmitigate)
   - [Câu 7: Đo đạc độ trễ < 50ms bằng cách nào? Chứng minh tính tương đương giữa Python và C++?](#câu-7-đo-đạc-độ-trễ--50ms-bằng-cách-nào-chứng-minh-tính-tương-đương-giữa-python-và-c)
   - [Câu 8: Có tính đặc trưng và suy luận AI như bình thường đối với các gói tin bị drop do quá tải hàng đợi không?](#câu-8-có-thể-tính-các-đặc-trưng-và-suy-luận-học-máy-như-bình-thường-đối-với-các-gói-tin-bị-drop-do-hàng-đợi-quá-tải-không)
3. [PHẦN II: CÁC CÂU HỎI XOÁY VỀ KINH TẾ, THỊ TRƯỜNG & KHỞI NGHIỆP (8 CÂU HỎI)](#phần-ii-các-câu-hỏi-xoáy-về-kinh-tế-thị-trường--khởi-nghiệp)
   - [Câu 8: Các em đã đi khảo sát thực tế chưa hay chỉ ngồi lấy số liệu trên mạng?](#câu-8-các-em-đã-đi-khảo-sát-thực-tế-chưa-hay-chỉ-ngồi-lấy-số-liệu-trên-mạng)
   - [Câu 9: Nếu các tập đoàn lớn (BKAV, Viettel, Cisco) làm thiết bị biên giá rẻ thì AERO cạnh tranh thế nào?](#câu-9-nếu-các-tập-đoàn-lớn-bkav-viettel-cisco-làm-thiết-bị-biên-giá-rẻ-thì-aero-cạnh-tranh-thế-nào)
   - [Câu 10: Nhóm toàn sinh viên kỹ thuật, làm sao tiếp cận và bán hàng cho hàng trăm doanh nghiệp (Go-To-Market)?](#câu-10-nhóm-toàn-sinh-viên-kỹ-thuật-làm-sao-tiếp-cận-và-bán-hàng-cho-hàng-trăm-doanh-nghiệp-go-to-market)
   - [Câu 11: Tại sao khách hàng chịu trả 550.000đ/tháng? Nếu họ chỉ mua phần cứng rồi hủy thuê bao thì sao?](#câu-11-tại-sao-khách-hàng-chịu-trả-550000đtháng-nếu-họ-chỉ-mua-phần-cứng-rồi-hủy-thuê-bao-thì-sao)
   - [Câu 12: Kêu gọi 2,5 tỷ VNĐ vốn hạt giống, số tiền này cụ thể tiêu vào đâu trong 12 tháng tới? Khi nào hòa vốn?](#câu-12-kêu-gọi-25-tỷ-vnđ-vốn-hạt-giống-số-tiền-này-cụ-thể-tiêu-vào-đâu-trong-12-tháng-tới-khi-nào-hòa-vốn)
   - [Câu 13: Tại sao quy mô thị trường lại tính bằng Tỷ USD khi khách hàng mục tiêu chỉ là quán ăn, cửa hàng?](#câu-13-tại-sao-quy-mô-thị-trường-lại-tính-bằng-tỷ-usd-khi-khách-hàng-mục-tiêu-chỉ-là-quán-ăn-cửa-hàng)
   - [Câu 14: Khả năng mở rộng quy mô sản xuất phần cứng: Nếu có đơn 500 chiếc/tháng thì sản xuất thế nào?](#câu-14-khả-năng-mở-rộng-quy-mô-sản-xuất-phần-cứng-nếu-có-đơn-500-chiếctháng-thì-sản-xuất-thế-nào)
   - [Câu 15: Sau khi tốt nghiệp đại học, đội ngũ có cam kết tiếp tục phát triển dự án thành doanh nghiệp không?](#câu-15-sau-khi-tốt-nghiệp-đại-học-đội-ngũ-có-cam-kết-tiếp-tục-phát-triển-dự-án-thành-doanh-nghiệp-không)

---

## 1. BỘ NGUYÊN TẮC VÀNG KHI TRẢ LỜI PHẢN BIỆN TRƯỚC BAN GIÁM KHẢO

1. **Nguyên tắc "Cảm ơn & Thừa nhận giá trị câu hỏi":** Luôn bắt đầu bằng câu xác nhận thông minh: *"Dạ em cảm ơn câu hỏi rất thực tế và sâu sắc của Thầy/Cô..."*. Không phản bác tay đôi, không ngắt lời giám khảo.
2. **Nguyên tắc "Định lượng đè bẹp định tính":** Tuyệt đối không trả lời chung chung *"nhóm em tối ưu thuật toán rất tốt"*. Hãy trả lời bằng con số: *"Mô hình nén còn 208KB, đo bằng esp_timer hết 18ms, sai số parity bằng 0"*.
3. **Nguyên tắc "Biết người biết ta":** 
   - Với câu hỏi kỹ thuật: Giám khảo đang kiểm tra xem sinh viên có **tự tay làm thật (Hands-on)** hay chỉ đi chém gió lý thuyết.
   - Với câu hỏi kinh tế: Giám khảo đang kiểm tra xem sinh viên có **tư duy kinh doanh thực tế (Business Sense)** hay đang mơ mộng trên mây.
4. **Nguyên tắc "Chuyển bại thành thắng (Bridge to Strengths)":** Khi bị hỏi vào điểm yếu (như phần cứng ESP32 yếu, chưa có nhiều khách hàng), hãy thẳng thắn thừa nhận giới hạn phạm vi, sau đó chuyển ngay sang giải pháp thiết kế bù trừ và thế mạnh độc bản của đề tài.

---

## PHẦN I: CÁC CÂU HỎI XOÁY VỀ KỸ THUẬT & CÔNG NGHỆ

---

### Câu 1: Xung nhịp ESP32 yếu (240MHz) sao gánh nổi lưu lượng mạng lớn / Gbps?
* **Cạm bẫy của Giám khảo:** Thầy cô ngành Mạng máy tính sẽ bẫy rằng ESP32 là vi điều khiển IoT giá vài chục nghìn đồng, làm sao phân tích được lưu lượng mạng doanh nghiệp lên tới hàng trăm Mbps hoặc Gigabit.
* **Chiến lược trả lời:** Phân tách rõ giữa **Data Plane (Chuyển tiếp gói tin)** và **Monitoring Plane (Giám sát trích xuất đặc trưng)**. AERO giám sát thụ động (Passive Sniffing), không làm router trung chuyển; đồng thời AERO áp dụng kiến trúc **Dual-Probe**.
* **Câu trả lời mẫu sắc bén:**
  > *"Em cảm ơn Thầy/Cô. Đây là câu hỏi mà nhóm em đã trăn trở ngay từ những ngày đầu thiết kế kiến trúc. Để giải quyết bài toán này, nhóm em xác lập 2 nguyên lý kỹ thuật:*
  > 
  > *Thứ nhất, **AERO không nằm trên đường truyền nối tiếp (Inline)** để chuyển tiếp gói tin, mà hoạt động ở chế độ giám sát thụ động (Passive Promiscuous Sniffing qua Wi-Fi hoặc Port Mirroring từ Switch). Do đó, thiết bị không bao giờ làm nghẽn mạng hay làm chậm tốc độ truyền dữ liệu của khách hàng.*
  > 
  > *Thứ hai, ESP32 không bao giờ 'giải mã toàn bộ payload của từng gigabyte dữ liệu'. Thay vào đó, bộ lọc phần cứng chỉ trích xuất **Metadata và Thống kê theo cửa sổ thời gian 2.0 giây** (bao gồm: số lượng gói tin, tỷ lệ kích thước gói, tần suất cờ TCP SYN/RST, số lượng cổng kết nối). Việc tính toán này chỉ tiêu tốn chưa đầy **15% công suất của nhân CPU 2**, để lại toàn bộ nhân CPU 1 cho FreeRTOS chạy tác vụ mạng và suy luận TinyML.*
  > 
  > *Thứ ba, với các đường truyền cáp quang Gigabit doanh nghiệp lớn, AERO áp dụng kiến trúc **Dual-Probe**: Node ESP32 chuyên trách bảo vệ phân đoạn Wi-Fi và IoT không dây; còn với mạng trục có dây, nhóm cung cấp module **AERO Host Probe** chạy trực tiếp như một service cực nhẹ trên Router OpenWrt hoặc máy chủ Gateway nội bộ."*

---

### Câu 2: Lưu lượng mã hóa TLS 1.3 / WPA3 không soi được payload thì AI bắt kiểu gì?
* **Cạm bẫy của Giám khảo:** Giám khảo An ninh mạng sẽ hỏi: Bây giờ 95% lưu lượng web và ứng dụng đều mã hóa HTTPS/TLS 1.3, không đọc được nội dung thì làm sao biết có mã độc hay SQL Injection?
* **Chiến lược trả lời:** Nhấn mạnh trường phái **Encrypted Traffic Analytics (Phân tích lưu lượng mã hóa)** dựa trên hình thái dòng chảy (Flow Behavioral Fingerprinting) thay vì kiểm tra gói tin sâu (Deep Packet Inspection - DPI). Đây là xu hướng bảo mật tiên tiến nhất thế giới hiện nay, vừa bảo vệ quyền riêng tư, vừa tuân thủ pháp luật.
* **Câu trả lời mẫu sắc bén:**
  > *"Thưa Thầy/Cô, việc không giải mã Payload chính là một **lợi thế có chủ đích** trong thiết kế của AERO, xét trên cả góc độ kỹ thuật và pháp lý:*
  > 
  > *Về mặt pháp lý: Việc soi nội dung gói tin của người dùng vi phạm nghiêm trọng quyền riêng tư theo **Nghị định 13/2023/NĐ-CP** và chuẩn GDPR. AERO bảo vệ mạng mà không bao giờ xâm phạm dữ liệu riêng tư của khách hàng.*
  > 
  > *Về mặt kỹ thuật: Mã hóa che giấu nội dung chữ bên trong, nhưng **hoàn toàn không thể che giấu được hành vi động học của dòng chảy (Flow Dynamics)**. Các cuộc tấn công mạng luôn để lại các 'dấu vân tay' đặc trưng ở tầng mạng và tầng giao vận:*
  > - *Tấn công DDoS làm bùng nổ đột biến tỷ lệ gói tin kích thước nhỏ (Small Packet Anomaly) và mất cân đối nghiêm trọng giữa gói tin đi và về (Asymmetric Flow).*
  > - *Port Scan bộc lộ qua tần suất mở kết nối thất bại (SYN không kèm ACK, cờ RST tăng vọt).*
  > - *Botnet / Mã độc liên lạc với máy chủ C&C (Command & Control) bộc lộ qua chu kỳ gửi tín hiệu 'nhịp tim' (Beaconing Inter-arrival Time) đều đặn một cách bất thường.*
  > 
  > *Trên tập dữ liệu benchmark quốc tế Edge-IIoTset, chỉ cần sử dụng 10 đặc trưng hình thái dòng chảy này, mô hình học máy của AERO đã đạt độ chính xác F1-score trên **98,5%** mà không cần đọc một byte payload nào."*

---

### Câu 3: Bị nghẽn do DDoS bão hòa hoặc bị tấn công trực tiếp vào Probe thì sao?
* **Cạm bẫy của Giám khảo:** Giám khảo muốn biết hệ thống có bị "gục ngã" khi lưu lượng vượt quá giới hạn lấy mẫu, hoặc thiết bị có bị hacker chiếm quyền điều khiển (hijack) hay không.
* **Chiến lược trả lời:** Trình bày cơ chế hàng đợi giới hạn (Bounded Queue & Drop Policy) và thiết kế tàng hình (Stealth/Air-gapped Monitoring).
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, nhóm em đã thiết kế cơ chế phòng vệ 2 tầng cho chính bản thân thiết bị AERO Probe:*
  > 
  > *1. Khi bị tấn công DDoS bão hòa lưu lượng:*
  > *Nếu lưu lượng vượt quá năng lực xử lý của bộ đệm RAM (chẳng hạn hàng triệu gói tin/giây), cơ chế hàng đợi giới hạn (Bounded Ring-Buffer) trên FreeRTOS sẽ kích hoạt quy tắc **Chủ động bỏ rơi gói thô (Drop Packet) nhưng giữ nguyên bộ đếm phần cứng (Hardware Counters)**. Hệ thống nhận thấy tốc độ gia tăng đột biến của biến đếm gói rơi (`dropped_packets_rate`), và chính chỉ số này là bằng chứng xác thực nhất để AERO **lập tức kích hoạt còi báo động tại chỗ trong chưa đầy 50ms**. Nghĩa là bão mạng không làm AERO bị 'mù', mà làm chuông báo động reo to hơn!*
  > 
  > *2. Khả năng tàng hình chống tấn công chiếm quyền (Zero-Attack Surface):*
  > *Card mạng Wi-Fi của ESP32 ở chế độ Promiscuous Sniffing là **hoàn toàn thụ động** — thiết bị không phát sóng phát IP, không mở bất kỳ cổng lắng nghe nào (No open listening ports) trên mạng giám sát. Attacker quét mạng sẽ hoàn toàn không thấy sự tồn tại của AERO Probe. Dữ liệu cảnh báo được truyền qua một kênh riêng biệt (VLAN cách ly, hoặc cáp USB Serial UART vật lý nối vào máy chủ), đảm bảo an toàn tuyệt đối."*

---

### Câu 4: Cảnh báo giả (False Positive) và trôi dạt dữ liệu (Concept Drift) giải quyết thế nào?
* **Cạm bẫy của Giám khảo:** Thầy cô ngành AI/ML sẽ bắt bẻ: "Mạng doanh nghiệp thay đổi thiết bị liên tục, giờ cao điểm khách đông lưu lượng tăng thì AI có báo động nhầm không? Mô hình train sẵn thì làm sao thích nghi với môi trường mới?"
* **Chiến lược trả lời:** Trình bày cơ chế **Hybrid Anomaly Detection (AI + Ngưỡng nhạy cảm động)** và chu trình **Cập nhật mô hình từ xa qua Digital Twin (MLOps tại biên)**.
* **Câu trả lời mẫu sắc bén:**
  > *"Thưa Thầy/Cô, cảnh báo giả là nỗi ám ảnh lớn nhất của các hệ thống an ninh mạng. AERO giải quyết triệt để vấn đề này bằng 3 cơ chế:*
  > 
  > *Thứ nhất, **Kiến trúc lọc 2 tầng (Two-Tier Filtering)**: Tầng 1 so sánh lưu lượng với chu kỳ sinh hoạt theo khung giờ (ví dụ: giờ trưa quán ăn đông khách là bình thường). Tầng 2 là mô hình AI chỉ báo động khi đồng thời xuất hiện sự bất thường về cả lưu lượng lẫn tỷ lệ phân bố gói tin (packet distribution).*
  > 
  > *Thứ hai, **Cơ chế Ngưỡng nhạy cảm động (Dynamic Sensitivity Tuning)**: Không fix cứng ngưỡng phát hiện trong firmware. Quản trị viên có thể điều chỉnh độ nhạy cho từng điểm đo qua thanh trượt trên Web Dashboard trong thời gian thực, gửi lệnh qua MQTT cập nhật ngay lập tức.*
  > 
  > *Thứ ba, **Xử lý trôi dạt dữ liệu (Concept Drift)**: Thiết bị biên AERO chỉ làm nhiệm vụ suy luận (Inference). Khi phát hiện các mẫu dữ liệu lạ lặp lại nhiều lần nhưng không phải tấn công, Probe sẽ đóng gói mẫu ngoại lệ (outlier telemetry) gửi về Server trung tâm. Tại đây, công cụ Digital Twin Lab của nhóm sẽ phân tích trôi dạt, huấn luyện lại mô hình và đẩy bộ trọng số C-array mới xuống chip biên qua tính năng **OTA Firmware Update** mà không cần can thiệp phần cứng."*

---

### Câu 5: Vị trí đặt thiết bị (Placement) và khả năng bao quát toàn bộ mạng LAN?
* **Cạm bẫy của Giám khảo:** Một cửa hàng hay văn phòng có nhiều phòng, dùng Switch có dây chia mạng, Wi-Fi phát qua nhiều Access Point. Một con ESP32 bắt Wi-Fi đặt ở góc phòng thì làm sao thấy được gói tin có dây hay ở phòng khác?
* **Chiến lược trả lời:** Thừa nhận phạm vi vật lý của sóng Wi-Fi và trình bày mô hình triển khai phân tán dạng Mesh/Multi-node cùng giải pháp Host Probe cho mạng dây.
* **Câu trả lời mẫu sắc bén:**
  > *"Em cảm ơn Thầy/Cô đã chỉ ra vấn đề thực tế về topo mạng. Nhóm em đã giải quyết bài toán này theo mô hình **Giám sát Phân tán (Distributed Edge Monitoring)**:*
  > 
  > *Đối với mạng không dây (Wi-Fi): Sóng 2.4GHz truyền qua không gian, AERO Probe được đặt cạnh các cụm thiết bị trọng yếu (như cụm máy POS thu ngân, cụm camera an ninh hoặc cạnh router Wi-Fi trung tâm). Chi phí 1 node AERO rất rẻ (chỉ vài trăm nghìn tiền linh kiện), nên doanh nghiệp có thể triển khai 2–3 node cho các góc khuất mà tổng chi phí vẫn thấp hơn nhiều so với mua một máy chủ lớn.*
  > 
  > *Đối với mạng có dây (Ethernet LAN qua Switch): Nếu doanh nghiệp dùng Switch có quản lý (Managed Switch), nhóm cấu hình 1 cổng **Port Mirroring / SPAN** cắm trực tiếp vào AERO Host Probe (chạy trên máy tính trạm POS hoặc Raspberry Pi). Mọi gói tin đi qua switch đều được nhân bản sang cổng này để AERO phân tích toàn diện. Nhờ đó, dù là lưu lượng không dây hay có dây, AERO đều bao quát 100%."*

---

### Câu 6: Thiết bị chỉ cảnh báo (Alert) hay có thể tự động chặn (Block/Mitigate)?
* **Cạm bẫy của Giám khảo:** Tên đề tài là "Automated Edge Response & Optimization" (Phản ứng tự động), nếu các em chỉ kêu còi hú với gửi thông báo thì mới chỉ là "Detect", sao gọi là "Response"?
* **Chiến lược trả lời:** Định nghĩa rõ cấp độ phản ứng an toàn (Safe Graduated Response) để tránh làm sập nhầm mạng khách hàng (Denial of Service do phản ứng sai).
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, chữ 'Response' (Phản ứng) trong AERO được thiết kế theo **3 cấp độ phản ứng phân tầng (Graduated Response)** để đảm bảo tính an toàn vận hành cao nhất cho doanh nghiệp:*
  > 
  > *1. **Cấp độ Vật lý tại chỗ (< 50 mili-giây):** Kích hoạt còi hú báo động và đèn LED đỏ tại quầy thu ngân. Giúp nhân viên cửa hàng lập tức phát hiện sự cố, tạm dừng nhập thông tin thẻ khách hàng để tránh lộ lọt dữ liệu.*
  > 
  > *2. **Cấp độ Mạng tự động (Network Enforcement):** AERO tích hợp module điều khiển tự động: Khi phát hiện IP hoặc MAC nội bộ bị nhiễm botnet đang gửi mã độc, AERO gửi lệnh API/SNMP tới Router/Switch mạng để **tự động cô lập cổng (Port Isolation) hoặc khóa MAC nghi ngờ vào Blacklist tạm thời**, chặn đứng cuộc tấn công lan rộng trong mạng nội bộ.*
  > 
  > *3. **Cấp độ Quản trị từ xa:** Đẩy bản tin Webhook lên Telegram/SMS của người phụ trách với nút bấm xác nhận 1-chạm: 'Ngắt kết nối chi nhánh' hoặc 'Chấp nhận lưu lượng'.*
  > 
  > *Cách tiếp cận này giúp ngăn chặn tấn công tức thì mà không gây rủi ro tự ngắt mạng kinh doanh sai lầm của khách hàng."*

---

### Câu 7: Đo đạc độ trễ < 50ms bằng cách nào? Chứng minh tính tương đương giữa Python và C++?
* **Cạm bẫy của Giám khảo:** Giám khảo kỹ thuật sẽ nghi ngờ các con số: "Độ trễ < 50ms và thời gian suy luận 15-35ms các em tự bịa ra hay đo bằng công cụ gì? Mô hình train bằng Scikit-Learn trên máy tính khi dịch sang C++ chạy trên chip có bị sai lệch kết quả không?"
* **Chiến lược trả lời:** Nêu rõ công cụ đo phần cứng (Hardware Timer ISR) và quy trình kiểm thử tương đương (Parity Verification).
* **Câu trả lời mẫu sắc bén:**
  > *"Em xin báo cáo chi tiết về phương pháp đo kiểm thực nghiệm của nhóm:*
  > 
  > *Về đo đạc độ trễ: Nhóm không đo bằng ước lượng cảm tính, mà sử dụng hàm đếm xung thời gian thực của chip ESP32 là `esp_timer_get_time()` với độ phân giải **micro-giây ($\mu s$)** và đo trực tiếp qua máy hiện sóng (Oscilloscope) trên chân GPIO kích hoạt còi báo động. Từ thời điểm gói tin bất thường cuối cùng lọt vào bộ đệm driver Wi-Fi đến khi chân GPIO xuất mức điện áp HIGH kích hoạt còi, tổng thời gian đo được trung bình là **38,4 mili-giây** (hoàn toàn nằm trong cam kết < 50ms).*
  > 
  > *Về tính tương đương Python vs C++ (Parity Check): Nhóm đã xây dựng một module kiểm thử tự động `test_parity.py`. Mô hình Random Forest và Isolation Forest sau khi huấn luyện trên Python được chuyển đổi trực tiếp thành cấu trúc mảng cây tĩnh trong file C header `tinyml_model.h`. Nhóm đã cho chạy đối chiếu chéo trên **10.000 vector mẫu thử nghiệm độc lập**: Kết quả phân loại giữa code C++ trên chip ESP32 và code Python Scikit-Learn trên máy tính đạt **sự trùng khớp 100% (Zero Divergence)**, sai số xác suất dự đoán dưới $10^{-6}$ do làm tròn số thực float32."*

---

### Câu 8: Có thể tính các đặc trưng và suy luận học máy như bình thường đối với các gói tin bị drop do hàng đợi quá tải không?
* **Cạm bẫy của Giám khảo:** Giám khảo chuyên ngành Mạng máy tính & Hệ thống nhúng đang gài bẫy về nguyên lý bộ nhớ và tính trung thực khoa học. Nếu sinh viên 'chém gió' rằng: *'Dạ hệ thống em tối ưu siêu việt nên gói tin bị drop vẫn tính toán và suy luận AI như bình thường'*, giám khảo sẽ bẻ gãy ngay vì vi phạm nguyên lý vật lý: **Gói tin đã bị drop khỏi hàng đợi RAM thì dữ liệu thô (payload/header) đã bị hủy, lấy đâu ra byte mà trích xuất đặc trưng!**
* **Chiến lược trả lời:**
  1. Thừa nhận dứt khoát và trung thực về mặt kỹ thuật: Đối với từng gói tin đơn lẻ đã bị drop, **không thể** trích xuất đặc trưng sâu (như cờ TCP, cổng dịch vụ, payload) hay suy luận AI cá lẻ cho gói tin đó.
  2. Chỉ ra cơ chế ghi nhận 2 tầng trong thiết kế của AERO: Gói tin bị drop **vẫn được bộ đếm phần cứng ghi nhận vào đặc trưng vĩ mô của cửa sổ** (`packet_rate`, `byte_rate`, `radio_queue_dropped`).
  3. Lập luận an ninh đanh thép: Hiện tượng "hàng đợi quá tải và drop gói" **chính là đặc trưng định danh lớn nhất của tấn công bão mạng (Volumetric DDoS)**. Hệ thống kích hoạt báo động trong dưới 50ms dựa trên tốc độ bùng nổ lưu lượng mà không cần cố phân tích từng gói rác.
  4. Cơ chế lấy mẫu đại diện (Sampling): Mô hình TinyML suy luận trên các gói tin được giữ lại trong hàng đợi, mang đầy đủ tính đại diện cho cả đợt tấn công lặp lại.
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, câu hỏi này chạm đúng vào bản chất kỹ thuật của hệ thống nhúng, và em xin trả lời thẳng thắn và chính xác về mặt nguyên lý:*
  > 
  > *Về mặt kỹ thuật vi điều khiển: Đối với các gói tin đã bị drop khỏi hàng đợi (Queue Drop) do quá tải bộ đệm, hệ thống **hoàn toàn KHÔNG THỂ trích xuất các đặc trưng sâu (như TCP flags, port, payload) hay chạy mô hình học máy per-packet trên chính gói tin đó**, bởi vì dữ liệu thô của gói tin đã bị driver hủy khỏi RAM để bảo vệ chip không bị treo tràn bộ nhớ (Out-of-Memory).*
  > 
  > *Tuy nhiên, AERO xử lý bài toán này bằng **3 cơ chế thiết kế bù trừ thông minh**:*
  > 
  > *Thứ nhất, **Đặc trưng thống kê vĩ mô vẫn được bảo toàn 100%**: Trong hàm ngắt nhận gói `wifi_promiscuous_rx_cb`, trước khi gói tin bị từ chối đưa vào hàng đợi `radioFrames`, bộ đếm phần cứng vẫn kịp cộng dồn: `total_packets++`, `total_bytes += len` và biến đếm `radio_queue_dropped++`. Do đó, ở cấp độ cửa sổ giám sát (Window-level 2.0s), các đặc trưng lưu lượng như `packet_rate` (tốc độ gói/giây), `byte_rate` và tỷ lệ drop **vẫn được tính toán đầy đủ và chính xác tuyệt đối**.*
  > 
  > *Thứ hai, **Hàng đợi quá tải chính là đặc trưng nhận diện tấn công DDoS**: Trong an ninh mạng, mục đích của kẻ tấn công khi dội bão gói tin (SYN Flood, UDP Flood) chính là làm nghẽn hàng đợi. Khi chỉ số `packet_rate` tăng vọt và xuất hiện `radio_queue_dropped > 0`, bộ phát hiện dị biệt dựa trên luật lưu lượng của AERO lập tức nhận diện đây là hành vi bất thường và **kích hoạt còi hú/đèn LED cảnh báo tại chỗ trong < 50ms**, mà không cần phải cố gắng đọc từng gói tin rác.*
  > 
  > *Thứ ba, **Cơ chế Lấy mẫu đại diện (Representative Sampling)**: Tấn công flood có tính chất lặp lại đồng dạng (hàng triệu gói tin có cùng kích thước, cùng cờ hiệu). Mô hình TinyML của AERO thực hiện suy luận trên các gói tin mẫu được nạp thành công vào hàng đợi. Các mẫu này phản ánh trọn vẹn bản chất và phân bố của toàn bộ luồng tấn công.*
  > 
  > *Nhờ cách tiếp cận này, AERO vừa bảo vệ an toàn cho chip biên, vừa không bỏ sót bất kỳ cuộc tấn công nào!"*

---

## PHẦN II: CÁC CÂU HỎI XOÁY VỀ KINH TẾ, THỊ TRƯỜNG & KHỞI NGHIỆP

---

### Câu 8: Các em đã đi khảo sát thực tế chưa hay chỉ ngồi lấy số liệu trên mạng?
* **Cạm bẫy của Giám khảo:** Thầy cô kinh tế luôn đặt câu hỏi này để "bắt bài" các đội thi sinh viên chỉ biết làm kỹ thuật trong lab mà chưa từng bước chân ra thị trường.
* **Chiến lược trả lời:** Đưa ra con số khảo sát thực tế chính xác: Địa điểm, số lượng mẫu, đối tượng tiếp xúc và các phát hiện bất ngờ từ thực tế.
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, nhóm em xác định rõ sản phẩm công nghệ chỉ có giá trị khi giải quyết đúng 'nỗi đau' của người dùng thật. Trong tháng 10/2026, nhóm đã trực tiếp thực hiện khảo sát thực địa tại **28 cơ sở kinh doanh** gồm 18 quán cà phê/nhà hàng F&B và 10 văn phòng công ty quy mô vừa và nhỏ tại khu vực quận Cầu Giấy và Đống Đa, Hà Nội.*
  > 
  > *Khảo sát thực tế mang lại cho nhóm 3 phát hiện cực kỳ giá trị:*
  > 1. *Có tới **89% (25/28 cơ sở)** từng bị sự cố mạng làm đơ máy POS tính tiền hoặc mất kết nối camera ít nhất 1 lần mỗi tháng, gây ách tắc thu ngân và mất khách vào giờ cao điểm.*
  > 2. *Gần như **100% các cơ sở** này không có nhân viên IT chuyên trách. Khi mạng hỏng, chủ quán chỉ biết khởi động lại router hoặc gọi điện cho nhà mạng và chờ đợi trong vô vọng.*
  > 3. *Đặc biệt, **93% (26/28 chủ cơ sở)** khẳng định sẵn sàng trả từ **500.000 đến 1.000.000 VNĐ mỗi tháng** nếu có một thiết bị cắm là chạy, tự động phát hiện và cảnh báo trước khi mạng bị sập.*
  > 
  > *Chính dữ liệu khảo sát thực tế này là cơ sở vững chắc để nhóm xây dựng mức giá thuê bao 550.000 VNĐ/tháng cho gói Pro."*

---

### Câu 9: Nếu các tập đoàn lớn (BKAV, Viettel, Cisco) làm thiết bị biên giá rẻ thì AERO cạnh tranh thế nào?
* **Cạm bẫy của Giám khảo:** Câu hỏi kinh điển của các nhà đầu tư mạo hiểm: "Rào cản gia nhập (Barrier to Entry) của các em là gì? Nếu ông lớn nhảy vào thì các em chết chắc?"
* **Chiến lược trả lời:** Phân tích điểm mù của các ông lớn (The Innovator's Dilemma) và 3 lớp phòng vệ độc bản của AERO.
* **Câu trả lời mẫu sắc bén:**
  > *"Em cảm ơn Thầy/Cô. Đây là câu hỏi chiến lược sống còn đối với mọi startup công nghệ. Nhóm em đã phân tích rất kỹ và tự tin bảo vệ thị phần nhờ 3 rào cản cạnh tranh (Moat):*
  > 
  > *1. **Rào cản về Mô hình kinh doanh & Chi phí vận hành (Business Model Moat):** Các tập đoàn lớn như Cisco, Fortinet hay Viettel được cấu trúc để bán các hợp đồng bảo mật dự án lớn trị giá hàng trăm triệu đến hàng tỷ đồng cho khối ngân hàng, chính phủ. Chi phí bán hàng (CAC) và bộ máy của họ quá cồng kềnh, không thể nào đi tiếp cận từng quán cà phê, cửa hàng bán lẻ để bán thiết bị 5 triệu đồng. Thị trường SME là một 'đại dương xanh' quá phân mảnh mà các ông lớn thường bỏ qua.*
  > 
  > *2. **Rào cản Kỹ thuật tối ưu hóa phần cứng biên (Deep TinyML Moat):** Phần lớn các giải pháp của ông lớn phụ thuộc vào nền tảng đám mây khổng lồ. Việc nén mô hình học máy hoạt động mượt mà trong RAM 2MB, điện năng < 2W trên vi điều khiển giá rẻ đòi hỏi kỹ thuật biên dịch C++ trần và kiến trúc firmware độc quyền mà nhóm đã mất hàng nghìn giờ nghiên cứu trong lab.*
  > 
  > *3. **Sự am hiểu thị trường bản địa:** AERO thiết kế giao diện thuần Việt, thông báo qua các kênh thân thuộc như Zalo/Telegram, tích hợp còi hú tại chỗ — giải quyết đúng thói quen vận hành của chủ kinh doanh Việt Nam mà các sản phẩm ngoại nhập không bao giờ có."*

---

### Câu 10: Nhóm toàn sinh viên kỹ thuật, làm sao tiếp cận và bán hàng cho hàng trăm doanh nghiệp (Go-To-Market)?
* **Cạm bẫy của Giám khảo:** Giám khảo kinh tế sẽ bẫy: "Sinh viên thường chỉ biết viết code, không biết bán hàng. Đi gõ cửa từng quán ăn để bán thiết bị thì bao giờ mới đạt 260 thiết bị?"
* **Chiến lược trả lời:** Khẳng định không áp dụng mô hình B2C hay bán lẻ trực tiếp gõ cửa (Direct Sales), mà áp dụng mô hình đòn bẩy **B2B2B qua Kênh Đối tác Tích hợp Hệ thống (SI) và Nhà thầu Viễn thông/CCTV (MSP)**.
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, nhóm em hoàn toàn ý thức được rằng nếu đi bán lẻ trực tiếp từng quán, chi phí tiếp cận khách hàng (CAC) sẽ ăn mòn toàn bộ lợi nhuận. Vì vậy, chiến lược Go-To-Market của AERO là mô hình **B2B2B thông qua Kênh Đối tác Phân phối (SI & MSP)**:*
  > 
  > *Tại Việt Nam hiện có hàng nghìn công ty dịch vụ tích hợp mạng, nhà thầu lắp đặt camera an ninh và đơn vị cung cấp phần mềm POS. Họ đã có sẵn mối quan hệ và quản lý hạ tầng mạng của hàng chục nghìn cửa hàng.*
  > 
  > *AERO mang đến cho các đối tác này một cơ hội kinh doanh hấp dẫn: Thay vì chỉ bán đứt camera một lần, họ có thể cài thêm AERO Edge Probe để cung cấp **Gói dịch vụ an ninh mạng định kỳ (Managed Network Service)** cho khách hàng. AERO chiết khấu 15–20% giá thiết bị và chia sẻ 20% doanh thu thuê bao trọn đời cho đối tác. Đối tác có thêm nguồn thu nhập thụ động hàng tháng, còn AERO tận dụng được toàn bộ đội ngũ bán hàng hàng nghìn người của đối tác mà không tốn chi phí cố định."*

---

### Câu 11: Tại sao khách hàng chịu trả 550.000đ/tháng? Nếu họ chỉ mua phần cứng rồi hủy thuê bao thì sao?
* **Cạm bẫy của Giám khảo:** Giám khảo muốn xoáy vào nguy cơ đứt gãy dòng tiền của mô hình Hardware-Enabled SaaS nếu khách hàng "mua đứt phần cứng rồi quỵt tiền dịch vụ".
* **Chiến lược trả lời:** Chỉ rõ sự khác biệt giá trị giữa phần cứng cơ bản và dịch vụ đám mây thông minh; định vị mức phí 550k/tháng là "chi phí bảo hiểm siêu rẻ" cho sự an tâm.
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, nếu khách hàng ngừng đóng phí thuê bao, thiết bị AERO Probe vẫn tiếp tục hoạt động cục bộ như một chiếc còi báo động đơn thuần. Tuy nhiên, khách hàng sẽ mất đi 3 giá trị sống còn nằm ở gói dịch vụ SaaS:*
  > 
  > *1. **Cập nhật Trí tuệ nhân tạo liên tục (Continuous Intelligence):** Tấn công mạng thay đổi hàng ngày. Thuê bao duy trì việc đồng bộ mô hình AI mới qua OTA từ nền tảng Digital Twin để nhận diện các biến thể mã độc và botnet mới nhất.*
  > *2. **Giám sát từ xa & Lưu trữ đám mây hợp chuẩn:** Dữ liệu cảnh báo được sao lưu an toàn 30 ngày trên Data Lake, giúp doanh nghiệp chứng minh sự tuân thủ an toàn thông tin khi cơ quan nhà nước kiểm tra theo Nghị định 13.*
  > *3. **Hỗ trợ kỹ thuật 24/7 từ chuyên gia:** Khi có còi báo động, khách hàng được đội ngũ kỹ thuật hỗ trợ cô lập sự cố từ xa.*
  > 
  > *Với mức giá **550.000 VNĐ/tháng**, tính ra chỉ **18.000 VNĐ mỗi ngày** — đúng bằng giá một ly trà đá vỉa hè. So với nguy cơ bị sập mạng mất 20 – 50 triệu tiền bán hàng trong vài giờ, mọi chủ doanh nghiệp đều coi 18.000đ này là khoản chi phí bảo hiểm rẻ nhất và đáng giá nhất trong vận hành."*

---

### Câu 12: Kêu gọi 2,5 tỷ VNĐ vốn hạt giống, số tiền này cụ thể tiêu vào đâu trong 12 tháng tới? Khi nào hòa vốn?
* **Cạm bẫy của Giám khảo:** Giám khảo nhà đầu tư kiểm tra tính kỷ luật tài chính: "Tiền xin về để làm gì? Có tiêu hoang phí không? Khi nào nhà đầu tư lấy lại vốn?"
* **Chiến lược trả lời:** Bóc tách 4 hạng mục phân bổ ngân sách chuẩn xác theo Đề án (Trang 28-29) và nêu mốc hòa vốn dựa trên số lượng thiết bị thực tế.
* **Câu trả lời mẫu sắc bén:**
  > *"Thưa Thầy/Cô và các Nhà đầu tư, số vốn 2,5 tỷ VNĐ ở vòng hạt giống được nhóm lập dự toán chi tiết cho 12 tháng tới theo nguyên tắc tiết kiệm tối đa và tập trung vào năng lực cốt lõi:*
  > 
  > 1. * **42% (~1,05 tỷ VNĐ) cho R&D Sản phẩm:** Thiết kế khuôn vỏ công nghiệp chống cháy, kiểm định đo kiểm chất lượng và chứng nhận hợp quy viễn thông tại Cục Tần số, tối ưu thuật toán TinyML.*
  > 2. * **28% (~0,70 tỷ VNĐ) cho Đội ngũ Công nghệ:** Chi trả lương bán thời gian và toàn thời gian cho 3 kỹ sư nòng cốt (nhúng, AI backend, frontend) và 1 nhân sự hỗ trợ kỹ thuật khách hàng.*
  > 3. * **20% (~0,50 tỷ VNĐ) cho Phát triển Kênh SI & Thí điểm:** Triển khai chương trình Pilot miễn phí tại 20 điểm đối tác trọng điểm, tham gia triển lãm công nghệ và tài liệu đào tạo đối tác bán hàng.*
  > 4. * **10% (~0,25 tỷ VNĐ) cho Pháp lý & Dự phòng rủi ro:** Đăng ký quyền sở hữu trí tuệ, chi phí thành lập doanh nghiệp khoa học công nghệ và quỹ an toàn.*
  > 
  > *Về điểm hòa vốn: Dự án đạt **Điểm hòa vốn vận hành hàng tháng (Operational Break-even) vào đầu Năm thứ 3**, tương ứng khi hệ thống đạt mốc **500 – 550 thiết bị** duy trì thuê bao hoạt động liên tục."*

---

### Câu 13: Tại sao quy mô thị trường lại tính bằng Tỷ USD khi khách hàng mục tiêu chỉ là quán ăn, cửa hàng?
* **Cạm bẫy của Giám khảo:** Giám khảo hỏi vặn: "Các em bán cho quán trà sữa, cửa hàng nhỏ lẻ ở Hà Nội mà dám ghi TAM hơn 4 tỷ USD, SAM 1,2 tỷ USD, có phải đang 'chém gió' số liệu của thế giới vào không?"
* **Chiến lược trả lời:** Giải thích rõ phương pháp luận bóc tách thị trường từ Quốc tế (TAM) $\rightarrow$ Khu vực & Việt Nam (SAM) $\rightarrow$ Thị phần mục tiêu cụ thể bằng tiền Việt Nam (SOM).
* **Câu trả lời mẫu sắc bén:**
  > *"Em cảm ơn Thầy/Cô đã hỏi để nhóm có cơ hội làm rõ phương pháp luận tính toán thị trường:*
  > 
  > *- **TAM (4,34 tỷ USD)** là quy mô toàn cầu của thị trường Giám sát và Phản ứng Lưu lượng mạng (Network Detection & Response - NDR) theo báo cáo chính thức của Gartner. Đây là con số định vị tiềm năng dài hạn của công nghệ Edge AI trong tương lai.*
  > 
  > *- **SAM (1,2 tỷ USD)** là phân khúc an ninh mạng dành cho SME và thiết bị IoT tại khu vực Đông Nam Á; trong đó riêng thị trường an ninh mạng Việt Nam đạt **355 triệu USD** năm 2026 với tốc độ tăng trưởng 14,5%/năm.*
  > 
  > *- Và con số sát sườn nhất của dự án chính là **SOM (3,5 – 5,0 triệu USD, tương đương khoảng 88 – 125 tỷ VNĐ)** trong vòng 3–5 năm tới tại Việt Nam:*
  > *Cơ sở tính toán của SOM rất thực tế: Việt Nam hiện có hơn 900.000 doanh nghiệp vừa và nhỏ, cùng hơn 50.000 điểm kinh doanh chuỗi F&B, bán lẻ có từ 3 chi nhánh trở lên. Mục tiêu SOM của AERO chỉ cần chiếm **1,0% – 1,5% thị phần** này, tương đương lắp đặt thành công cho **5.000 – 7.000 điểm mạng**. Con số này hoàn toàn khả thi và thực tế, không hề thổi phồng."*

---

### Câu 14: Khả năng mở rộng quy mô sản xuất phần cứng: Nếu có đơn 500 chiếc/tháng thì sản xuất thế nào?
* **Cạm bẫy của Giám khảo:** Giám khảo nghi ngờ năng lực sản xuất của sinh viên: "Bây giờ làm 1-2 cái mạch demo thì dễ, nhưng khi có hợp đồng 500 cái thì sinh viên ngồi hàn tay à? Nguồn chip lấy ở đâu?"
* **Chiến lược trả lời:** Trình bày quy trình Design for Manufacturing (DFM), hợp tác với xưởng gia công SMT chuyên nghiệp trong nước và quy trình đóng gói kiểm thử tự động.
* **Câu trả lời mẫu sắc bén:**
  > *"Dạ thưa Thầy/Cô, ngay từ giai đoạn thiết kế mạch mẫu (TRL 4), nhóm em đã tuân thủ nghiêm ngặt nguyên lý **Thiết kế để Sản xuất hàng loạt (Design for Manufacturing - DFM)**:*
  > 
  > 1. * **Lựa chọn linh kiện chuẩn hóa:** Toàn bộ linh kiện trên AERO Probe (từ chip vi điều khiển ESP32, IC nguồn hạ áp, module OLED, linh kiện thụ động) đều là linh kiện công nghiệp phổ dụng, có sẵn tại các nhà phân phối lớn với số lượng hàng chục nghìn chiếc, không bị phụ thuộc vào linh kiện độc quyền hay khan hiếm.*
  > 2. * **Gia công bằng dây chuyền SMT tự động:** Nhóm tuyệt đối không hàn tay thủ công. Thiết kế mạch đã hoàn thiện bộ file Gerber, Pick-and-Place và BOM để bàn giao cho các nhà máy gia công bo mạch SMT chuyên nghiệp tại Hà Nội (như Sao Kim, FastPCB). Các nhà máy này có năng lực xuất xưởng **500 – 1.000 bo mạch hoàn chỉnh chỉ trong 7 – 10 ngày**.*
  > 3. * **Khâu tự động hóa của nhóm:** Nhóm đã xây dựng bộ mạch Jig kiểm thử tự động (Automated Test Jig). Khi bo mạch từ xưởng về, chỉ cần đặt vào Jig là hệ thống tự động nạp firmware, kiểm tra sóng Wi-Fi, đo đạc dòng điện tiêu thụ và in mã QR xuất xưởng trong vòng **45 giây/thiết bị**."*

---

### Câu 15: Sau khi tốt nghiệp đại học, đội ngũ có cam kết tiếp tục phát triển dự án thành doanh nghiệp không?
* **Cạm bẫy của Giám khảo:** Thầy cô lo ngại đây chỉ là "dự án làm phong trào để thi lấy giải", thi xong là sinh viên giải tán đi làm thuê cho các tập đoàn lớn, không ai duy trì sản phẩm cho khách hàng.
* **Chiến lược trả lời:** Khẳng định cam kết gắn bó, định hướng thành lập Doanh nghiệp Khởi nghiệp Khoa học Công nghệ (Spin-off từ HUST) và có sự bảo trợ của phòng lab/giảng viên hướng dẫn.
* **Câu trả lời mẫu sắc bén:**
  > *"Em xin cảm ơn câu hỏi rất tâm huyết của Thầy/Cô. Chúng em xin khẳng định bằng cam kết cao nhất:*
  > 
  > *AERO không phải là một đề tài làm ra để lấy bằng khen hay tham gia phong trào rồi bỏ xó. Đây là kết quả nghiên cứu khoa học nghiêm túc suốt hơn 1 năm qua của nhóm tại phòng lab trường Đại học Bách khoa Hà Nội, dưới sự định hướng chuyên môn của các Thầy Cô bộ môn.*
  > 
  > *Kế hoạch cụ thể của nhóm sau cuộc thi:*
  > 1. *Hai thành viên nòng cốt về AI và Hệ thống nhúng của nhóm đã đăng ký học tiếp chương trình Thạc sĩ nghiên cứu tại HUST để tiếp tục phát triển sâu hơn về công nghệ Edge AI.*
  > 2. *Dự án đã có lộ trình đăng ký tham gia Vườn ươm Khởi nghiệp Đổi mới Sáng tạo của Trường và tiến tới thành lập **Doanh nghiệp Khoa học & Công nghệ (Spin-off)** vào Quý 1/2027.*
  > 3. *Nhóm đã ký thỏa thuận cam kết phân chia cổ phần và thời gian cống hiến (Vesting 3 năm), đảm bảo dự án có tính kế thừa và vận hành liên tục, đem lại giá trị thực sự cho xã hội."*

---
*Tài liệu được lưu trữ tại `docs/Câu hỏi/QUESTIONS.md` – Sử dụng làm cẩm nang ôn luyện vấn đáp cho toàn bộ thành viên đội thi.*

