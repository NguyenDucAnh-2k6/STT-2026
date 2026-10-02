# Phản biện Kinh tế & Thương mại đề án AERO

## Nhận định giám khảo

AERO có **logic sản phẩm tốt nhưng mô hình tài chính hiện chưa đủ độ tin cậy để gọi là “sẵn sàng thương mại hóa”**. Điểm mạnh là mô hình bán thiết bị kết hợp thuê bao định kỳ, giá tiếp cận được và giải quyết đúng khoảng trống của tổ chức không đủ nguồn lực vận hành SOC; điểm yếu quyết định là TAM–SAM–SOM chưa được chứng minh bằng dữ liệu mua thực tế, dòng tiền bỏ sót hoặc phân loại sai CAPEX, LTV chưa điều chỉnh đúng theo churn và lợi ích “xanh” chưa được lượng hóa.

**Chấm điểm kinh tế đề xuất: 5,8/10.** Đây là mức “có tiềm năng, đáng cho thử nghiệm/pilot có điều kiện”, chưa phải mức có thể tin ngay vào dự báo hòa vốn.

## Số liệu nền của đề án

| Hạng mục                        |                                                Số liệu AERO đưa ra | Nhận xét sơ bộ                                                                                                               |
| ------------------------------- | -----------------------------------------------------------------: | ---------------------------------------------------------------------------------------------------------------------------- |
| Giá thiết bị                    |                            4,5–6 triệu đồng; trung bình 5,25 triệu | Phù hợp để giảm rào cản mua ban đầu                                                                                          |
| Thuê bao                        | Basic 300.000; Pro 550.000; Enterprise 800.000 đồng/thiết bị/tháng | Có phân tầng nhưng chưa chứng minh mức sẵn sàng trả                                                                          |
| Biên gộp phần cứng              |                                           15–20%; trung bình 17,5% | Quá mỏng nếu bán qua đối tác và có bảo hành tại chỗ                                                                          |
| Biên gộp dịch vụ                |                                             55–65%; trung bình 60% | Có thể hấp dẫn, nhưng chưa có bảng cost-to-serve                                                                             |
| CAPEX ban đầu                   |                                                 500–800 triệu đồng | Chưa có bảng phân rã và mốc giải ngân                                                                                        |
| CAPEX mở rộng                   |                                                 300–500 triệu đồng | Chưa được phản ánh rõ trong dòng tiền 3 năm                                                                                  |
| OPEX giai đoạn đầu              |                                             60–80 triệu đồng/tháng | Có dấu hiệu thiếu chi phí nhân sự, bán hàng, tuân thủ và hỗ trợ                                                              |
| Doanh thu năm 1/2/3             |                                 380 triệu / 1,94 tỷ / 5,36 tỷ đồng | Tăng rất nhanh nhưng chưa có phễu bán hàng để chứng minh                                                                     |
| Dòng tiền lũy kế cuối năm 1/2/3 |                          -600 triệu / -890 triệu / +610 triệu đồng | Mâu thuẫn với CAPEX công bố và thời điểm hòa vốn                                                                             |
| LTV:CAC công bố                 |                                                              2,9:1 | Dưới mốc 3:1 thường được dùng như chuẩn tham chiếu; quan trọng hơn, phép tính chưa phản ánh churn đã nêu trong đề án[^1][^2] |

## Mô hình và thị trường

### Điểm hợp lý

Mô hình **hardware-enabled subscription** là lựa chọn đúng hướng: thiết bị tạo “điểm đặt chân” trong hạ tầng khách hàng, còn dashboard, cập nhật mô hình, lịch sử cảnh báo và hỗ trợ tạo doanh thu định kỳ. Cấu trúc này cũng tạo switching cost tự nhiên nếu AERO thực sự tích lũy baseline, chính sách và lịch sử cảnh báo riêng cho từng điểm mạng.

Nhu cầu thị trường là có thật: khảo sát tại Việt Nam trên hơn 500 lãnh đạo công nghệ cho thấy 42,1% tổ chức thiếu ngân sách và 38,4% thiếu chuyên môn để vận hành bảo mật hiệu quả; đây vừa là cơ hội cho sản phẩm “cắm là chạy”, vừa là cảnh báo rằng khách hàng mục tiêu rất nhạy cảm về giá. Các SME cũng thường đầu tư an ninh mạng ở mức thấp và phản ứng sau khi sự cố xảy ra, nên “có nỗi đau” không tự động đồng nghĩa với “sẵn sàng mua ngay”.[^3][^4]

### Lỗ hổng thị trường

**Chân dung khách hàng đang bị chia đôi.** Phần đầu đề án hướng tới ngân hàng, tài chính, viễn thông, công nghiệp và tổ chức vừa–lớn có CIO/CISO; phần thương mại lại hướng tới SME, trường học, phòng lab và đơn vị chưa có SOC. Hai nhóm có quy trình mua, yêu cầu SLA, chứng nhận, ngân sách và chu kỳ bán hàng hoàn toàn khác nhau; cùng một gói Enterprise 800.000 đồng/tháng khó đáp ứng kỳ vọng của ngân hàng nhưng có thể vẫn cao với trường học nhỏ.

**TAM 900 tỷ, SAM 180 tỷ và SOM 3–5 tỷ đồng chưa có “cầu nối dữ liệu”.** Con số khoảng 940.000 doanh nghiệp phù hợp với mốc cuối năm 2024, trong khi đến cuối năm 2025 số doanh nghiệp hoạt động đã vượt một triệu; tuy vậy, cập nhật mẫu số không giải quyết được vấn đề cốt lõi là chưa chứng minh vì sao chỉ 55.000–65.000 tổ chức có hạ tầng phù hợp và mức chi tiêu bình quân lấy từ đâu. TAM cần được tính từ số **điểm mạng đủ điều kiện × tỷ lệ có nhu cầu × tỷ lệ sẵn sàng trả × doanh thu bình quân**, không nên lấy tổng số doanh nghiệp rồi lọc bằng tỷ lệ nội bộ chưa khảo sát.[^5][^6]

**Đơn vị đo đang lẫn giữa “doanh nghiệp”, “khách hàng”, “điểm mạng” và “thiết bị”.** Dự báo bán 700 thiết bị không cho biết đó là 700 khách hàng hay 70 khách hàng có 10 chi nhánh; sự khác biệt này làm thay đổi CAC, chi phí triển khai, churn, doanh thu tài khoản và quy mô SOM.

**Đối thủ bị đóng khung quá hẹp vào sản phẩm thương mại tập trung.** Suricata là công cụ IDS/IPS và giám sát mạng mã nguồn mở; Zeek là nền tảng phân tích lưu lượng thời gian thực chạy được trên phần cứng phổ thông; Wazuh cung cấp XDR/SIEM mã nguồn mở không có phí giấy phép. Vì vậy, AERO không thể chỉ bán thông điệp “rẻ hơn Darktrace/Vectra”; lợi thế phải là tổng chi phí sở hữu thấp hơn một cấu hình mini-PC + Suricata/Zeek/Wazuh, nhờ triển khai nhanh, AI cục bộ, ít cảnh báo giả, quản trị OTA và hỗ trợ tiếng Việt.[^7][^8][^9]

## Tính khả thi tài chính

### Unit economics

Phép tính phần cứng của đề án là đúng về số học: với giá 5,25 triệu và biên gộp 17,5%, giá vốn khoảng 4,33 triệu, lợi nhuận gộp khoảng 0,92 triệu đồng. Gói Pro tạo lợi nhuận gộp dịch vụ khoảng 330.000 đồng/tháng nếu biên dịch vụ 60% là đúng.

Tuy nhiên, LTV 8,84 triệu đồng được tính như thể mọi khách hàng đều trả đủ 24 tháng. Nếu áp dụng chính giả định churn của đề án — 3%/tháng trong 12 tháng đầu và 1,2%/tháng trong 12 tháng sau — retention cuối tháng 24 chỉ khoảng:

\[
(1-0,03)^{12}\times(1-0,012)^{12}\approx 60\%
\]

Số tháng thuê bao kỳ vọng trong 24 tháng vào khoảng 18 tháng, không phải 24 tháng. Khi đó, LTV lợi nhuận gộp hợp lý hơn là khoảng:

\[
0,92 + 0,33\times18 = 6,86\text{ triệu đồng}
\]

Với CAC 3 triệu đồng, **LTV:CAC điều chỉnh chỉ khoảng 2,29:1**, thấp đáng kể so với 2,9:1 công bố và dưới mốc tham chiếu 3:1. Chưa kể CAC 3 triệu mới lấy ngân sách marketing chia số khách dự kiến, chưa bao gồm đầy đủ lương sales, presales, demo, thiết bị pilot, đi lại, hồ sơ thầu và thời gian của đội sáng lập.[^1][^2]

### Dòng tiền và hòa vốn

Bảng năm 1 cho doanh thu 380 triệu, COGS+OPEX 980 triệu và dòng tiền -600 triệu; ba số này khớp chính xác, cho thấy CAPEX 500–800 triệu chưa được cộng vào dòng tiền, dù phần diễn giải lại nói năm 1 là giai đoạn đầu tư CAPEX. Nếu bổ sung CAPEX ban đầu, dòng tiền năm 1 phải âm khoảng **1,1–1,4 tỷ đồng**, không phải 600 triệu.

Nếu CAPEX mở rộng 300–500 triệu được chi trong năm 2 cùng khoản lỗ vận hành 290 triệu, đáy dòng tiền lũy kế có thể ở khoảng **-1,69 đến -2,19 tỷ đồng**, trước dự phòng. Vì vậy, tuyên bố chỉ cần 900 triệu–1 tỷ đồng để qua đáy là không an toàn; cần một mô hình dòng tiền theo tháng, thể hiện rõ tồn kho, đặt cọc linh kiện, VAT, công nợ B2B và lịch thanh toán của khách hàng.

Thời điểm hòa vốn cũng bị dùng lẫn hai khái niệm. Với dòng tiền lũy kế cuối năm 2 là -890 triệu và dòng tiền năm 3 là +1,5 tỷ, nếu dòng tiền phân bổ tương đối đều thì **hòa vốn tiền mặt xảy ra khoảng tháng thứ 7 của năm 3, tức gần quý III**, không phải quý I. Quý I năm 3 chỉ có thể là hòa vốn vận hành theo tháng/quý; đề án phải tách rõ “operating break-even” và “cumulative cash break-even”.

### Chi phí còn thiếu

- **Nhân sự đầy đủ:** lương kỹ sư AI/backend/frontend/firmware, QA, DevSecOps, presales, sales, customer success, hỗ trợ ngoài giờ, bảo hiểm và thuế lao động.
- **Triển khai và hậu mãi:** khảo sát mạng, lắp đặt, cấu hình mirror/TAP, đi lại, đào tạo, đổi trả/RMA, thiết bị dự phòng, bảo hành và xử lý cảnh báo giả.
- **Kênh B2B2C:** hoa hồng, chiết khấu nhà phân phối, hỗ trợ kỹ thuật cho đối tác và marketing development fund. Ví dụ, chỉ 10% chiết khấu trên giá thiết bị 5,25 triệu đã lấy đi 525.000 đồng, khiến lãi gộp phần cứng giảm từ khoảng 920.000 xuống 395.000 đồng trước bảo hành.
- **Cloud và dữ liệu:** lưu trữ log, băng thông, monitoring, backup, threat-intelligence feed, huấn luyện lại mô hình, OTA, ký mã phần mềm và phản ứng sự cố cho chính nền tảng AERO.
- **Tuân thủ và pháp lý:** hợp đồng xử lý dữ liệu, kiểm thử xâm nhập độc lập, hồ sơ đánh giá tác động, tư vấn pháp lý, bảo hiểm trách nhiệm công nghệ và chi phí ứng phó vi phạm. Nghị định 13 yêu cầu bên xử lý/kiểm soát dữ liệu áp dụng biện pháp bảo vệ, chứng minh tuân thủ và lập hồ sơ đánh giá tác động từ khi bắt đầu xử lý dữ liệu cá nhân.[^10][^11]
- **Vốn lưu động phần cứng:** MOQ, biến động tỷ giá/giá chip, vận chuyển, thuế nhập khẩu, tồn kho chậm luân chuyển, linh kiện lỗi thời và chênh lệch giữa trả tiền nhà cung cấp với thu tiền khách hàng.

## Bài toán chi phí xanh

AERO hiện chưa chứng minh được “green premium”; thực tế chiến lược tốt hơn là tạo **green discount** — vừa giảm truyền dữ liệu và cloud, vừa giảm tổng chi phí sở hữu. Edge AI có cơ sở kỹ thuật để giảm độ trễ, băng thông và mức phơi lộ dữ liệu nhờ xử lý gần nguồn.[^12][^13]

Tuy nhiên, edge không tự động đồng nghĩa với xanh: nó chuyển một phần năng lượng từ truyền dẫn/cloud sang thiết bị chạy liên tục tại từng điểm mạng, đồng thời phát sinh phần cứng và rác thải điện tử; các nghiên cứu nhấn mạnh phải đo đồng thời năng lượng tính toán cục bộ và phần truyền dẫn/cloud tránh được. Đề án hiện thiếu công suất thiết bị, điện năng theo năm, dữ liệu truyền tránh được, thời gian sử dụng, phương án sửa chữa/tái sử dụng và phát thải vòng đời.[^14][^15]

Bộ chỉ số tối thiểu cần đưa vào pilot:

| Chỉ số                  | Cách chứng minh                                                          |
| ----------------------- | ------------------------------------------------------------------------ |
| Điện năng edge          | Đo watt trung bình và kWh/điểm/năm trong tải thật                        |
| Băng thông tránh truyền | So sánh GB/tháng giữa raw traffic tập trung và chỉ gửi metadata/cảnh báo |
| Cloud tránh dùng        | So sánh compute, storage và log-retention trước/sau triển khai           |
| TCO 3 năm               | Thiết bị + thuê bao + điện + triển khai + nhân công vận hành             |
| Tác động vòng đời       | Tuổi thọ thiết bị, tỷ lệ sửa chữa, tái sử dụng và thu hồi cuối vòng đời  |
| Green payback           | Thời gian để khoản tiết kiệm cloud/băng thông/điện bù chi phí thiết bị   |

Khách hàng không nên bị yêu cầu trả cao hơn chỉ vì nhãn “xanh”. Thông điệp bán hàng nên là: **TCO thấp hơn, dữ liệu ở lại tại chỗ, hoạt động khi mất Internet và giảm tải cloud**; lợi ích xanh là kết quả được đo lường, không phải khẩu hiệu.

## Khả năng mở rộng

Phần mềm và mô hình AI có thể scale, nhưng hoạt động kinh doanh hiện vẫn mang tính dịch vụ tại chỗ. Mỗi thiết bị mới có thể đòi hỏi khảo sát topology, cấu hình switch, tinh chỉnh ngưỡng và xử lý false positive; nếu chưa có zero-touch provisioning, fleet management, OTA an toàn và playbook hỗ trợ đối tác, số lượng ticket có thể tăng gần tuyến tính với số thiết bị.

Biên phần cứng 15–20% không đủ hấp thụ đồng thời chiết khấu kênh, bảo hành, hàng lỗi và biến động linh kiện. Cách scale phù hợp hơn là thuê ODM/EMS lắp ráp theo lô, chuẩn hóa 1–2 SKU, yêu cầu khách hàng trả trước phần cứng và dùng đối tác cho triển khai cấp 1; AERO giữ lại AI, cloud control plane, bản quyền phần mềm và hỗ trợ cấp 2/3.

### Rủi ro có thể làm dự án phá sản

| Rủi ro                         | Mức độ         | Cơ chế gây thiệt hại                                        | Chỉ báo phải theo dõi                                    |
| ------------------------------ | -------------- | ----------------------------------------------------------- | -------------------------------------------------------- |
| Không đạt product–market fit   | Rất cao        | Pilot miễn phí nhưng không chuyển đổi trả phí               | Tỷ lệ pilot-to-paid, lý do từ chối mua                   |
| False positive/missed attack   | Rất cao        | Churn, SLA credit, mất uy tín hoặc trách nhiệm pháp lý      | Precision, recall, cảnh báo hữu ích/100 cảnh báo         |
| CAC và chu kỳ bán hàng cao     | Cao            | Cạn tiền trước khi có đủ thuê bao                           | CAC fully loaded, sales cycle, win rate                  |
| Biên phần cứng bị bào mòn      | Cao            | Hoa hồng, bảo hành và giá chip làm mỗi thiết bị lỗ          | Contribution margin sau kênh và RMA                      |
| Churn cao hơn dự kiến          | Cao            | LTV giảm mạnh, không hoàn vốn CAC                           | Logo churn, device churn, net revenue retention          |
| Thiếu vốn lưu động             | Cao            | Phải trả linh kiện trước, thu tiền B2B sau                  | Cash conversion cycle, tồn kho, công nợ                  |
| Sự cố bảo mật của AERO         | Rất cao        | Thiết bị bảo mật trở thành điểm xâm nhập                    | Thời gian vá lỗi, tỷ lệ cập nhật OTA, pentest findings   |
| Không đáp ứng tuân thủ/mua sắm | Trung bình–cao | Không qua thẩm định của trường, ngân hàng, doanh nghiệp lớn | Thời gian hoàn tất hồ sơ, số deal bị chặn bởi compliance |

## Điểm mạnh kinh tế

- **Doanh thu lai hợp lý:** thiết bị tạo doanh thu ban đầu, subscription tạo dòng tiền lặp lại và cơ sở tăng LTV.
- **Giá đầu vào thấp và giá trị vận hành rõ:** AERO có cơ hội phù hợp với SME/trường học thiếu ngân sách và nhân lực chuyên trách, đúng với khoảng trống đang tồn tại tại Việt Nam.[^4][^3]
- **Edge tạo khác biệt có thể thương mại hóa:** xử lý tại chỗ có thể giảm độ trễ, truyền dữ liệu và phụ thuộc cloud; nếu đo được TCO và điện năng, “xanh” sẽ trở thành lợi thế chi phí thay vì chi phí cộng thêm.[^12][^14]

## Lỗ hổng tài chính

- **LTV 2,9:1 bị thổi phồng:** dùng đủ 24 tháng thuê bao nhưng đồng thời giả định có churn; điều chỉnh theo churn hai giai đoạn đưa LTV:CAC xuống khoảng 2,29:1.
- **Nhu cầu vốn bị đánh giá thiếu:** bảng dòng tiền khớp doanh thu trừ COGS+OPEX nhưng chưa phản ánh nhất quán 500–800 triệu CAPEX ban đầu và 300–500 triệu CAPEX mở rộng.
- **Hòa vốn quý I năm 3 không khớp bảng:** dữ liệu năm cho thấy hòa vốn tiền mặt gần quý III nếu không có lịch dòng tiền chi tiết chứng minh khác.
- **TAM/SAM/SOM chưa kiểm chứng:** chưa có khảo sát willingness-to-pay, số điểm mạng, tỷ lệ chuyển đổi và ACV theo phân khúc; con số doanh nghiệp toàn quốc không đủ làm bằng chứng thị trường.
- **Biên phần cứng 15–20% quá mong manh:** chưa trừ hoa hồng đối tác, lắp đặt, đổi trả, bảo hành, thiết bị pilot và vốn tồn kho.
- **“Xanh” chưa có kế toán tác động:** không có kWh, GB tránh truyền, chi phí cloud tránh được, tuổi thọ hay rác thải điện tử; chưa thể kết luận tổng tác động môi trường dương.

## Câu hỏi phản biện

1. **“Bảng của đội cho thấy 380 triệu doanh thu trừ 980 triệu COGS+OPEX đúng bằng âm 600 triệu, vậy 500–800 triệu CAPEX ban đầu nằm ở đâu? Nếu cộng cả CAPEX mở rộng, số vốn tối thiểu để không đứt tiền mặt là bao nhiêu theo từng tháng?”** Đội phải mang bảng cash flow 36 tháng và chứng minh đáy tiền mặt, không trả lời bằng doanh thu hoặc lợi nhuận kế toán.

2. **“Đội công bố churn 3%/tháng năm đầu và 1,2%/tháng năm sau nhưng LTV lại nhân đủ 24 tháng. Khi điều chỉnh theo xác suất sống sót, LTV:CAC còn khoảng 2,29:1; vậy ở mức churn/CAC nào mô hình bắt đầu không hoàn vốn?”** Đội cần trình bày sensitivity matrix theo churn, CAC và biên dịch vụ.

3. **“Tại sao khách hàng trả 5,25 triệu thiết bị cộng 550.000 đồng/tháng cho AERO thay vì dùng mini-PC với Suricata/Zeek/Wazuh miễn phí bản quyền, hoặc nâng cấp firewall sẵn có? Hãy chứng minh bằng TCO 3 năm, tỷ lệ cảnh báo hữu ích và số giờ nhân sự vận hành tiết kiệm được.”** Suricata, Zeek và Wazuh đều là đối thủ thay thế mã nguồn mở thực tế, không thể bỏ qua.[^8][^9][^7]

## Giải pháp tối ưu hóa

### Chuẩn hóa unit economics

Trong 4–6 tháng pilot, theo dõi theo **account–site–device**, không gộp ba đơn vị này. Báo cáo tối thiểu gồm CAC fully loaded, số thiết bị/tài khoản, gross margin sau kênh và bảo hành, pilot-to-paid, churn theo cohort, ticket/thiết bị/tháng, thời gian triển khai và số tháng hoàn vốn; chỉ scale khi LTV:CAC điều chỉnh churn đạt ít nhất 3:1 và CAC payback dưới 12 tháng.[^2][^1]

### Thu hẹp beachhead

Chọn một phân khúc đầu tiên, đề xuất **trường đại học/phòng lab và SME công nghệ có 2–10 điểm mạng tại Hà Nội**, vì dễ tiếp cận, chu kỳ mua ngắn hơn ngân hàng và có môi trường thử nghiệm. Thiết kế một gói duy nhất trong pilot: thiết bị đặt cọc hoặc trả trước, Pro theo năm có chiết khấu, phạm vi SLA rõ; hoãn “Enterprise” đến khi có đội hỗ trợ và chứng nhận phù hợp.

### Chuyển xanh thành TCO

Thực hiện thử nghiệm A/B tại ít nhất 3 môi trường: đo công suất edge, GB dữ liệu tránh truyền, cloud/storage tránh dùng, số giờ vận hành và chất lượng phát hiện. Từ đó xuất bản bảng **TCO + Green ROI 3 năm**; nếu tổng điện năng không giảm, không quảng bá “tiết kiệm năng lượng”, mà tập trung vào riêng tư, độ trễ, khả năng hoạt động offline và giảm băng thông.

## Bảng điểm

| Tiêu chí                        |       Điểm | Nhận xét                                                                  |
| ------------------------------- | ---------: | ------------------------------------------------------------------------- |
| Mô hình kinh doanh & thị trường |    1,7/2,5 | Mô hình lai tốt, nhưng phân khúc và TAM chưa đủ bằng chứng                |
| Tính khả thi tài chính          |    1,1/2,5 | Có unit economics ban đầu nhưng sai lệch LTV, CAPEX và hòa vốn            |
| Bài toán chi phí xanh           |    1,1/2,0 | Có logic giảm truyền dữ liệu, chưa đo TCO hay tác động vòng đời           |
| Mở rộng & quản trị rủi ro       |    1,9/3,0 | Có tiềm năng scale phần mềm, nhưng phần cứng, hỗ trợ và tuân thủ còn nặng |
| **Tổng**                        | **5,8/10** | **Đáng pilot có điều kiện; chưa đủ cơ sở gọi vốn theo dự báo hiện tại**   |

---

## References

1. [LTV/CAC Ratio: Meaning, Formula & Importance](https://www.gilion.com/basics/ltv-cac-ratio) - CAC is the amount of money you spend to acquire a new customer, while LTV is the total value of all ...

2. [LTV:CAC Ratio: what it is and how to calculate it](https://www.klipfolio.com/kpis/saas/customer-lifetime-value-to-customer-acquisition-cost) - The LTV:CAC Ratio compares the lifetime value of a customer to what it cost to acquire them. Divide ...

3. [Vietnam Enterprise Cybersecurity Landscape 2026 | VNETWORK](https://www.vnetwork.vn/en-US/bao-cao-toan-canh-an-ninh-mang-doanh-nghiep-viet-nam-2026/) - Vietnamese businesses are spending on cybersecurity — but only 1 in 3 is truly protected. Download t...

4. [SMEs urged to bolster cybersecurity capacity for safe, ...](https://vietnamnet.vn/en/smes-urged-to-bolster-cybersecurity-capacity-for-safe-trusted-digital-growth-2507076.html) - A report by the National Cybersecurity Association showed a worrying surge in cyberattacks in 2025, ...

5. [Doanh nhân Việt trên hành trình kinh doanh có trách nhiệm](https://congthuong.vn/doanh-nhan-viet-tren-hanh-trinh-kinh-doanh-co-trach-nhiem-425060.html) - Nhân ngày Doanh nhân Việt Nam, ông Nguyễn Quang Vinh - Phó Chủ tịch VCCI đã chia sẻ với phóng viên B...

6. [Bức tranh phát triển doanh nghiệp Việt Nam năm 2025](https://www.nso.gov.vn/du-lieu-va-so-lieu-thong-ke/2026/01/buc-tranh-phat-trien-doanh-nghiep-viet-nam-nam-2025/) - Năm 2025 là năm có ý nghĩa quan trọng trong quá trình phát triển kinh tế - xã hội Việt Nam, đánh dấu...

7. [Suricata: Home](https://suricata.io/) - Suricata is a high performance, open source network analysis and threat detection software used by m...

8. [Zeek: The Open Source Network Monitor](https://zeek.org/) - The Open Source Network Monitor Flexible, scriptable, and powered by defenders ... The world's leadi...

9. [Wazuh - Open Source XDR. Open Source SIEM.](https://wazuh.com/) - Wazuh is a free and open source security platform that unifies XDR and SIEM protection for endpoints...

10. [TOÀN VĂN: Nghị định 13/2023/NĐ-CP bảo vệ dữ liệu cá nhân](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-dinh-13-2023-nd-cp-bao-ve-du-lieu-ca-nhan-119230516104357809.htm) - Toàn văn Nghị định 13/2023/NĐ-CP ngày 17/4/2023 của Chính phủ bảo vệ dữ liệu cá nhân.

11. [Nghị định số 13/2023/NĐ-CP của Chính phủ: Bảo vệ dữ liệu cá nhân](https://vanban.chinhphu.vn/?pageid=27160&docid=207759) - Nghị định số 13/2023/NĐ-CP của Chính phủ: Bảo vệ dữ liệu cá nhân

12. [Edge Artificial Intelligence: A Systematic Review of ...](https://arxiv.org/html/2510.01439v1)

13. [Edge AI for Internet of Energy: Challenges and Perspectives](https://arxiv.org/html/2311.16851)

14. [Type of the Paper (Article](https://arxiv.org/pdf/2608.04499v1.pdf)

15. [[PDF] Carbon-Aware Resource Management in Cloud, Edge, and AI ...](https://www.jier.org/index.php/journal/article/download/4449/3477/7800)
