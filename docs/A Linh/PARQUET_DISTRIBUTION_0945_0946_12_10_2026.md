# So sánh Parquet trước 09:46 và từ 09:46 — 12/10/2026

**Hai portion tổng thể gần nhau về protocol và kích thước gói. Điều này chưa chứng minh workload Twin thực tế**, vì portion sau mốc chủ yếu vẫn là traffic loopback nền, chỉ 196 packet attributable cho Port_Scanning. Không có workload Normal HTTP được xác minh trong snapshot này.

## Phạm vi và phương pháp

Chốt inventory 92 file Parquet trong `data_lake/raw/`, chia theo **mtime của file, múi giờ Asia/Bangkok UTC+7**: trước 09:46:00 gồm 1 file 09:44 và 23 file 09:45; từ 09:46 có 68 file đến 09:48. Không file nào thay đổi trong lúc đọc. Kiểm tra thêm riêng đúng phút 09:45 để tránh ảnh hưởng file 09:44. Không sửa capture hoặc nhãn cũ.

Mtime là lúc ghi batch, không phải thời điểm từng packet. Khoảng packet thực trước mốc: 09:44:52.864–09:45:44.954; sau mốc: 09:46:24.591–09:48:00.267. Một capture PCAP sau mốc gồm packet 09:46:47.970–09:47:03.719, được ghi Parquet khi import xong.

So protocol bằng total variation (TV), feature numeric bằng khoảng cách ECDF Kolmogorov–Smirnov (KS), categorical bằng TV. Cả hai trong [0,1], 0 là phân bố quan sát giống nhau. Đây là độ lớn khác biệt, không phải p-value hoặc kiểm định độc lập: packet cùng flow tương quan mạnh. Không dùng khoảng cách nhỏ làm chứng minh workload đúng.

Script: `scratch/compare_parquet_0945_0946.py`; inventory, các distribution và đủ 56 feature distances trong `scratch/parquet_distribution_0945_0946_2026-10-12.json`.

## Kết quả tổng thể

| Đại lượng | Trước 09:46 | Từ 09:46 |
| --- | ---: | ---: |
| File | 24 | 68 |
| Dòng | 8.925 | 29.187 |
| TCP | 98,812% | 99,010% |
| TLSv1.2 | 1,188% | 0,990% |
| Endpoint hai chiều đều loopback | 100% | 100% |
| Frame median | 45 byte | 44 byte |
| Frame p95 | 45 byte | 45 byte |
| TCP payload khác 0, tính trên mọi dòng | 49,938% | 49,690% |
| TCP payload p95 | 1 byte | 1 byte |
| Top 3 nhóm endpoint có hướng | 49,479% | 49,457% |
| Features hằng số | 45/56 | 42/56 |
| Malformed / duplicate packet ID | 0 / 0 | 0 / 0 |
| Verified label | 0 | 0 |

**Protocol TV = 0,001975**, chỉ khoảng 0,198 điểm phần trăm phần khối lượng cần chuyển giữa bins. **Frame-size KS = 0,002105**, khác tối đa khoảng 0,210 điểm phần trăm trên CDF. Chỉ dùng các file đúng phút 09:45 thì protocol TV = 0,001480, kết luận gần nhau không thay đổi. Hai portion đều loopback; đây không phải phép so với Wi-Fi.

Trong 56 canonical features, **42 có empirical distribution giống hệt**. Một số khoảng cách lớn:

| Feature | KS/TV |
| --- | ---: |
| tcp.srcport | 0,346 KS |
| tcp.dstport | 0,344 KS |
| tcp.ack_raw | 0,326 KS |
| tcp.checksum | 0,309 KS |
| tcp.ack | 0,136 KS |
| tcp.seq | 0,130 KS |
| tcp.payload | 0,0154 TV |
| tcp.len | 0,00248 KS |
| tcp.flags | 0,00172 KS |

Port/sequence/ACK raw/checksum có thể thay mạnh giữa các phiên do endpoint ephemeral, TCP state và dữ liệu cụ thể. Không dùng KS của checksum hoặc số port để kết luận attack phi thực tế. Phần lớn features protocol khác đều bằng 0 ở cả hai portion, làm similarity tổng thể cao nhưng không cung cấp coverage IoT.

## Tách nguồn trong portion sau mốc

| Nguồn | Dòng | TCP | TV protocol so baseline | KS frame so baseline |
| --- | ---: | ---: | ---: | ---: |
| Collector live, backend tshark | 15.767 | 98,947% | 0,00135 | 0,00146 |
| Importer Twin, backend pcap | 13.420 | 99,083% | 0,00271 | 0,00363 |

Không so số dòng 8.925 với 29.187 như throughput vì thời lượng khác và phần sau trộn live với PCAP. Live chỉ lưu **16,16% trước / 15,97% sau** sequence span quan sát; đây là coverage của pipeline nhận/lưu, không đo kernel loss. PCAP Twin nhập đủ 13.420 packet theo manifest, sequence coverage 100%. Không trộn coverage hai nguồn thành kết luận loss chung.

Packet ID không overlap giữa hai portion. Tuy vậy live/PCAP sau mốc là hai capture có thể quan sát cùng traffic, nên packet ID khác không chứng minh mọi observation độc lập hoặc không có duplicate packet trên dây.

## Workload Twin thực sự là gì?

Manifest `d49af70886804d3fbbb666ed2313aa97`:

- Scenario **Port_Scanning**, thời lượng 15 giây, 28 recorded socket flows tới localhost cổng 8088.
- 13.420 packet PCAP = parsed = saved; **196 packet có nhãn requested Port_Scanning**, 13.224 Unknown; 0 verified.
- **98,54% capture Twin là Unknown**, không có attribution cho workload đã chọn. Không tự coi đó là attack; capture Port_Scanning hiện dùng filter loopback rộng, chứa nhiều ứng dụng nền.
- Trước mốc không có packet cổng 8088. Sau mốc có 196 trong importer và 37 trong collector live. Giữ riêng các nguồn, không cộng làm số packet độc lập của attack.

Riêng 196 packet attributable:

| Đại lượng | Loopback baseline | Port_Scanning attributable |
| --- | ---: | ---: |
| TCP | 98,812% | 100% |
| Payload TCP khác 0 | 49,938% | 0% |
| Frame median / p95 | 45 / 45 byte | 44 / 56 byte |
| Frame-size KS so baseline | — | **0,2714** |

Workload riêng **khác baseline**, phù hợp việc một TCP connect probe tạo handshake/close/control packet không payload, trong khi traffic nền có nhiều segment 1 byte. Khác biệt Normal-versus-probe là điều mong đợi; không phải bằng chứng đủ để gọi probe phi thực tế. Nhưng code chỉ probe **một cổng**, nên chưa tái hiện port scan nhiều cổng/host hoặc attack chuẩn benchmark; nhãn vẫn unverified là hợp lý.

## Kết luận và bước so sánh đúng

1. Không thấy thay đổi lớn của distribution tổng thể khi bật --twin-lab trong snapshot này. Traffic loopback nền chi phối phép so, không chứng minh generator realistic.
2. Baseline mang nhãn Unknown, không có cổng lab 8088, không phải một thí nghiệm Normal HTTP đã xác minh. Cả hai phần đều loopback, chưa có Wi-Fi comparison.
3. Workload thực chỉ 196 packet Port_Scanning. Tách capture attributable khỏi background để đánh giá; không gán lại toàn bộ Unknown theo nút UI.
4. Muốn so tính thực tế: chạy cùng ứng dụng/dịch vụ và hành động normal/probe trong lab đối chứng, thu cùng filter và capture backend, cùng thời lượng, so số flow, tỷ lệ SYN/SYNACK/ACK/FIN/RST, payload, IAT/RTT và kết quả dịch vụ. Sau đó mới so loopback với VM/LAN/Wi-Fi theo cùng workload; khác biệt link-layer vẫn cần giữ provenance.
5. Chưa concat hai portion cho supervised training: cả hai có **0 verified labels**, thiếu ground truth và không độc lập theo packet.

Không chạy thêm generator, không retrain và không thay nhãn dữ liệu trong khảo sát này.
