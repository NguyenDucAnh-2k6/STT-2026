# Kiểm tra raw content mới — 12/10/2026, 11:48–11:52

**Phần lưu TCP payload/query/body/Info đã hoạt động và khớp PCAP.** Bốn capture Twin có 8.287 dòng qua training gate hiện tại. Đây vẫn là workload lab có nhãn tự động, không chứng minh tính đại diện hoặc khai thác attack thành công.

## Phạm vi

- Latest live session: sess_44be3e117bf844caafcead249955f32a, 188 batch tới 000187, **85.740 dòng**, packet **11:50:27.452–11:52:54.161**.
- Hai Twin thuộc khoảng session đó: Vulnerability_scanner và DDoS_UDP.
- Kiểm tra riêng hai capture có content schema mới ngay trước đó, SQLi/XSS khoảng 11:48; không gọi chúng là cùng live session.
- Đọc Parquet/PCAP; không đổi dữ liệu, nhãn hoặc model. Số liệu: scratch/collect_quality_20261012_115027.json; script scratch/audit_latest_collect.py. Không xuất payload/query/body/Info nguyên văn.

## Twin

| Scenario | Packet / dòng | TCP payload có dữ liệu | HTTP query | HTTP body | Raw Info | Qua gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQL_injection | 2.705 | 624 | 208 | 208 | 2.705 | 2.705 |
| XSS | 2.914 | 672 | 224 | 224 | 2.914 | 2.914 |
| Vulnerability_scanner | 812 | 0 | 0 | 0 | 812 | 812 |
| DDoS_UDP | 1.856 | 0 | 0 | 0 | 1.856 | 1.856 |
| **Tổng** | **8.287** | **1.296** | **432** | **432** | **8.287** | **8.287** |

Mỗi manifest COMPLETED có PCAP frame = parse = saved, reject 0. Nhãn tự động Unknown 0. Đối chiếu manifest flow/time: mismatch 0. Native TShark đọc lại mọi frame xác nhận mismatch **0** cho raw_packet_info, raw_tcp_payload_hex, raw_http_query, raw_http_body và raw_mqtt_message. Text UTF-8 encode lại khớp bytes hex, không mismatch.

SQLi có 208 request mang chữ ký SQLi, 208 HTTP response và 208 JSON body. XSS có 224 request mang chữ ký XSS, 224 response và 224 JSON body. Payload có dữ liệu đều hợp lệ hex và đúng tcp.len. Query giữ output dissector và percent encoding; body giữ nội dung trước normalization. Các giá trị absent được giữ null, không tạo body giả.

Không có dữ liệu MQTT trong bốn scenario này; cột raw_mqtt_message có mặt nhưng null là đúng với traffic quan sát. Chưa thể gọi đây là kiểm chứng capture nội dung MQTT thực.

## Live collector

- raw_packet_info có nội dung trên **85.740/85.740** dòng.
- raw_tcp_payload_hex có **42.347** dòng; raw_tcp_payload_text có **41.753** dòng.
- Decode status: not_observed 43.393; utf8_valid 41.753; encrypted_transport 496; non_utf8 98. Mismatch text/bytes **0**.
- Không có HTTP query/body trong session live 11:50–11:52; phần HTTP SQLi/XSS nằm trong capture trước đó đã kiểm tra riêng, không kết luận query/body bị mất.
- 85.740 live rows Unknown không vào supervised training. Kiểm tra coverage sequence và schema ở JSON; live không thay thế PCAP lưu đầy đủ.

## Chất lượng và giới hạn

Gate hiện nhận cả 8.287 Twin rows do schema/features và nhãn controlled_flow hợp lệ, không còn verified gate. Unknown của live vẫn bị loại.

Chưa đủ kết luận dataset production:

1. SQLi vẫn chỉ 6 mẫu request và XSS 4 mẫu, lặp. Chưa có Normal đối chứng cùng dịch vụ trong bốn capture này. Split theo session/template, không random packet để đánh giá độc lập.
2. Vulnerability_scanner hiện là port probe, không chứng minh lỗ hổng/exploit. SQLi/XSS vẫn gửi tới benign target, không thực thi nội dung chèn.
3. **Raw payload mới hiện chỉ bao phủ TCP**: DDoS_UDP không có raw_udp_payload_hex/text. Null TCP payload ở UDP là đúng, nhưng chưa đủ để dùng NLP trên payload UDP. PCAP vẫn giữ bytes UDP và là nguồn bổ sung sau này; không cần bỏ capture cũ.
4. Nội dung là field TShark theo packet/first occurrence, không bảo đảm HTTP message hoặc TCP stream đã assemble đầy đủ trong mọi môi trường. Không có decode plaintext cho TLS/QUIC.

Kết luận: raw TCP/HTTP/Info đạt yêu cầu lưu để dùng encoder sau này; cần thêm raw UDP nếu muốn phân tích nội dung UDP, và tăng diversity/Normal/session held-out trước khi đánh giá khả năng phân loại thực tế.
