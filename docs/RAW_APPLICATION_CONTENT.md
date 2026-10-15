# Raw application content dành cho NLP

Từ 12/10/2026, host TShark parser lưu nội dung thô bên cạnh 56 canonical features. Cả host live MQTT collector và Twin PCAP importer dùng cùng parser. Các trường raw không nằm trong model feature order, không được category encode/scale bởi pipeline hiện tại.

| Trường | Ý nghĩa |
| --- | --- |
| content_schema_version | Version 1 của metadata nội dung. |
| raw_tcp_payload_hex | Giữ nguyên field tcp.payload từ TShark, gồm leading zero; dùng hex để phục hồi bytes mà không mất dữ liệu nhị phân. |
| raw_tcp_payload_text | Decode UTF-8 strict, giữ nguyên whitespace/NUL/newline nếu hợp lệ. Null khi absent, non-UTF8, invalid hex hoặc transport TLS/SSL/QUIC. Không dùng replacement character làm mất bytes. |
| raw_tcp_payload_decode_status | not_observed, utf8_valid, non_utf8, invalid_hex hoặc encrypted_transport. UTF-8 hợp lệ không tự chứng minh đây là văn bản ứng dụng. |
| raw_tcp_payload_byte_count | Độ dài bytes đã decode từ hex, null khi absent/invalid. |
| raw_http_query / raw_http_uri / raw_http_method | Field HTTP do dissector trích; không strip hoặc tự URL-decode. Query giữ percent encoding theo output dissector. |
| raw_http_body | Giữ nguyên http.file_data trước normalization. Không đổi literal body 0 thành missing, không strip whitespace. |
| raw_http_body_field_type | Type của http.file_data trong registry TShark; representation là output field của dissector, không mặc định byte-exact UTF-8 cho mọi content-type. |
| raw_http_body_completeness | dissector_field_only khi có body; not_observed khi không có. Không tuyên bố luôn đầy đủ HTTP message. |
| raw_mqtt_message / raw_mqtt_topic | Giữ field mqtt.msg/topic nguyên văn theo dissector. |
| raw_mqtt_message_field_type | Type registry cho mqtt.msg; giúp chọn decoder sau này. |
| raw_packet_info | Giữ _ws.col.Info phục vụ audit; không tự render raw content bằng HTML trên dashboard. |
| content_capture_truncated | frame.cap_len < frame.len. Chỉ báo truncation của captured frame, không chứng minh body reassembly đầy đủ. |
| content_encrypted_transport | Protocol stack có tls/ssl/quic; không giả định ciphertext là plaintext. |
| content_scope | packet-fields-first-occurrence: cùng semantics -E occurrence=f của extractor. |

Empty field được lưu null trong raw metadata; literal chuỗi 0 vẫn là 0. Các canonical features cũ vẫn có sentinel 0/normalization như trước, để giữ model parity. Raw metadata là nơi lấy content cho NLP, không lấy chuỗi đã normalize/scaled rồi gọi là bytes gốc.

## Giới hạn

- Đây là nội dung đã được TShark trích trên record packet, có thể gồm field do TCP reassembly cung cấp ở một frame. Không phải bộ HTTP transaction/stream đã assemble đầy đủ cho NLP.
- Không có field HTTP không đồng nghĩa body rỗng: có thể chưa đủ segment, protocol không decode được hoặc payload mã hóa. Giữ PCAP và capture_id/sequence/timestamp/endpoints để reassemble sau này.
- HTTP binary body/encoding/content compression cần decoder phù hợp. TCP hex và PCAP là nguồn phục hồi bytes; raw_http_body chỉ bảo đảm giữ output dissector hiện có.
- Live MQTT vẫn có giới hạn JSON 1 MB và queue bounded. Thêm nội dung làm message lớn hơn; counters drop/failure vẫn phải theo dõi. Twin lưu PCAP/import batch không phụ thuộc queue packet MQTT.
- Query/body có thể chứa nội dung riêng tư; các cột raw đi cùng Parquet khi chủ động cloud sync. Không tự upload hoặc tạo log plaintext trong tính năng này.

## Sử dụng và dữ liệu cũ

Restart launcher/host/backend rồi collect phiên mới; không cần thêm flag. Raw metadata không tự thay model hoặc chạy NLP training. Khi bổ sung encoder, fit vocabulary/tokenizer chỉ trên train và split theo flow/session/template trước khi đánh giá.

Parquet cũ không được viết lại. Nếu còn PCAP, có thể trích lại vào một dataset riêng với provenance/identity rõ ràng để tránh nhân đôi sample; không tự migrate hoặc relabel trong thay đổi này.

Validation: test packet extraction → Parquet giữ unicode, tabs/newlines, whitespace, query percent encoding và literal 0; binary/TLS/missing/truncated được đánh dấu rõ. Native offline PCAP → MQTT → Parquet kiểm tra raw fields và canonical parity, không gửi attack thật.
