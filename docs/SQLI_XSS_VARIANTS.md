# SQLi/XSS: không gian request theo grammar cho lab

## Thay đổi

Danh sách 6 SQLi / 4 XSS cố định được thay bằng HttpVariantGenerator (firmware/simulator/http_variants.py), version http-grammar-v1. Mỗi lớp có 8 family, cùng pool 8 endpoint/8 parameter và 2 User-Agent, GET query/POST form/POST JSON. Content-Length dùng độ dài bytes thật; query/form URL encode chuẩn, JSON UTF-8. Không chỉ nối nonce vào request cũ: thay cả expression/markup/context và vị trí nội dung.

SQLi families: quoted_boolean, numeric_boolean, union_constants (projection 2–6 cột constant), stacked_select, exists_constant, like_expression, case_expression, arithmetic_boolean. Thay identifier/string/number/quote và cấu trúc theo grammar. Đây là mẫu cú pháp cho lab, không đảm bảo đúng mọi SQL dialect hoặc phù hợp mọi vị trí injection.

XSS families: script, image_event, svg_event, focus_event, toggle_event, load_event, javascript_uri, attribute_context. Nội dung thử alert, không gửi dữ liệu/cookie ra ngoài. Attribute escaping giữ markup/JS quoting theo ngữ cảnh. Chưa có vulnerable app/browser execution để xác minh reflected/stored/DOM XSS.

Target Twin vẫn localhost/cổng lab, filter service port, count 8 request mỗi burst và thời lượng 1–60 giây. Không tăng flood rate chỉ để tăng số mẫu. Benign HTTP target đọc request nhưng không thực thi query/script; nhãn tự động vẫn theo attributable flow, không theo kết quả exploit.

## Seed và provenance

Tùy chọn .env: TWIN_VARIATION_SEED=42. Không cần thêm nếu dùng default. Actual 32-bit seed được derive từ base seed + experiment ID; mỗi experiment có bộ biến thể khác nhau. Manifest lưu actual seed, version, generated_requests (số đã sinh/attempt, không phải số exploit thành công), family/placement counts. Seed đủ chính xác khi đi qua JSON/browser.

Generator duy trì state xuyên suốt experiment; burst sau không reset về chuỗi đầu. Muốn replay nội dung offline, tạo HttpVariantGenerator bằng manifest request_generator.seed rồi gọi next(scenario) theo đúng thứ tự và số generated_requests. Version source phải khớp. Replay không bảo đảm cùng timing/packet segmentation.

Flow manifest và packet Parquet có:

- request_variant_id: hash URI/body của request;
- request_template_family, request_placement, request_method;
- request_generator_version.

Các trường là metadata phục vụ audit/group split, **không đưa vào classifier/NLP input**, vì family trực tiếp gắn với loại scenario. Nhãn, nguồn và schema packet hiện có được giữ. Actual raw payload/query/body vẫn là nơi lấy nội dung cho encoder.

## Giảm shortcut và đánh giá

SQLi/XSS và Normal dùng cùng pool User-Agent; bỏ Sqlmap cố định dành riêng cho SQLi. SQLi/XSS dùng cùng pool path/parameter để giảm shortcut theo endpoint. Điều này không loại bỏ mọi bias: Normal hiện vẫn là baseline HTTP hạn chế, chưa có đủ benign counterpart cùng path/body/template. Cần bổ sung dữ liệu đối chứng và test trên app/môi trường khác.

Offline test sinh **10.000 unique variants mỗi lớp**, đủ 8 family và 3 placement, seed replay đúng; kiểm tra wire structure, Content-Length, JSON/form/query và không reset giữa burst. Đây là 20.000 request string, không phải 20.000 kiểu attack độc lập hoặc corpus đủ chất lượng tự động.

Giữ family/template/session khác nhau cho held-out test. Không random split packet của cùng request/flow, không gọi tăng độ đa dạng từ random string là bằng chứng generalization. Chưa chạy các biến thể attack qua mạng thực hoặc benchmark reproduction trong validation này; tests dùng generator offline, socket mocking và HTTP localhost benign.

## UDP payload và Edge-IIoTset

CSV ML Edge-IIoTset đang dùng có tcp.payload; UDP chỉ có udp.port, udp.stream, udp.time_delta, không có udp.payload. Không bắt buộc lưu một cột UDP payload riêng để khớp 56 canonical features. Nếu cần NLP/byte analysis UDP sau này, có thể lưu metadata raw_udp_payload_hex hoặc thiết kế cột nội dung chung có transport tag; không được đổ bytes UDP vào tcp.payload vì khác nghĩa. PCAP giữ bytes để trích lại. Thay đổi này không thêm raw UDP column hoặc sửa dataset/model cũ.
