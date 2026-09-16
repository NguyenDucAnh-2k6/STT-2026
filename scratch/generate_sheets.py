"""
Script tạo file Excel phân chia công việc Kỹ thuật & Kinh tế
dựa trên Đề án Sáng tạo trẻ AERO 2026.
"""

import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def build_aero_spreadsheet():
    wb = openpyxl.Workbook()
    
    # Font definitions
    font_family = "Segoe UI"
    f_title = Font(name=font_family, size=16, bold=True, color="FFFFFF")
    f_subtitle = Font(name=font_family, size=11, italic=True, color="E2E8F0")
    f_sec_header = Font(name=font_family, size=12, bold=True, color="FFFFFF")
    f_tbl_header = Font(name=font_family, size=10, bold=True, color="1E293B")
    f_group = Font(name=font_family, size=11, bold=True, color="0F172A")
    f_cell = Font(name=font_family, size=10, color="1E293B")
    f_cell_bold = Font(name=font_family, size=10, bold=True, color="1E293B")
    f_kpi_num = Font(name=font_family, size=15, bold=True, color="0F172A")
    f_kpi_lbl = Font(name=font_family, size=9, bold=True, color="64748B")

    # Status fonts & fills
    fill_done = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid") # light green
    font_done = Font(name=font_family, size=9, bold=True, color="166534") # dark green
    
    fill_inprog = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid") # light amber
    font_inprog = Font(name=font_family, size=9, bold=True, color="92400E") # dark amber

    fill_todo = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid") # light gray
    font_todo = Font(name=font_family, size=9, bold=True, color="475569") # dark slate

    # Section & Header Fills
    fill_banner_tech = PatternFill(start_color="1E3A8A", end_color="1E3A8A", fill_type="solid") # Dark Blue
    fill_banner_biz = PatternFill(start_color="064E3B", end_color="064E3B", fill_type="solid") # Dark Emerald
    fill_tbl_head_tech = PatternFill(start_color="E0F2FE", end_color="E0F2FE", fill_type="solid") # Light Sky Blue
    fill_tbl_head_biz = PatternFill(start_color="D1FAE5", end_color="D1FAE5", fill_type="solid") # Light Mint
    fill_group_tech = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
    fill_kpi_card = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")

    # Borders
    thin_border_side = Side(border_style="thin", color="CBD5E1")
    border_cell = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=thin_border_side)
    thick_bottom = Side(border_style="medium", color="0284C7")
    border_tbl_header_tech = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=thick_bottom)
    border_tbl_header_biz = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=Side(border_style="medium", color="059669"))

    border_kpi = Border(
        left=Side(border_style="thin", color="E2E8F0"),
        right=Side(border_style="thin", color="E2E8F0"),
        top=Side(border_style="thin", color="E2E8F0"),
        bottom=Side(border_style="medium", color="0284C7")
    )
    border_kpi_biz = Border(
        left=Side(border_style="thin", color="E2E8F0"),
        right=Side(border_style="thin", color="E2E8F0"),
        top=Side(border_style="thin", color="E2E8F0"),
        bottom=Side(border_style="medium", color="059669")
    )

    # =========================================================================
    # TAB 1: KỸ THUẬT (TECHNICAL & R&D ROADMAP)
    # =========================================================================
    ws_tech = wb.active
    ws_tech.title = "Kỹ Thuật & R&D"
    ws_tech.views.sheetView[0].showGridLines = True

    # 1. Banner Header
    ws_tech.merge_cells("A1:I1")
    ws_tech["A1"] = "DỰ ÁN AERO - BẢNG PHÂN CHIA CÔNG VIỆC VÀ TIẾN ĐỘ KỸ THUẬT (R&D)"
    ws_tech["A1"].font = f_title
    ws_tech["A1"].fill = fill_banner_tech
    ws_tech["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws_tech.row_dimensions[1].height = 40

    ws_tech.merge_cells("A2:I2")
    ws_tech["A2"] = "Đề án Sáng tạo trẻ 2026 | Đội thi: Innovate Future | GVHD: ThS. Nguyễn Duy Tùng (Trường CNTT&TT - ĐHBK Hà Nội)"
    ws_tech["A2"].font = f_subtitle
    ws_tech["A2"].fill = fill_banner_tech
    ws_tech["A2"].alignment = Alignment(horizontal="center", vertical="center")
    ws_tech.row_dimensions[2].height = 24

    # 2. KPI Summary Cards (Row 4 & 5)
    kpis_tech = [
        ("B4:B5", "A4:B5", "TỔNG SỐ HẠNG MỤC", "24 Đầu việc", "A4", "A5"),
        ("C4:D5", "C4:D5", "ĐÃ HOÀN THÀNH", "17 Hạng mục (71%)", "C4", "C5"),
        ("E4:F5", "E4:F5", "ĐANG THỰC HIỆN", "4 Hạng mục (17%)", "E4", "E5"),
        ("G4:G5", "G4:G5", "KẾ HOẠCH BƯỚC TIẾP", "3 Hạng mục (12%)", "G4", "G5"),
        ("H4:I5", "H4:I5", "TRL MỤC TIÊU", "TRL 4-5 → TRL 6-7", "H4", "H5")
    ]
    
    # We will build cards manually
    cards_tech = [
        ("A", "B", "TỔNG SỐ ĐẦU VIỆC KỸ THUẬT", "24 Hạng mục", "0284C7"),
        ("C", "D", "ĐÃ HOÀN THÀNH (PROTOTYPE)", "17 Đầu việc (71%)", "10B981"),
        ("E", "F", "ĐANG TRIỂN KHAI / THỬ NGHIỆM", "4 Đầu việc (17%)", "F59E0B"),
        ("G", "G", "CẦN LÀM TIẾP (TRL 6-7)", "3 Đầu việc", "6366F1"),
        ("H", "I", "TRL HIỆN TẠI VÀ MỤC TIÊU", "TRL 4-5 đạt → TRL 6-7", "0F172A"),
    ]
    for c_start, c_end, lbl, val, color_hex in cards_tech:
        ws_tech.merge_cells(f"{c_start}4:{c_end}4")
        ws_tech.merge_cells(f"{c_start}5:{c_end}5")
        top_cell = ws_tech[f"{c_start}4"]
        bot_cell = ws_tech[f"{c_start}5"]
        top_cell.value = lbl
        top_cell.font = f_kpi_lbl
        top_cell.alignment = Alignment(horizontal="center", vertical="center")
        bot_cell.value = val
        bot_cell.font = Font(name=font_family, size=13, bold=True, color=color_hex)
        bot_cell.alignment = Alignment(horizontal="center", vertical="center")
        
        # Apply borders & fill
        for col_idx in range(openpyxl.utils.column_index_from_string(c_start), openpyxl.utils.column_index_from_string(c_end) + 1):
            cl = get_column_letter(col_idx)
            ws_tech[f"{cl}4"].fill = fill_kpi_card
            ws_tech[f"{cl}5"].fill = fill_kpi_card
            ws_tech[f"{cl}4"].border = Border(top=Side(style="thin", color="CBD5E1"), left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1"))
            ws_tech[f"{cl}5"].border = Border(bottom=Side(style="medium", color=color_hex), left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1"))

    ws_tech.row_dimensions[4].height = 18
    ws_tech.row_dimensions[5].height = 26

    # 3. Table Header (Row 7)
    headers_tech = [
        ("A7", "STT", 6),
        ("B7", "Phân hệ / Nhóm nhiệm vụ", 24),
        ("C7", "Nội dung kỹ thuật chi tiết", 38),
        ("D7", "Mô-đun / Mã nguồn tương ứng", 26),
        ("E7", "Nhân sự phụ trách", 20),
        ("F7", "TRL", 8),
        ("G7", "Trạng thái", 16),
        ("H7", "Tiến độ", 10),
        ("I7", "Kết quả nghiệm thu & Bước triển khai tiếp", 38)
    ]
    for pos, text, width in headers_tech:
        ws_tech[pos] = text
        ws_tech[pos].font = f_tbl_header
        ws_tech[pos].fill = fill_tbl_head_tech
        ws_tech[pos].alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws_tech[pos].border = border_tbl_header_tech
        col_letter = pos[0]
        ws_tech.column_dimensions[col_letter].width = width

    ws_tech.row_dimensions[7].height = 30

    # Data Rows for Tech Tab
    tech_tasks = [
        # Nhóm 1
        ("GROUP", "1. THU THẬP & TIỀN XỬ LÝ DỮ LIỆU CHUẨN EDGE-IIOTSET (NỘI DUNG 1 - MỤC 4.1)", ""),
        ("1.1", "Chuẩn hóa Schema Dữ liệu", "Thiết lập cấu trúc 61 đặc trưng mạng đầu vào và 15 lớp nhãn tấn công chuẩn Edge-IIoTset", "ml_engine/config/schema.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 4", "HOÀN THÀNH", "100%", "Đã loại bỏ rò rỉ dữ liệu (IP, time), chuẩn hóa 56 đặc trưng hành vi và 15 nhãn."),
        ("1.2", "Pipeline Tiền xử lý & Scaler", "Xây dựng bộ tiền xử lý số liệu, mã hóa nhãn OrdinalEncoder và chuẩn hóa StandardScaler", "ml_engine/preprocessing/", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 4", "HOÀN THÀNH", "100%", "Đã xuất artifacts preprocessor.joblib và scaler.joblib tương thích suy luận trực tiếp."),
        ("1.3", "Trích xuất đặc trưng thời gian thực", "Ánh xạ luồng telemetry thực tế (packet_rate, byte_rate, syn_ratio...) sang vector 56 chiều", "ml_engine/preprocessing/feature_preprocessor.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 4", "HOÀN THÀNH", "100%", "Đã kiểm thử trích xuất và biến đổi trong thời gian < 0.1ms trên máy tính."),

        # Nhóm 2
        ("GROUP", "2. NGHIÊN CỨU & PHÁT TRIỂN MÔ HÌNH HỌC MÁY 2 TẦNG (DUAL ML PIPELINE - NỘI DUNG 2)", ""),
        ("2.1", "Tier 1: Anomaly Detector (Unsupervised)", "Huấn luyện Isolation Forest trên lưu lượng Normal sạch để bắt các tấn công Zero-day đột biến", "ml_engine/algorithms/anomaly_detectors.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Đã kiểm nghiệm dải điểm Isolation score [-0.62 -> -0.37], ngưỡng chuẩn hóa 0.55."),
        ("2.2", "Mở rộng Anomaly Models", "Tích hợp và đóng gói One-Class SVM, Elliptic Envelope và Local Outlier Factor (LOF)", "ml_engine/algorithms/anomaly_detectors.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 4", "HOÀN THÀNH", "100%", "Hỗ trợ thay đổi linh hoạt qua cờ dòng lệnh --anomaly-model trên cả train và runtime."),
        ("2.3", "Tier 2: Attack Classifiers (15 lớp)", "Xây dựng thư viện mô hình phân loại: Decision Tree, Random Forest, Extra Trees, GBDT, MLP", "ml_engine/algorithms/classifiers.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Decision Tree đạt F1 90.62%, Random Forest đạt F1 96.84%, Ensemble Soft-Voting đạt 97.2%."),
        ("2.4", "Tối ưu hóa Siêu tham số (Optuna HPO)", "Bayesian Optimization (TPE Sampler) kết hợp 5-Fold Stratified CV, lưu persistent vào SQLite", "ml_engine/tuning/optuna_tuner.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 4", "HOÀN THÀNH", "100%", "Lưu trữ toàn bộ study vào optuna_study.db, hỗ trợ cắt tỉa sớm Median/Hyperband."),
        ("2.5", "Bộ suy luận thời gian thực (Inference Engine)", "Daemon suy luận 2 tầng, nhận MQTT, phân loại và cảnh báo với độ trễ < 1.5ms", "ml_engine/inference_service.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Khởi động độc lập, tự động nạp Artifacts, xuất cảnh báo JSON qua MQTT topic."),

        # Nhóm 3
        ("GROUP", "3. FIRMWARE BIÊN ESP32 PROMISCUOUS & MÀN HÌNH OLED (NỘI DUNG 3 - MỤC 4.1)", ""),
        ("3.1", "Bắt gói tin Promiscuous 802.11", "Cấu hình phần cứng radio ESP32 bắt toàn bộ khung truyền WiFi over-the-air", "firmware/esp32_probe/esp32_probe.ino", "Thành viên Phần cứng", "TRL 5", "HOÀN THÀNH", "100%", "Trích xuất thống kê gói tin (packet_rate, byte_rate, syn_ratio, unique_ports) trong cửa sổ 1s."),
        ("3.2", "Chế độ Sniffing Mọi Mạng (All-Networks)", "Mở khóa radio, thực hiện Fast Channel Hopping liên tục từ kênh 1 đến 13 mỗi 300ms", "firmware/esp32_probe/config.h", "Thành viên Phần cứng", "TRL 5", "HOÀN THÀNH", "100%", "Thoát ly ràng buộc AP của máy tính, bắt được tất cả các router và thiết bị xung quanh."),
        ("3.3", "TinyML On-Device C Code", "Xuất cây quyết định sang mã nguồn C thuần (tinyml_model.h) nhúng chạy trực tiếp on-chip ESP32", "ml_engine/exporter/tinyml_exporter.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Thời gian suy luận on-chip < 50 micro-giây, RAM tiêu thụ < 25KB, độ chính xác tương đương Python."),
        ("3.4", "Giao tiếp Hiển thị OLED SSD1306", "Hiển thị kênh, tốc độ gói, trạng thái mạng, mối đe dọa trực quan trên màn hình I2C (128x64 & 128x32)", "firmware/esp32_probe/esp32_probe.ino", "Thành viên Phần cứng", "TRL 5", "HOÀN THÀNH", "100%", "Tích hợp I2C Scanner, hạ xung 100kHz, Auto-Recovery phục hồi tự động khi cắm lỏng dây."),
        ("3.5", "Dual-Transport High Availability", "Truyền đồng thời qua Wi-Fi MQTT và cáp USB Serial Bridge (ESP32_TELEMETRY:)", "launcher/workers.py", "Thành viên Phần cứng", "TRL 5", "HOÀN THÀNH", "100%", "Đảm bảo truyền số liệu 100% không gián đoạn kể cả khi Wi-Fi đổi pass hay mất mạng."),

        # Nhóm 4
        ("GROUP", "4. DATA LAKEHOUSE & TÁI HUẤN LUYỆN HYBRID (QUẢN TRỊ DỮ LIỆU THỰC ĐỊA)", ""),
        ("4.1", "Data Lakehouse Columnar Engine", "Lưu trữ telemetry liên tục dạng Apache Parquet nén Snappy, phân vùng theo ngày (date=YYYY-MM-DD)", "data_lake/lakehouse.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Đã kiểm thử ghi đệm và chốt tệp tự động, truy vấn tốc độ cao với pyarrow và SQLite Catalog."),
        ("4.2", "Data Lake Collector Daemon", "Lắng nghe telemetry, attack scenario và model prediction từ MQTT để lưu trữ liên tục", "data_lake/collector.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Tự động tích hợp vào vòng đời run_system.py, hỗ trợ cờ --record-lake và chốt tệp khi Ctrl+C."),
        ("4.3", "Quy trình Tái huấn luyện Hybrid", "Tích hợp dữ liệu Normal thực tế từ Data Lakehouse vào quy trình huấn luyện Isolation Forest", "ml_engine/train.py", "Nguyễn Hữu Đức Anh (AI Lead)", "TRL 5", "HOÀN THÀNH", "100%", "Đã kiểm thử cờ --data-source hybrid: khử triệt để False Positives do lệch phân phối môi trường."),

        # Nhóm 5
        ("GROUP", "5. SOC WEB DASHBOARD & TRUNG TÂM GIÁM SÁT THỜI GIAN THỰC (FASTAPI + ES MODULES)", ""),
        ("5.1", "Backend Modular FastAPI & WebSocket", "Kiến trúc API Router, WebSocket Broadcast và MQTT Client Bridge", "dashboard/backend/", "Thành viên Giao diện / Web", "TRL 5", "HOÀN THÀNH", "100%", "Tách module routers/api.py, ws.py, state.py, hỗ trợ API Data Lake summary & sessions."),
        ("5.2", "Frontend Glassmorphism Component-based", "Giao diện Dark Mode Cyberpunk, biểu đồ Chart.js live, đồng hồ Gauge đo nguy cơ", "dashboard/frontend/", "Thành viên Giao diện / Web", "TRL 5", "HOÀN THÀNH", "100%", "Cấu trúc Native ES Modules (state.js, components, services), hiển thị huy hiệu Data Lake."),
        ("5.3", "Control Bar Bắn Gói Tin Mạng Thật", "Bộ phát động tấn công raw socket (Port Scan, UDP Flood, SYN Flood, Exfil) điều khiển từ Dashboard", "firmware/simulator/attack_traffic_generator.py", "Thành viên Giao diện / Web", "TRL 5", "HOÀN THÀNH", "100%", "Socket mạng thật 100% bắn tới IP Gateway/Target, thiết bị biên bắt được và phân loại tức thời."),

        # Nhóm 6
        ("GROUP", "6. KHẢ NĂNG TƯƠNG THÍCH ĐA NỀN TẢNG & TỰ ĐỘNG HÓA LAUNCHER", ""),
        ("6.1", "Khử Hardcode & Hỗ trợ Cross-Platform", "Tự động tìm kiếm đường dẫn arduino-cli, cổng COM, IP LAN trên Windows, Linux, macOS", "launcher/flasher.py, network.py", "Trưởng nhóm kỹ thuật", "TRL 5", "HOÀN THÀNH", "100%", "Đã kiểm thử trên Windows PowerShell, Linux bash và macOS. Bổ sung script run_system.sh."),
        ("6.2", "Tự động biên dịch & nạp code CLI (--flash)", "Tích hợp nạp firmware 1-click qua arduino-cli không cần mở Arduino IDE GUI", "launcher/flasher.py", "Trưởng nhóm kỹ thuật", "TRL 5", "HOÀN THÀNH", "100%", "Biên dịch và nạp code thành công, tự động nhận diện chip ESP32 qua CP210x/CH340."),
        ("6.3", "Zero-Config Wi-Fi Roaming & UDP Beacon", "Tự động lấy ngầm SSID/Password máy tính đang bắt và phát UDP beacon định vị IP Broker", "launcher/workers.py, network.py", "Trưởng nhóm kỹ thuật", "TRL 5", "HOÀN THÀNH", "100%", "ESP32 tự cập nhật IP máy tính khi chuyển đổi mạng Wi-Fi mà không cần nạp lại code."),

        # Nhóm 7: BƯỚC TIẾP THEO (NEXT STEPS)
        ("GROUP", "7. THỬ NGHIỆM THỰC ĐỊA, THIẾT KẾ PHẦN CỨNG & HOÀN THIỆN SẢN PHẨM (MỤC 4.2 - 4.3)", ""),
        ("7.1", "Thử nghiệm Thí điểm Thực địa (Giai đoạn 3 R&D)", "Triển khai hệ thống tại 1-2 điểm thực tế (Phòng Lab / Khoa / Đơn vị đối tác tại ĐHBK Hà Nội)", "Hệ thống AERO hoàn chỉnh", "Toàn đội kỹ thuật", "TRL 6", "ĐANG TRIỂN KHAI", "35%", "Kế hoạch Q3/2026: Lắp đặt 2 box giám sát liên tục 4-6 tuần, ghi nhận 50,000+ mẫu lưu lượng thực tế."),
        ("7.2", "Thiết kế Vỏ Hộp Công Nghiệp & Mạch PCB", "Thiết kế vỏ hộp in 3D/CNC tản nhiệt, thu gọn linh kiện thành bo mạch PCB tích hợp hoàn chỉnh", "firmware/hardware_design/", "Thành viên Phần cứng", "TRL 6", "KẾ HOẠCH TIẾP", "15%", "Kế hoạch Q4/2026: Hoàn thiện bản vẽ CAD vỏ hộp có khe cắm ăng-ten ngoài và màn hình hiển thị."),
        ("7.3", "Kiểm định Ổn định & Bảo mật Hệ thống (Giai đoạn 5)", "Đánh giá an toàn kênh truyền MQTT (TLS), mã hóa lưu trữ Data Lake và độ bền nhiệt thiết bị biên", "Bảo mật & Kiểm thử", "Trưởng nhóm kỹ thuật", "TRL 6-7", "KẾ HOẠCH TIẾP", "20%", "Kế hoạch Q1/2027: Stress test nhiệt độ hoạt động 24/7, kích hoạt TLS MQTT Certificate Authentication."),
        ("7.4", "Đăng ký Sở hữu Trí tuệ / Bản quyền Tác giả", "Đăng ký bản quyền phần mềm AERO Core Engine và giải pháp hữu ích thiết bị phát hiện xâm nhập biên", "Hồ sơ Pháp lý & SHTT", "Trưởng nhóm kỹ thuật + GVHD", "TRL 6", "ĐANG TRIỂN KHAI", "40%", "Kế hoạch Q4/2026: Soạn thảo bản mô tả sáng chế/giải pháp hữu ích nộp Cục Sở hữu Trí tuệ.")
    ]

    current_row = 8
    for item in tech_tasks:
        if item[0] == "GROUP":
            ws_tech.merge_cells(f"A{current_row}:I{current_row}")
            ws_tech[f"A{current_row}"] = f"▶ {item[1]}"
            ws_tech[f"A{current_row}"].font = f_group
            ws_tech[f"A{current_row}"].fill = fill_group_tech
            ws_tech[f"A{current_row}"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
            ws_tech.row_dimensions[current_row].height = 24
            for col_idx in range(1, 10):
                ws_tech[f"{get_column_letter(col_idx)}{current_row}"].border = border_cell
            current_row += 1
        else:
            stt, workstream, details, module, owner, trl, status, progress, deliverable = item
            ws_tech[f"A{current_row}"] = stt
            ws_tech[f"B{current_row}"] = workstream
            ws_tech[f"C{current_row}"] = details
            ws_tech[f"D{current_row}"] = module
            ws_tech[f"E{current_row}"] = owner
            ws_tech[f"F{current_row}"] = trl
            ws_tech[f"G{current_row}"] = status
            ws_tech[f"H{current_row}"] = progress
            ws_tech[f"I{current_row}"] = deliverable

            # Alignments
            ws_tech[f"A{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_tech[f"B{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_tech[f"C{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_tech[f"D{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_tech[f"E{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_tech[f"F{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_tech[f"G{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_tech[f"H{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_tech[f"I{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            # Fonts
            for col_letter in ["A", "B", "C", "D", "E", "F", "H", "I"]:
                ws_tech[f"{col_letter}{current_row}"].font = f_cell
            ws_tech[f"B{current_row}"].font = f_cell_bold
            ws_tech[f"H{current_row}"].font = f_cell_bold

            # Status highlight
            if status == "HOÀN THÀNH":
                ws_tech[f"G{current_row}"].fill = fill_done
                ws_tech[f"G{current_row}"].font = font_done
            elif status == "ĐANG TRIỂN KHAI":
                ws_tech[f"G{current_row}"].fill = fill_inprog
                ws_tech[f"G{current_row}"].font = font_inprog
            else:
                ws_tech[f"G{current_row}"].fill = fill_todo
                ws_tech[f"G{current_row}"].font = font_todo

            # Borders
            for col_idx in range(1, 10):
                ws_tech[f"{get_column_letter(col_idx)}{current_row}"].border = border_cell

            ws_tech.row_dimensions[current_row].height = 36
            current_row += 1


    # =========================================================================
    # TAB 2: KINH TẾ (BUSINESS & FINANCIAL ROADMAP)
    # =========================================================================
    ws_biz = wb.create_sheet(title="Kinh Tế & Thương Mại")
    ws_biz.views.sheetView[0].showGridLines = True

    # 1. Banner Header
    ws_biz.merge_cells("A1:I1")
    ws_biz["A1"] = "DỰ ÁN AERO - KẾ HOẠCH KINH DOANH, TÀI CHÍNH & THƯƠNG MẠI HÓA"
    ws_biz["A1"].font = f_title
    ws_biz["A1"].fill = fill_banner_biz
    ws_biz["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws_biz.row_dimensions[1].height = 40

    ws_biz.merge_cells("A2:I2")
    ws_biz["A2"] = "Căn cứ Đề án Sáng tạo trẻ 2026 (Mục 5.1 - 5.5 & Mục 1.3 - 1.4) | Doanh nghiệp B2B & Khởi nghiệp Đổi mới sáng tạo"
    ws_biz["A2"].font = f_subtitle
    ws_biz["A2"].fill = fill_banner_biz
    ws_biz["A2"].alignment = Alignment(horizontal="center", vertical="center")
    ws_biz.row_dimensions[2].height = 24

    # 2. KPI Summary Cards
    cards_biz = [
        ("A", "B", "NHU CẦU GỌI VỐN SEED", "2,5 TỶ VNĐ", "059669"),
        ("C", "D", "DOANH THU DỰ PHÓNG NĂM 1-3", "380Tr → 1,94Tỷ → 5,36Tỷ", "0F766E"),
        ("E", "F", "ĐIỂM HÒA VỐN DỰ KIẾN", "Đầu Năm 3 (Sau 24 tháng)", "D97706"),
        ("G", "G", "THỊ TRƯỜNG MỤC TIÊU (SOM)", "9 – 22 Tỷ VNĐ", "4338CA"),
        ("H", "I", "TỶ LỆ HOÀN THIỆN ĐỀ ÁN", "Đạt 75% Kế hoạch", "0F172A"),
    ]
    for c_start, c_end, lbl, val, color_hex in cards_biz:
        ws_biz.merge_cells(f"{c_start}4:{c_end}4")
        ws_biz.merge_cells(f"{c_start}5:{c_end}5")
        top_cell = ws_biz[f"{c_start}4"]
        bot_cell = ws_biz[f"{c_start}5"]
        top_cell.value = lbl
        top_cell.font = f_kpi_lbl
        top_cell.alignment = Alignment(horizontal="center", vertical="center")
        bot_cell.value = val
        bot_cell.font = Font(name=font_family, size=13, bold=True, color=color_hex)
        bot_cell.alignment = Alignment(horizontal="center", vertical="center")

        for col_idx in range(openpyxl.utils.column_index_from_string(c_start), openpyxl.utils.column_index_from_string(c_end) + 1):
            cl = get_column_letter(col_idx)
            ws_biz[f"{cl}4"].fill = fill_kpi_card
            ws_biz[f"{cl}5"].fill = fill_kpi_card
            ws_biz[f"{cl}4"].border = Border(top=Side(style="thin", color="CBD5E1"), left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1"))
            ws_biz[f"{cl}5"].border = Border(bottom=Side(style="medium", color=color_hex), left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1"))

    ws_biz.row_dimensions[4].height = 18
    ws_biz.row_dimensions[5].height = 26

    # 3. Table Header
    headers_biz = [
        ("A7", "STT", 6),
        ("B7", "Trụ cột kinh tế / Hạng mục", 24),
        ("C7", "Nội dung công việc chi tiết theo Đề án", 38),
        ("D7", "Chỉ số / Thông số định lượng mục tiêu", 26),
        ("E7", "Nhân sự phụ trách", 20),
        ("F7", "Thời hạn", 12),
        ("G7", "Trạng thái", 16),
        ("H7", "Tiến độ", 10),
        ("I7", "Kế hoạch hành động cụ thể & Deliverables", 38)
    ]
    for pos, text, width in headers_biz:
        ws_biz[pos] = text
        ws_biz[pos].font = f_tbl_header
        ws_biz[pos].fill = fill_tbl_head_biz
        ws_biz[pos].alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws_biz[pos].border = border_tbl_header_biz
        col_letter = pos[0]
        ws_biz.column_dimensions[col_letter].width = width

    ws_biz.row_dimensions[7].height = 30

    # Data Rows for Biz Tab
    biz_tasks = [
        # Nhóm 1
        ("GROUP", "1. NGHIÊN CỨU THỊ TRƯỜNG & KHÁCH HÀNG MỤC TIÊU (MỤC 5.1 ĐỀ ÁN)", ""),
        ("1.1", "Quy mô Thị trường (TAM - SAM - SOM)", "Định lượng dung lượng thị trường an ninh mạng biên cho doanh nghiệp vừa & nhỏ (SMEs)", "TAM: 3.500 tỷ | SAM: 450 tỷ | SOM: 9-22 tỷ VNĐ", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Đã phân tích 3 phân khúc chính: Trường học/Viện, SMEs văn phòng và Nhà máy IoT."),
        ("1.2", "Khảo sát Nỗi đau Khách hàng (Pain Points)", "Phỏng vấn 15-20 quản trị viên mạng về chi phí SOC đắt đỏ, quá tải báo động và nhân sự mỏng", "15+ Doanh nghiệp & đơn vị giáo dục", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "85% khách hàng phản hồi cần thiết bị cắm là chạy (Plug & Play), cảnh báo qua Telegram/Web."),
        ("1.3", "Phân tích Đối thủ Cạnh tranh (USP)", "Lập ma trận so sánh với các giải pháp Firewall/IDS truyền thống (Suricata, Snort, Fortinet)", "Giá thành 1/5, suy luận on-device, không lộ dữ liệu", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Xác lập USP độc nhất: Giám sát biên không cần can thiệp router, phân tích cục bộ không đẩy raw data lên cloud."),

        # Nhóm 2
        ("GROUP", "2. THIẾT KẾ MÔ HÌNH KINH DOANH & ĐỊNH GIÁ SẢN PHẨM (MỤC 5.2 - 5.3 ĐỀ ÁN)", ""),
        ("2.1", "Mô hình Doanh thu Hybrid (HW + SaaS)", "Xây dựng mô hình kết hợp: Bán phần cứng biên (One-time) + Thuê bao phần mềm giám sát (Monthly SaaS)", "HW: 17.5% margin | SaaS: 80% margin", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Đảm bảo dòng tiền định kỳ (Recurring Revenue) ổn định, giảm thiểu rủi ro biến động doanh số phần cứng."),
        ("2.2", "Chiến lược Định giá Sản phẩm", "Xây dựng 3 gói dịch vụ: Gói Basic, Gói Pro và Gói Enterprise cho mạng lớn", "Box: 5.25Tr | Pro: 1.5Tr/tháng | Basic: 500k/tháng", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Giá bán thiết bị trung bình 5.25 triệu VNĐ (COGS ~4.33tr), phí thuê bao phù hợp ngân sách SMEs."),
        ("2.3", "Mô hình Tỷ lệ Rời bỏ (Churn Rate Model)", "Mô hình hóa tỷ lệ giữ chân khách hàng: Năm 1 (~3%/tháng), Năm 2 trở đi (~1.2%/tháng)", "Retention 24 tháng: ~65%", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Đã tích hợp giả định Churn Rate vào công thức LTV và thời gian hoàn vốn theo góp ý hội đồng."),

        # Nhóm 3
        ("GROUP", "3. KẾ HOẠCH TÀI CHÍNH 3 NĂM & GỌI VỐN SEED ROUND (MỤC 5.5 & 1.4 ĐỀ ÁN)", ""),
        ("3.1", "Dự phóng Doanh thu 3 năm", "Mô hình dự báo doanh số thiết bị bán ra và doanh thu thuê bao lũy kế qua 3 năm", "Năm 1: 380Tr | Năm 2: 1.94Tỷ | Năm 3: 5.36Tỷ", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Số lượng thiết bị bán lũy kế: 60 box (Năm 1) -> 260 box (Năm 2) -> 700 box (Năm 3)."),
        ("3.2", "Kế hoạch Chi phí (COGS & OPEX)", "Dự toán chi phí sản xuất phần cứng, chi phí máy chủ cloud, marketing và nhân sự vận hành", "Dòng tiền âm tối đa: ~900Tr - 1Tỷ VNĐ", "Thành viên Kinh doanh", "Q3/2026", "HOÀN THÀNH", "100%", "Xác định điểm hòa vốn tại đầu Năm 3 khi doanh thu thuê bao định kỳ vượt chi phí duy trì cố định."),
        ("3.3", "Hồ sơ Gọi vốn Hạt giống (Seed Round)", "Lập bảng sử dụng vốn gọi 2.5 tỷ VNĐ: R&D (42%), Nhân sự (28%), Mkt/Sales (20%), Dự phòng (10%)", "Mức gọi vốn: 2.500.000.000 VNĐ", "Toàn đội dự án", "Q3/2026", "HOÀN THÀNH", "100%", "Đã hoàn thành cơ cấu phân bổ chi tiết tương ứng với các hoạt động R&D và nhân sự mục 1.4."),

        # Nhóm 4
        ("GROUP", "4. CHIẾN LƯỢC TIẾP CẬN THỊ TRƯỜNG & PHÂN PHỐI (GTM STRATEGY - MỤC 5.4 ĐỀ ÁN)", ""),
        ("4.1", "Chương trình Dùng thử Thí điểm (Pilot POC)", "Thiết kế gói POC 30 ngày dùng thử miễn phí cho 3-5 đối tác doanh nghiệp đầu tiên", "3-5 Khách hàng thử nghiệm", "Thành viên Kinh doanh", "Q4/2026", "ĐANG TRIỂN KHAI", "50%", "Đang tiếp cận bộ phận IT một số Viện trong ĐHBK Hà Nội và 2 công ty công nghệ tại Cầu Giấy/Hai Bà Trưng."),
        ("4.2", "Xây dựng Mạng lưới Đối tác Tích hợp (SI Partners)", "Hợp tác với các công ty tích hợp hệ thống vừa và nhỏ tại Hà Nội để làm đại lý bán phần cứng", "2-3 Đối tác SI phân phối", "Thành viên Kinh doanh", "Q1/2027", "KẾ HOẠCH TIẾP", "25%", "Chiết khấu 15-20% cho đại lý SI, tận dụng sẵn tệp khách hàng doanh nghiệp có nhu cầu bảo mật."),
        ("4.3", "Tiếp thị Kỹ thuật số & Content Marketing", "Xây dựng Website giới thiệu sản phẩm, viết Whitepaper so sánh kỹ thuật, chia sẻ giải pháp mã nguồn mở", "1 Whitepaper + 5 Bài viết kỹ thuật", "Thành viên Giao diện / Mkt", "Q4/2026", "ĐANG TRIỂN KHAI", "40%", "Tập trung truyền thông vào tính năng Edge TinyML suy luận tại chỗ, tiết kiệm băng thông và bảo vệ quyền riêng tư."),

        # Nhóm 5
        ("GROUP", "5. HỒ SƠ DỰ THI SÁNG TẠO TRẺ & KẾT NỐI ĐẦU TƯ (MỤC 1.3 - 1.4 ĐỀ ÁN)", ""),
        ("5.1", "Hoàn thiện Đề án Thuyết minh Dự thi", "Biên soạn toàn văn bản thuyết minh dự án theo biểu mẫu quy chuẩn của Ban tổ chức Sáng tạo trẻ", "File: Sáng tạo trẻ.docx (500+ đoạn)", "Toàn đội thi", "T9/2026", "HOÀN THÀNH", "100%", "Đã hoàn thiện đầy đủ các mục: Thuyết minh, Công nghệ, R&D, Kinh doanh, Dự phóng tài chính và Phụ lục."),
        ("5.2", "Xây dựng Slide Thuyết trình (Pitch Deck)", "Thiết kế bộ slide trình bày 10-12 trang chuẩn pitching khởi nghiệp công nghệ cho Vòng Triển khai", "Slide Pitching 10-12 slides", "Toàn đội thi", "Q4/2026", "ĐANG TRIỂN KHAI", "45%", "Nhấn mạnh vào Prototype chạy thật 100%, demo bắn gói tin mạng thật và tiềm năng thị trường SMEs."),
        ("5.3", "Video Giới thiệu & Demo Vận hành", "Sản xuất video clip 3-5 phút giới thiệu giải pháp, quay cận cảnh phần cứng ESP32 và SOC Dashboard", "Video Clip Full HD 3-5 phút", "Thành viên Giao diện", "Q4/2026", "KẾ HOẠCH TIẾP", "30%", "Kịch bản: Bật máy tính -> Bấm nút tấn công trên Web -> ESP32 hú còi/báo động và nhận diện chính xác 100%."),
        ("5.4", "Tư vấn & Phản biện cùng Mạng lưới Chuyên gia", "Làm việc định kỳ với GVHD ThS. Nguyễn Duy Tùng và các mentor an ninh mạng / khởi nghiệp", "Các buổi phản biện định kỳ", "Trưởng nhóm + GVHD", "Hàng tháng", "ĐANG TRIỂN KHAI", "60%", "Tiếp thu ý kiến hoàn thiện mô hình churn rate, liên kết rủi ro kỹ thuật vào chi phí dự phòng.")
    ]

    current_row = 8
    for item in biz_tasks:
        if item[0] == "GROUP":
            ws_biz.merge_cells(f"A{current_row}:I{current_row}")
            ws_biz[f"A{current_row}"] = f"▶ {item[1]}"
            ws_biz[f"A{current_row}"].font = f_group
            ws_biz[f"A{current_row}"].fill = fill_group_tech
            ws_biz[f"A{current_row}"].alignment = Alignment(horizontal="left", vertical="center", indent=1)
            ws_biz.row_dimensions[current_row].height = 24
            for col_idx in range(1, 10):
                ws_biz[f"{get_column_letter(col_idx)}{current_row}"].border = border_cell
            current_row += 1
        else:
            stt, workstream, details, metrics, owner, timeline, status, progress, action_plan = item
            ws_biz[f"A{current_row}"] = stt
            ws_biz[f"B{current_row}"] = workstream
            ws_biz[f"C{current_row}"] = details
            ws_biz[f"D{current_row}"] = metrics
            ws_biz[f"E{current_row}"] = owner
            ws_biz[f"F{current_row}"] = timeline
            ws_biz[f"G{current_row}"] = status
            ws_biz[f"H{current_row}"] = progress
            ws_biz[f"I{current_row}"] = action_plan

            ws_biz[f"A{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_biz[f"B{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_biz[f"C{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_biz[f"D{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_biz[f"E{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws_biz[f"F{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_biz[f"G{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_biz[f"H{current_row}"].alignment = Alignment(horizontal="center", vertical="center")
            ws_biz[f"I{current_row}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

            for col_letter in ["A", "B", "C", "D", "E", "F", "H", "I"]:
                ws_biz[f"{col_letter}{current_row}"].font = f_cell
            ws_biz[f"B{current_row}"].font = f_cell_bold
            ws_biz[f"H{current_row}"].font = f_cell_bold

            if status == "HOÀN THÀNH":
                ws_biz[f"G{current_row}"].fill = fill_done
                ws_biz[f"G{current_row}"].font = font_done
            elif status == "ĐANG TRIỂN KHAI":
                ws_biz[f"G{current_row}"].fill = fill_inprog
                ws_biz[f"G{current_row}"].font = font_inprog
            else:
                ws_biz[f"G{current_row}"].fill = fill_todo
                ws_biz[f"G{current_row}"].font = font_todo

            for col_idx in range(1, 10):
                ws_biz[f"{get_column_letter(col_idx)}{current_row}"].border = border_cell

            ws_biz.row_dimensions[current_row].height = 36
            current_row += 1

    # Save to Root Directory
    output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "AERO_Ke_Hoach_De_An_Sang_Tao_Tre.xlsx")
    wb.save(output_path)
    print(f"Spreadsheet created successfully at: {output_path}")

if __name__ == "__main__":
    build_aero_spreadsheet()
