import os
import sys
import shutil
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Set stdout to UTF-8
sys.stdout.reconfigure(encoding='utf-8')

ROOT_DIR = r"d:\STT 2026"
EXCEL_PATH = os.path.join(ROOT_DIR, "AERO_Ke_Hoach_De_An_Sang_Tao_Tre.xlsx")
BACKUP_PATH = os.path.join(ROOT_DIR, "AERO_Ke_Hoach_De_An_Sang_Tao_Tre_backup.xlsx")

# 1. Backup original file
shutil.copy2(EXCEL_PATH, BACKUP_PATH)
print(f"[OK] Da tao backup tai: {BACKUP_PATH}")

# 2. Load workbook
wb = openpyxl.load_workbook(EXCEL_PATH)
sheet_name = "Kinh Tế & Thương Mại"

# Recreate sheet to have fresh layout while preserving index position
sheet_idx = wb.sheetnames.index(sheet_name)
del wb[sheet_name]
ws = wb.create_sheet(title=sheet_name, index=sheet_idx)
print(f"[OK] Da khoi tao lai sheet '{sheet_name}' tai vi tri index {sheet_idx}")

# Gridlines visible
ws.views.sheetView[0].showGridLines = True

# Colors & Styles Definition
FONT_NAME = "Quattrocento Sans"

title_font = Font(name=FONT_NAME, size=15, bold=True, color="1E293B")
subtitle_font = Font(name=FONT_NAME, size=10.5, italic=True, color="475569")
kpi_label_font = Font(name=FONT_NAME, size=9.5, bold=True, color="475569")
kpi_val_font = Font(name=FONT_NAME, size=13, bold=True, color="0F172A")
section_header_font = Font(name=FONT_NAME, size=11, bold=True, color="0F172A")
col_header_font = Font(name=FONT_NAME, size=10, bold=True, color="0F172A")
cell_font = Font(name=FONT_NAME, size=9.5, color="1E293B")
cell_bold_font = Font(name=FONT_NAME, size=9.5, bold=True, color="1E293B")
cell_code_font = Font(name="Consolas", size=9, color="0F172A")

# Status / Priority Fonts & Fills
fill_status_inprogress = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid") # Amber
font_status_inprogress = Font(name=FONT_NAME, size=9, bold=True, color="92400E")

fill_status_urgent = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid") # Red
font_status_urgent = Font(name=FONT_NAME, size=9, bold=True, color="B91C1C")

fill_status_review = PatternFill(start_color="E0E7FF", end_color="E0E7FF", fill_type="solid") # Indigo
font_status_review = Font(name=FONT_NAME, size=9, bold=True, color="3730A3")

fill_status_done = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid") # Green
font_status_done = Font(name=FONT_NAME, size=9, bold=True, color="166534")

# Theme Fills
fill_kpi_card = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
fill_table_header = PatternFill(start_color="D1FAE5", end_color="D1FAE5", fill_type="solid") # Emerald-100
fill_sub_table_header = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid") # Slate-200
fill_section_group = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid") # Slate-100
fill_zebra = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
fill_total_row = PatternFill(start_color="E6FFFA", end_color="E6FFFA", fill_type="solid") # Teal tint

# Borders
thin_gray = Side(style='thin', color='CBD5E1')
medium_navy = Side(style='medium', color='334155')
double_navy = Side(style='double', color='0F172A')

border_all_thin = Border(left=thin_gray, right=thin_gray, top=thin_gray, bottom=thin_gray)
border_header = Border(left=thin_gray, right=thin_gray, top=medium_navy, bottom=medium_navy)
border_total = Border(left=thin_gray, right=thin_gray, top=thin_gray, bottom=double_navy)
border_card = Border(left=thin_gray, right=thin_gray, top=thin_gray, bottom=thin_gray)

# Alignments
align_left = Alignment(horizontal='left', vertical='center', wrap_text=True)
align_center = Alignment(horizontal='center', vertical='center', wrap_text=True)
align_right = Alignment(horizontal='right', vertical='center')

# Column Widths (Cols A -> I)
col_widths = {
    'A': 7.0,    # STT
    'B': 28.0,   # Đầu mục / Hạng mục cần sửa
    'C': 42.0,   # Vấn đề bất hợp lý & Nguyên nhân cần sửa
    'D': 42.0,   # Phương án sửa đổi & Số liệu định lượng chuẩn hóa
    'E': 18.0,   # Nhân sự phụ trách
    'F': 14.0,   # Hạn sửa
    'G': 18.0,   # Trạng thái
    'H': 14.0,   # Mức ưu tiên
    'I': 38.0,   # Sản phẩm đầu ra & Vị trí trong Đề án
}
for col, width in col_widths.items():
    ws.column_dimensions[col].width = width

# ----------------------------------------------------
# ROW 1: MAIN TITLE
# ----------------------------------------------------
ws.merge_cells('A1:I1')
ws['A1'] = "DỰ ÁN AERO - KẾ HOẠCH RÀ SOÁT, TÁI CẤU TRÚC KINH TẾ & TÀI CHÍNH THƯƠNG MẠI HÓA"
ws['A1'].font = title_font
ws['A1'].alignment = Alignment(horizontal='center', vertical='center')
ws.row_dimensions[1].height = 28

# ROW 2: SUBTITLE
ws.merge_cells('A2:I2')
ws['A2'] = "Căn cứ Đề án Sáng tạo trẻ 2026 (Mục 5.1 - 5.5 & Mục 1.3 - 1.4) | Danh mục chi tiết các điểm bất hợp lý cần sửa & mô hình định lượng chuẩn hóa"
ws['A2'].font = subtitle_font
ws['A2'].alignment = Alignment(horizontal='center', vertical='center')
ws.row_dimensions[2].height = 20

ws.row_dimensions[3].height = 8

# ----------------------------------------------------
# ROWS 4-5: KPI SUMMARY CARDS
# ----------------------------------------------------
kpi_cards = [
    ('A4:B4', 'A5:B5', 'NHU CẦU GỌI VỐN SEED', '2,5 TỶ VNĐ', 'Runway: 24 Tháng'),
    ('C4:D4', 'C5:D5', 'DOANH THU DỰ PHÓNG NĂM 1-3', '380Tr → 1,94Tỷ → 5,36Tỷ', 'Tăng trưởng quy mô 60 → 260 → 700 Box'),
    ('E4:F4', 'E5:F5', 'ĐIỂM HÒA VỐN DỰ KIẾN', 'Đầu Năm 3 (Tháng 25)', 'Quy mô hòa vốn: ~520 Box Active'),
    ('G4:G4', 'G5:G5', 'THỊ TRƯỜNG SOM (NĂM 3)', '3,8 – 5,4 TỶ VNĐ', '2 - 3% Thị phần SAM'),
    ('H4:I4', 'H5:I5', 'TIẾN ĐỘ RÀ SOÁT ĐỀ ÁN', '16 Hạng mục (9 Rất cao)', 'Tỷ lệ hoàn thiện tài chính: ~45%'),
]

for top_range, btm_range, label, val, sub in kpi_cards:
    ws.merge_cells(top_range)
    ws.merge_cells(btm_range)
    top_cell = ws[top_range.split(':')[0]]
    btm_cell = ws[btm_range.split(':')[0]]
    
    top_cell.value = label
    top_cell.font = kpi_label_font
    top_cell.alignment = Alignment(horizontal='center', vertical='center')
    top_cell.fill = fill_kpi_card
    
    btm_cell.value = val
    btm_cell.font = kpi_val_font
    btm_cell.alignment = Alignment(horizontal='center', vertical='center')
    btm_cell.fill = fill_kpi_card

ws.row_dimensions[4].height = 18
ws.row_dimensions[5].height = 26
ws.row_dimensions[6].height = 10

# ----------------------------------------------------
# ROW 7: MAIN TABLE HEADERS
# ----------------------------------------------------
headers = [
    "STT",
    "Phân hệ / Đầu mục Đề án cần sửa",
    "Vấn đề bất hợp lý hiện tại & Nguyên nhân cần sửa",
    "Phương án sửa đổi & Số liệu định lượng chuẩn hóa",
    "Nhân sự phụ trách",
    "Hạn sửa",
    "Trạng thái",
    "Mức ưu tiên",
    "Sản phẩm đầu ra (Deliverables) & Vị trí Đề án"
]
for col_idx, h in enumerate(headers, 1):
    cell = ws.cell(row=7, column=col_idx, value=h)
    cell.font = col_header_font
    cell.fill = fill_table_header
    cell.border = border_header
    cell.alignment = align_center
ws.row_dimensions[7].height = 32

# ----------------------------------------------------
# ACTION ITEMS DATA
# ----------------------------------------------------
action_groups = [
    {
        "group_title": "▶ 1. CHUẨN HÓA QUY MÔ THỊ TRƯỜNG & KHẢO SÁT KHÁCH HÀNG (MỤC 5.1 ĐỀ ÁN)",
        "items": [
            (
                "1.1",
                "Mâu thuẫn số liệu TAM - SAM - SOM",
                "Excel ghi TAM 3.500 tỷ, SAM 450 tỷ, SOM 9-22 tỷ; trong khi Word (P381-385) ghi TAM 900 tỷ, SAM 180 tỷ, SOM 3-5 tỷ. Hai tài liệu vênh nhau 3 - 4 lần khiến số liệu thiếu tin cậy.",
                "Thống nhất 100% theo số liệu chuẩn hóa: TAM = 900 tỷ VNĐ/năm (toàn quốc); SAM = 180 tỷ VNĐ/năm (SMEs & chi nhánh tại HN/phụ cận); SOM = 3,8 – 5,4 tỷ VNĐ/năm vào Năm 3 (~700 thiết bị).",
                "Phụ trách Kinh tế / All",
                "20/09/2026",
                "ĐANG SỬA",
                "RẤT CAO",
                "Sửa triệt để Mục 5.1 & Hình 5.1 trong file Sáng tạo trẻ.docx và đồng bộ sheet Excel."
            ),
            (
                "1.2",
                "Thiếu công thức định lượng chi tiết cho SOM",
                "SOM nêu 3-5 tỷ nhưng chưa có công thức chuyển đổi từ SAM sang SOM. Giám khảo không thấy căn cứ tính toán quy mô khách hàng mục tiêu.",
                "Bổ sung công thức: SOM = SAM × 2%–3% thị phần thâm nhập tại HN/phụ cận = 3,8 – 5,4 tỷ VNĐ/năm (tương ứng ~700 thiết bị biên và doanh thu thuê bao lũy kế ở Năm 3).",
                "Phụ trách Kinh tế",
                "22/09/2026",
                "CHỜ DUYỆT",
                "CAO",
                "Bổ sung đoạn thuyết minh công thức chuyển đổi SOM tại Mục 5.1 bản Thuyết minh."
            ),
            (
                "1.3",
                "Dữ liệu khảo sát Nỗi đau khách hàng còn định tính",
                "Nêu khảo sát 15-20 quản trị mạng nhưng chỉ mô tả chung chung bằng lời, thiếu biểu đồ tỷ lệ % quan ngại chi phí, thời gian xử lý sự cố và nhân lực.",
                "Bổ sung bảng số liệu: 85% đơn vị không có SOC chuyên trách; 92% lo ngại chi phí giải pháp ngoại (>200Tr/năm); 78% mong muốn cảnh báo tức thời <1s tại biên mạng.",
                "All",
                "25/09/2026",
                "ĐANG SỬA",
                "CAO",
                "Bổ sung Bảng khảo sát định lượng vào Mục 5.1 và đính kèm Phụ lục B Đề án."
            )
        ]
    },
    {
        "group_title": "▶ 2. TÁI CẤU TRÚC CHI PHÍ PHẦN CỨNG & BÓC TÁCH GIÁ VỐN BOM (MỤC 5.3 ĐỀ ÁN)",
        "items": [
            (
                "2.1",
                "Nghịch lý Giá vốn phần cứng (COGS) 4,33 triệu cho ESP32",
                "Thiết bị biên thực chất dùng ESP32 (linh kiện ~300k-500k) nhưng COGS trong đề án lại ghi 4.331.000 VNĐ. Giám khảo sẽ bắt bẻ ngay rằng BoM vô lý hoặc khai khống chi phí.",
                "Bóc tách cấu trúc giá vốn thành 7 thành phần hoàn chỉnh: BoM linh kiện cốt lõi (450k) + Phụ kiện công nghiệp (280k) + Vỏ IP54/DIN rail (220k) + Kiểm thử Burn-in (350k) + Dịch vụ triển khai on-site (1.800k) + Bảo hành 1-1 (600k) + Hoa hồng SI (630k) = 4.330.000 VNĐ.",
                "Nguyễn Hữu Đức Anh (Hardware Lead)",
                "22/09/2026",
                "RẤT CAO",
                "RẤT CAO",
                "Bảng bóc tách BoM chi tiết 7 thành tố tại Mục 5.3 Word & Bảng tham chiếu 1 Excel."
            ),
            (
                "2.2",
                "Tách bạch Chi phí Dịch vụ Triển khai On-site",
                "Trước đây gộp toàn bộ vào giá vốn thiết bị khiến giá phần cứng bị hiểu nhầm là đắt đỏ. Khách hàng B2B cần biết rõ tiền mua thiết bị vs. tiền dịch vụ cài đặt.",
                "Quy định rõ trong hợp đồng mẫu: Giá thiết bị gồm 2 phần: Thiết bị phần cứng bàn giao (2.500.000 VNĐ) + Gói dịch vụ tích hợp mạng & cấu hình on-site (2.750.000 VNĐ).",
                "Phụ trách Kinh tế",
                "24/09/2026",
                "CHỜ DUYỆT",
                "CAO",
                "Cập nhật cơ cấu gói sản phẩm tại Mục 5.3 và đưa vào Phụ lục Hợp đồng mẫu."
            ),
            (
                "2.3",
                "Rủi ro biên lợi nhuận phần cứng bị âm khi chiết khấu đại lý SI",
                "Mục 5.4 nêu phân phối qua đối tác SI nhưng chưa tính hoa hồng chiết khấu (12-15%). Nếu trừ hoa hồng vào biên lãi 17,5% thì bán thiết bị sẽ bị hòa hoặc lỗ.",
                "Đưa khoản chiết khấu SI Partner 12% (~630.000 VNĐ/box) vào thẳng cấu trúc giá vốn COGS hoặc thỏa thuận chiết khấu lũy tiến trên số lượng thiết bị cam kết.",
                "Phụ trách Kinh tế",
                "26/09/2026",
                "ĐANG SỬA",
                "CAO",
                "Cập nhật Chính sách phân phối đại lý SI tại Mục 5.4 Đề án."
            )
        ]
    },
    {
        "group_title": "▶ 3. ĐỒNG BỘ ĐỊNH GIÁ DỊCH VỤ SAAS & SO SÁNH TCO ĐỐI THỦ (MỤC 5.2 - 5.3 ĐỀ ÁN)",
        "items": [
            (
                "3.1",
                "Mâu thuẫn giá gói dịch vụ SaaS Pro giữa 2 tài liệu",
                "Excel ghi Gói Pro 1.500.000 đ/tháng, Basic 500.000 đ/tháng; Word ghi Basic 300.000 đ/tháng, Pro 550.000 đ/tháng, Enterprise 800.000 đ/tháng. Nếu dùng giá Excel thì bảng tài chính sụp đổ.",
                "Chuẩn hóa 100% toàn bộ tài liệu theo bộ giá: Basic (300.000 đ/tháng) | Pro (550.000 đ/tháng - gói chủ lực tính ARPU) | Enterprise (800.000 đ/tháng).",
                "Phụ trách Kinh tế",
                "20/09/2026",
                "HOÀN THÀNH",
                "RẤT CAO",
                "Đã sửa đồng bộ trong Excel; kiểm tra lại toàn bộ Mục 5.3 trong file Word."
            ),
            (
                "3.2",
                "Thiếu bảng so sánh chi phí sở hữu tổng thể (TCO Comparison)",
                "Đề án tuyên bố 'giá thành bằng 1/5 giải pháp truyền thống' nhưng thiếu bảng so sánh TCO 3 năm chi tiết với Fortinet, Sophos, Snort để chứng minh luận điểm.",
                "Xây dựng bảng so sánh TCO 3 năm cho mạng 10 điểm biên: Fortinet FortiGate (~250-380Tr), Snort Server (~160-220Tr) vs AERO Edge AI (~80-95Tr). Chứng minh tiết kiệm 65% – 75%.",
                "Lê Việt Anh / AI Lead",
                "23/09/2026",
                "ĐANG SỬA",
                "CAO",
                "Bổ sung Bảng so sánh TCO vào Mục 5.3 & Bảng tham chiếu 2 Excel."
            )
        ]
    },
    {
        "group_title": "▶ 4. TÁI LẬP CHI PHÍ VẬN HÀNH OPEX, QUỸ LƯƠNG & CLOUD DATA LAKE (MỤC 5.3 & 5.5)",
        "items": [
            (
                "4.1",
                "Quỹ lương 58 triệu/tháng cho 5-6 nhân sự là phi thực tế",
                "Ngân sách nhân sự 700 triệu/12 tháng chia 5 người chỉ được 9-11 triệu/người/tháng. Không đủ để duy trì đội ngũ kỹ thuật an ninh mạng làm việc full-time.",
                "Phân kỳ quỹ nhân sự 2 giai đoạn: Giai đoạn 1 (Tháng 1-12): Trợ cấp Co-founders (4 người × 8-10Tr) + thuê chuyên gia cố vấn part-time (15-20Tr/tháng) = ~58Tr/tháng. Giai đoạn 2: Tăng lương chính thức lấy từ dòng tiền doanh thu SaaS lũy kế.",
                "All Co-founders",
                "24/09/2026",
                "ĐANG SỬA",
                "RẤT CAO",
                "Bổ sung giải trình phân kỳ quỹ lương tại Mục 1.4 và Mục 5.5 Đề án."
            ),
            (
                "4.2",
                "Thiếu hoàn toàn dự toán chi phí Cloud Server & Data Lakehouse",
                "Hệ thống thu thập telemetry 1s/lần, lưu trữ Parquet, xử lý 56 đặc trưng nhưng chi phí hạ tầng máy chủ bị bỏ trống hoàn toàn trong bảng tài chính.",
                "Lập bảng dự toán chi phí Cloud Server theo quy mô box: Năm 1 (60 box): ~3,5Tr/tháng (~42Tr/năm); Năm 2 (260 box): ~8,5Tr/tháng (~102Tr/năm); Năm 3 (700 box): ~18Tr/tháng (~216Tr/năm).",
                "Nguyễn Hữu Đức Anh (Backend)",
                "25/09/2026",
                "ĐANG SỬA",
                "CAO",
                "Bổ sung Bảng dự toán Cloud Data Lake tại Bảng tham chiếu 3 & Mục 5.3."
            ),
            (
                "4.3",
                "Chi phí Marketing & Bán hàng (CAC 3.000.000 VNĐ) thiếu bóc tách",
                "CAC 3 triệu/khách chỉ là ước tính chia đều (500Tr / 160 khách), chưa có breakdown chi phí từng kênh tiếp cận thị trường cụ thể.",
                "Phân bổ ngân sách Marketing 500 triệu (12-18 tháng đầu): Chương trình Pilot POC miễn phí 5 đối tác (150Tr) + Content kỹ thuật/Whitepaper (80Tr) + Gian hàng sự kiện Sáng tạo trẻ/Hội thảo (120Tr) + Hoa hồng mở đại lý SI (150Tr).",
                "Phụ trách Kinh tế",
                "27/09/2026",
                "CHỜ DUYỆT",
                "CAO",
                "Bổ sung Bảng phân bổ ngân sách GTM chi tiết tại Mục 5.4 Đề án."
            )
        ]
    },
    {
        "group_title": "▶ 5. HOÀN THIỆN MÔ HÌNH UNIT ECONOMICS & DỰ PHÓNG P&L 3 NĂM (MỤC 5.5 ĐỀ ÁN)",
        "items": [
            (
                "5.1",
                "Công thức LTV chưa tính tác động của Churn Rate",
                "LTV tính bằng cách nhân thẳng 24 tháng (8,84 triệu) mà chưa trừ tỷ lệ khách hàng rời bỏ (Churn 3% năm 1, 1.2% năm 2), làm thổi phồng LTV.",
                "Tính LTV chiết khấu theo thời gian duy trì thực tế (~19,2 tháng do churn) → LTV thực tế = 0,92Tr (lãi box) + (0,33Tr × 19,2 tháng) ≈ 7,25 triệu VNĐ → LTV/CAC đạt 2,42x (vẫn an toàn > 2,0x).",
                "Phụ trách Kinh tế",
                "25/09/2026",
                "ĐANG SỬA",
                "RẤT CAO",
                "Hiệu chỉnh công thức và bảng Unit Economics tại Mục 5.5 bản Thuyết minh."
            ),
            (
                "5.2",
                "Dự phóng Tài chính trong Excel chưa có bảng số liệu chi tiết",
                "Excel chỉ có 1 dòng ghi tổng doanh thu 3 năm, không có bảng phân bổ doanh thu phần cứng, doanh thu thuê bao, COGS, OPEX và dòng tiền theo quý.",
                "Xây dựng bảng dự phóng P&L chi tiết 3 Năm: Năm 1 (DT 380Tr, CP 980Tr, Dòng tiền thuần -600Tr); Năm 2 (DT 1.940Tr, CP 2.230Tr, Dòng tiền thuần -290Tr, Lũy kế -890Tr); Năm 3 (DT 5.360Tr, CP 3.860Tr, Dòng tiền thuần +1.500Tr, Lũy kế +610Tr).",
                "Phụ trách Kinh tế",
                "26/09/2026",
                "ĐANG SỬA",
                "RẤT CAO",
                "Bảng P&L 3 Năm tham chiếu 4 tại Excel và cập nhật Hình 5.2 Word."
            ),
            (
                "5.3",
                "Thiếu kịch bản độ nhạy tài chính (Base / Worst / Best Case)",
                "Mục 5.5.1 trong Word yêu cầu phân tích kịch bản tốt/xấu nhưng chưa có bảng số liệu so sánh khi tốc độ bán hàng không đạt kỳ vọng.",
                "Lập 3 kịch bản: Kịch bản Cơ sở (Base Case: 700 box, DT 5,36 tỷ), Kịch bản Thận trọng (Worst Case: đạt 60% kế hoạch, 420 box, cần kéo dài runway), Kịch bản Tăng trưởng (Best Case: đạt 130% kế hoạch, 910 box).",
                "All",
                "28/09/2026",
                "CHỜ DUYỆT",
                "TRUNG BÌNH",
                "Bổ sung Mục 5.5.1 Kịch bản tài chính tốt/xấu trong file Word."
            )
        ]
    },
    {
        "group_title": "▶ 6. KẾ HOẠCH GỌI VỐN 2,5 TỶ, RUNWAY & ĐIỂM HÒA VỐN (MỤC 1.4 & 5.5 ĐỀ ÁN)",
        "items": [
            (
                "6.1",
                "Chứng minh quy mô vốn gọi 2,5 tỷ VNĐ và mức dòng tiền âm lũy kế",
                "Con số gọi vốn 2,5 tỷ chưa giải trình được vì sao cần 2,5 tỷ mà không phải 1,5 hay 3 tỷ. Chưa liên kết chặt chẽ với lộ trình dòng tiền âm.",
                "Chứng minh bằng dòng tiền âm cực đại: Cuối năm 2 dòng tiền âm lũy kế là -890 triệu VNĐ + CAPEX mở rộng (300-500Tr) + Quỹ dự phòng an toàn 24 tháng cho chi phí cố định (~1 tỷ) = Tổng nhu cầu an toàn là 2,5 tỷ VNĐ.",
                "All",
                "20/09/2026",
                "HOÀN THÀNH",
                "RẤT CAO",
                "Hoàn thiện thuyết minh Mục 1.4 & Bảng tham chiếu 5 Excel."
            ),
            (
                "6.2",
                "Mô hình hóa điểm hòa vốn (Break-even Point) theo quy mô thiết bị",
                "Chưa nêu rõ điểm hòa vốn theo tháng và số lượng thiết bị hoạt động tối thiểu để bù đắp chi phí cố định hàng tháng.",
                "Điểm hòa vốn xác định tại Tháng thứ 25 (Đầu Năm 3), khi quy mô đạt ~520 thiết bị duy trì thuê bao (Doanh thu định kỳ đạt ~286Tr/tháng ≥ Chi phí OPEX cố định ~250Tr/tháng).",
                "Phụ trách Kinh tế",
                "25/09/2026",
                "ĐANG SỬA",
                "CAO",
                "Bổ sung đồ thị & phân tích điểm hòa vốn tại Mục 5.5."
            )
        ]
    }
]

# Insert action items
current_row = 8
for grp in action_groups:
    # Group header row
    ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
    g_cell = ws.cell(row=current_row, column=1, value=grp["group_title"])
    g_cell.font = section_header_font
    g_cell.fill = fill_section_group
    g_cell.alignment = Alignment(horizontal='left', vertical='center', indent=1)
    for c in range(1, 10):
        ws.cell(row=current_row, column=c).border = border_all_thin
    ws.row_dimensions[current_row].height = 25
    current_row += 1
    
    for item in grp["items"]:
        stt, task, issue, solution, owner, deadline, status, priority, deliverable = item
        
        c_stt = ws.cell(row=current_row, column=1, value=stt)
        c_task = ws.cell(row=current_row, column=2, value=task)
        c_issue = ws.cell(row=current_row, column=3, value=issue)
        c_sol = ws.cell(row=current_row, column=4, value=solution)
        c_owner = ws.cell(row=current_row, column=5, value=owner)
        c_dl = ws.cell(row=current_row, column=6, value=deadline)
        c_st = ws.cell(row=current_row, column=7, value=status)
        c_pr = ws.cell(row=current_row, column=8, value=priority)
        c_del = ws.cell(row=current_row, column=9, value=deliverable)
        
        c_stt.alignment = align_center
        c_task.alignment = align_left
        c_issue.alignment = align_left
        c_sol.alignment = align_left
        c_owner.alignment = align_center
        c_dl.alignment = align_center
        c_st.alignment = align_center
        c_pr.alignment = align_center
        c_del.alignment = align_left
        
        for c in [c_stt, c_task, c_issue, c_sol, c_owner, c_dl, c_del]:
            c.font = cell_font
            c.border = border_all_thin
        c_stt.font = cell_code_font
        c_task.font = cell_bold_font
        
        # Format Status
        c_st.border = border_all_thin
        if status == "HOÀN THÀNH":
            c_st.fill = fill_status_done
            c_st.font = font_status_done
        elif status == "ĐANG SỬA":
            c_st.fill = fill_status_inprogress
            c_st.font = font_status_inprogress
        else: # CHỜ DUYỆT
            c_st.fill = fill_status_review
            c_st.font = font_status_review
            
        # Format Priority
        c_pr.border = border_all_thin
        if priority == "RẤT CAO":
            c_pr.fill = fill_status_urgent
            c_pr.font = font_status_urgent
        elif priority == "CAO":
            c_pr.fill = fill_status_inprogress
            c_pr.font = font_status_inprogress
        else:
            c_pr.fill = fill_kpi_card
            c_pr.font = cell_font
            
        ws.row_dimensions[current_row].height = 42
        current_row += 1

current_row += 1

# ----------------------------------------------------
# PHẦN 2: CÁC BẢNG DỮ LIỆU ĐỊNH LƯỢNG CHUẨN HÓA THAM CHIẾU
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
t2_cell = ws.cell(row=current_row, column=1, value="PHẦN B: CÁC BẢNG DỮ LIỆU ĐỊNH LƯỢNG CHUẨN HÓA THAM CHIẾU (FINANCIAL REFERENCE DATA TABLES)")
t2_cell.font = Font(name=FONT_NAME, size=13, bold=True, color="FFFFFF")
t2_cell.fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid") # Deep Slate 900
t2_cell.alignment = Alignment(horizontal='center', vertical='center')
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 30
current_row += 2

# ----------------------------------------------------
# BẢNG B1: BÓC TÁCH CHI TIẾT GIÁ VỐN (COGS) THIẾT BỊ EDGE PROBE
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
b1_title = ws.cell(row=current_row, column=1, value="BẢNG B1: BÓC TÁCH CHI TIẾT GIÁ VỐN HÀNG BÁN (COGS) THIẾT BỊ AERO EDGE PROBE (GIÁ BÁN: 5.250.000 VNĐ)")
b1_title.font = section_header_font
b1_title.fill = fill_table_header
b1_title.alignment = Alignment(horizontal='left', vertical='center', indent=1)
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 25
current_row += 1

b1_headers = ["Mã BoM", "Hạng mục Cấu thành Giá vốn Thiết bị", "Chi tiết Kỹ thuật / Quy cách Linh kiện", "Đơn giá (VNĐ)", "Tỷ trọng (%)", "Ghi chú & Căn cứ Xác định", "Phân loại Chi phí", "Nhà cung ứng / Đơn vị thực hiện", "Giải trình Thuyết minh Đề án"]
for c_idx, h in enumerate(b1_headers, 1):
    c = ws.cell(row=current_row, column=c_idx, value=h)
    c.font = col_header_font
    c.fill = fill_sub_table_header
    c.border = border_header
    c.alignment = align_center
ws.row_dimensions[current_row].height = 24
current_row += 1

bom_rows = [
    ("BOM-01", "Module Vi xử lý & Mạng cốt lõi", "ESP32-S3-WROOM-1 (16MB Flash, 8MB PSRAM) + LAN8720A Ethernet + TVS Diode", 450000, "10.4%", "Mạch chính trích xuất 56 đặc trưng thời gian thực", "Linh kiện trực tiếp", "Espressif / Đại lý cấp 1", "Mục 4.1 & 4.3 Đề án"),
    ("BOM-02", "Bộ Phụ kiện Công nghiệp", "Bộ đổi nguồn MeanWell 5V/2A công nghiệp + Cáp đúc Cat6 chống nhiễu 3m", 280000, "6.5%", "Đảm bảo hoạt động liên tục 24/7 ổn định nhiệt độ", "Linh kiện trực tiếp", "MeanWell Vietnam", "Mục 4.3 Kiểm định 24/7"),
    ("BOM-03", "Vỏ hộp Công nghiệp & Gá lắp", "Hộp nhựa ABS kỹ thuật chuẩn IP54 + Gá ray DIN rail 35mm tủ rack + ốc vít đồng", 220000, "5.1%", "Lắp đặt linh hoạt trong tủ mạng văn phòng/nhà xưởng", "Linh kiện trực tiếp", "Xưởng gia công khuôn mẫu", "Mục 4.3 Đóng gói sản phẩm"),
    ("BOM-04", "Gia công SMT, Nạp FW & Burn-in Test", "Chi phí hàn dán SMT, nạp firmware, kiểm thử tải cao 48h tại phòng lab", 350000, "8.1%", "Đo tỷ lệ rớt gói tin và độ trễ phân tích < 0.1ms", "Nhân công trực tiếp", "Đội ngũ kỹ thuật AERO", "Mục 4.3 Giai đoạn 5"),
    ("BOM-05", "Dịch vụ Khảo sát & Lắp đặt On-site", "Kỹ thuật viên đến trực tiếp văn phòng khách hàng cấu hình SPAN port & VLAN", 1800000, "41.6%", "Dịch vụ triển khai chuyên nghiệp bảo đảm kết nối an toàn", "Dịch vụ triển khai", "Đội triển khai hiện trường", "Mục 5.3 & 5.4 Bán hàng B2B"),
    ("BOM-06", "Dự phòng Bảo hành 1 Đổi 1 & Linh kiện", "Quỹ dự phòng đổi mới ngay trong 24h khi có sự cố phần cứng trong 12 tháng", 600000, "13.9%", "Tỷ lệ hỏng hóc dự phòng 5% + chi phí vận chuyển bảo hành", "Bảo hành & Hỗ trợ", "Bộ phận CS & Hậu mãi", "Mục 5.3 Chính sách bảo hành"),
    ("BOM-07", "Chiết khấu Kênh Đối tác SI (12%)", "Hoa hồng chia sẻ cho đại lý tích hợp hệ thống vừa và nhỏ tại Hà Nội", 630000, "14.5%", "Đảm bảo đối tác có động lực phân phối phần cứng AERO", "Chi phí bán hàng", "Đối tác SI phân phối", "Mục 5.4 Kênh B2B2C")
]

start_bom_row = current_row
for row_data in bom_rows:
    code, name, spec, cost, pct, note, cost_type, vendor, ref = row_data
    ws.cell(row=current_row, column=1, value=code).alignment = align_center
    ws.cell(row=current_row, column=2, value=name).alignment = align_left
    ws.cell(row=current_row, column=3, value=spec).alignment = align_left
    
    c_cost = ws.cell(row=current_row, column=4, value=cost)
    c_cost.alignment = align_right
    c_cost.number_format = '#,##0 "đ"'
    
    ws.cell(row=current_row, column=5, value=pct).alignment = align_center
    ws.cell(row=current_row, column=6, value=note).alignment = align_left
    ws.cell(row=current_row, column=7, value=cost_type).alignment = align_center
    ws.cell(row=current_row, column=8, value=vendor).alignment = align_left
    ws.cell(row=current_row, column=9, value=ref).alignment = align_left
    
    for c_idx in range(1, 10):
        ws.cell(row=current_row, column=c_idx).font = cell_font
        ws.cell(row=current_row, column=c_idx).border = border_all_thin
    ws.cell(row=current_row, column=2).font = cell_bold_font
    ws.row_dimensions[current_row].height = 22
    current_row += 1

# Total BoM Row
ws.cell(row=current_row, column=1, value="TỔNG COGS").alignment = align_center
ws.cell(row=current_row, column=2, value="TỔNG GIÁ VỐN HÀNG BÁN / 1 THIẾT BỊ").alignment = align_left
ws.cell(row=current_row, column=3, value="Đã bao gồm thiết bị + phụ kiện + công lắp đặt on-site + bảo hành + hoa hồng SI").alignment = align_left
c_tot = ws.cell(row=current_row, column=4, value=f"=SUM(D{start_bom_row}:D{current_row-1})")
c_tot.alignment = align_right
c_tot.number_format = '#,##0 "đ"'
ws.cell(row=current_row, column=5, value="100.0%").alignment = align_center
ws.cell(row=current_row, column=6, value="Biên lợi nhuận gộp thiết bị: 17,5% (Lợi nhuận gộp: 920.000 đ/box)").alignment = align_left
ws.cell(row=current_row, column=7, value="Giá bán niêm yết:").alignment = align_right
ws.cell(row=current_row, column=8, value="5.250.000 đ").alignment = align_center
ws.cell(row=current_row, column=9, value="Khớp 100% Mục 5.3 & 5.5").alignment = align_left

for c_idx in range(1, 10):
    c = ws.cell(row=current_row, column=c_idx)
    c.font = cell_bold_font
    c.fill = fill_total_row
    c.border = border_total
ws.row_dimensions[current_row].height = 24
current_row += 2

# ----------------------------------------------------
# BẢNG B2: MA TRẬN ĐỊNH GIÁ DỊCH VỤ SAAS & SO SÁNH TCO
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
b2_title = ws.cell(row=current_row, column=1, value="BẢNG B2: MA TRẬN ĐỊNH GIÁ DỊCH VỤ SAAS & SO SÁNH CHI PHÍ SỞ HỮU TỔNG THỂ (TCO 3 NĂM)")
b2_title.font = section_header_font
b2_title.fill = fill_table_header
b2_title.alignment = Alignment(horizontal='left', vertical='center', indent=1)
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 25
current_row += 1

b2_headers = ["Gói Dịch vụ", "Giá thuê bao / tháng", "Biên lãi gộp", "Tính năng Phát hiện Bất thường", "Quản lý Data Lakehouse", "Dashboard & Báo cáo", "Thời gian lưu trữ log", "SLA Hỗ trợ", "Đối tượng Khách hàng Mục tiêu"]
for c_idx, h in enumerate(b2_headers, 1):
    c = ws.cell(row=current_row, column=c_idx, value=h)
    c.font = col_header_font
    c.fill = fill_sub_table_header
    c.border = border_header
    c.alignment = align_center
ws.row_dimensions[current_row].height = 24
current_row += 1

saas_rows = [
    ("Gói Basic", "300.000 đ", "58.0%", "Giám sát lưu lượng biên cơ bản + Rule-based", "Lưu trữ nội bộ SQLite Catalog", "Dashboard Web cơ bản", "7 ngày", "Giờ hành chính (8/5)", "Văn phòng nhỏ, trường mầm non, cửa hàng"),
    ("Gói Pro (Chủ lực)", "550.000 đ", "60.0%", "Dual ML Pipeline: Anomaly (Tier 1) + Classifier 15 lớp (Tier 2)", "Đầy đủ Parquet Hot/Cold Storage + Partition ngày", "Dashboard SOC Realtime + Webhook cảnh báo", "30 ngày", "Phản hồi < 4h (12/7)", "SMEs 50-300 thiết bị, trường học, chi nhánh ngân hàng"),
    ("Gói Enterprise", "800.000 đ", "65.0%", "Full ML Suite + Tùy biến ngưỡng theo từng điểm giám sát", "Data Lakehouse dài hạn + Trích xuất huấn luyện lại", "Multi-tenant Dashboard + Tích hợp SIEM/Syslog", "12 tháng", "Ưu tiên 24/7 + Onsite", "Hạ tầng mạng phân tán, chuỗi chi nhánh, bệnh viện")
]

for row_data in saas_rows:
    for c_idx, val in enumerate(row_data, 1):
        c = ws.cell(row=current_row, column=c_idx, value=val)
        c.font = cell_font
        c.border = border_all_thin
        if c_idx in [1, 2, 3, 7, 8]:
            c.alignment = align_center
        else:
            c.alignment = align_left
        if c_idx == 1:
            c.font = cell_bold_font
    ws.row_dimensions[current_row].height = 24
    current_row += 1

current_row += 1

# ----------------------------------------------------
# BẢNG B3: DỰ TOÁN CHI PHÍ HẠ TẦNG CLOUD & DATA LAKEHOUSE
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
b3_title = ws.cell(row=current_row, column=1, value="BẢNG B3: DỰ TOÁN CHI PHÍ HẠ TẦNG MÁY CHỦ CLOUD & PARQUET DATA LAKEHOUSE (NĂM 1 - NĂM 3)")
b3_title.font = section_header_font
b3_title.fill = fill_table_header
b3_title.alignment = Alignment(horizontal='left', vertical='center', indent=1)
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 25
current_row += 1

b3_headers = ["Giai đoạn", "Số Box Hoạt động", "Lưu lượng Bản ghi / Tháng", "Cấu hình Máy chủ Cloud", "Lưu trữ Data Lake Parquet", "Băng thông & Mạng", "Chi phí / Tháng", "Tổng Chi phí / Năm", "Ghi chú Vận hành & Mở rộng"]
for c_idx, h in enumerate(b3_headers, 1):
    c = ws.cell(row=current_row, column=c_idx, value=h)
    c.font = col_header_font
    c.fill = fill_sub_table_header
    c.border = border_header
    c.alignment = align_center
ws.row_dimensions[current_row].height = 24
current_row += 1

cloud_rows = [
    ("Năm 1 (Thương mại hóa)", "60 Thiết bị", "~5,1 triệu bản ghi / tháng", "1x VPS (4 vCPU, 8GB RAM, SSD 100GB)", "Cloud Object Storage 300GB", "IP Tĩnh + 2TB Băng thông", 3500000, 42000000, "1 Instance chạy Embedded MQTT Broker + Ingestion Collector"),
    ("Năm 2 (Mở rộng quy mô)", "260 Thiết bị", "~22,4 triệu bản ghi / tháng", "Cụm 2x VPS (8 vCPU, 16GB RAM)", "Parquet Data Lake 2TB (Snappy)", "IP Tĩnh + 5TB Băng thông", 8500000, 102000000, "Cân bằng tải Nginx, tách biệt Ingestion Collector và Dashboard"),
    ("Năm 3 (Tăng trưởng cao)", "700 Thiết bị", "~60,4 triệu bản ghi / tháng", "Cụm Cloud Scaling (16 vCPU, 32GB RAM)", "Data Lake Tiering 8TB (Hot/Cold)", "Dedicated 1Gbps Port", 18000000, 216000000, "Tối ưu hóa nén Parquet theo phân vùng ngày và backup SQLite")
]

for row_data in cloud_rows:
    p, b_cnt, recs, conf, stg, bw, m_cost, y_cost, note = row_data
    ws.cell(row=current_row, column=1, value=p).alignment = align_center
    ws.cell(row=current_row, column=2, value=b_cnt).alignment = align_center
    ws.cell(row=current_row, column=3, value=recs).alignment = align_center
    ws.cell(row=current_row, column=4, value=conf).alignment = align_left
    ws.cell(row=current_row, column=5, value=stg).alignment = align_left
    ws.cell(row=current_row, column=6, value=bw).alignment = align_center
    
    c_m = ws.cell(row=current_row, column=7, value=m_cost)
    c_m.alignment = align_right
    c_m.number_format = '#,##0 "đ"'
    
    c_y = ws.cell(row=current_row, column=8, value=y_cost)
    c_y.alignment = align_right
    c_y.number_format = '#,##0 "đ"'
    
    ws.cell(row=current_row, column=9, value=note).alignment = align_left
    
    for c_idx in range(1, 10):
        ws.cell(row=current_row, column=c_idx).font = cell_font
        ws.cell(row=current_row, column=c_idx).border = border_all_thin
    ws.cell(row=current_row, column=1).font = cell_bold_font
    ws.row_dimensions[current_row].height = 22
    current_row += 1

current_row += 1

# ----------------------------------------------------
# BẢNG B4: BẢNG DỰ PHÓNG TÀI CHÍNH P&L 3 NĂM
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
b4_title = ws.cell(row=current_row, column=1, value="BẢNG B4: BẢNG DỰ PHÓNG TÀI CHÍNH 3 NĂM & CÁC CỘT MỐC DÒNG TIỀN (NĂM 1 - NĂM 3)")
b4_title.font = section_header_font
b4_title.fill = fill_table_header
b4_title.alignment = Alignment(horizontal='left', vertical='center', indent=1)
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 25
current_row += 1

b4_headers = ["Chỉ tiêu Tài chính (Đơn vị: Triệu VNĐ)", "Năm 1 (Q1-Q4)", "Năm 2 (Q5-Q8)", "Năm 3 (Q9-Q12)", "Tổng 3 Năm", "Công thức / Phương pháp tính toán", "Giả định Churn & Tăng trưởng", "Căn cứ trong Đề án", "Đánh giá Tính khả thi"]
for c_idx, h in enumerate(b4_headers, 1):
    c = ws.cell(row=current_row, column=c_idx, value=h)
    c.font = col_header_font
    c.fill = fill_sub_table_header
    c.border = border_header
    c.alignment = align_center
ws.row_dimensions[current_row].height = 24
current_row += 1

pnl_rows = [
    ("Số thiết bị bán mới trong năm (Box)", 60, 200, 440, "=SUM(B{r}:D{r})", "Kế hoạch bán hàng qua kênh Direct + Đối tác SI", "Năm 1: 15 box/quý; N2: 50 box/quý; N3: 110 box/quý", "Mục 5.4 & 5.5", "Khả thi cao"),
    ("Số thiết bị lũy kế lắp đặt (Box)", 60, 260, 700, 700, "Lũy kế thiết bị biên vật lý đã xuất xưởng", "Khách hàng mua phần cứng không đổi", "Mục 5.5 Hình 5.2", "Đạt mục tiêu SOM"),
    ("Số thuê bao duy trì hoạt động (Active Subs)", 54, 230, 640, 640, "Đã trừ tỷ lệ rời bỏ Churn (N1: 3%/tháng, N2+: 1.2%/tháng)", "Retention sau 24 tháng đạt ~65%", "Mục 5.5 Churn model", "Chuẩn SaaS B2B"),
    ("Doanh thu Bán thiết bị (Hardware Revenue)", 315.0, 1050.0, 2310.0, "=SUM(B{r}:D{r})", "Số box bán mới × Giá 5,25 triệu VNĐ/thiết bị", "Giá niêm yết không đổi trong 3 năm", "Mục 5.3 & 5.5", "Dòng tiền tức thời"),
    ("Doanh thu Thuê bao dịch vụ (SaaS Subscription)", 65.0, 890.0, 3050.0, "=SUM(B{r}:D{r})", "Số thuê bao active × ARPU 550.000 VNĐ/tháng", "Doanh thu định kỳ tích lũy theo thời gian", "Mục 5.3 & 5.5", "Biên lợi nhuận cao"),
    ("TỔNG DOANH THU (REVENUE)", 380.0, 1940.0, 5360.0, "=SUM(B{r}:D{r})", "Doanh thu Thiết bị + Doanh thu Thuê bao SaaS", "Tăng trưởng: N2 gấp 5.1x; N3 gấp 2.8x", "Khớp 100% P503-505", "Đạt mục tiêu đề án"),
    ("Giá vốn hàng bán (COGS Phần cứng & Dịch vụ)", 270.0, 930.0, 2010.0, "=SUM(B{r}:D{r})", "COGS phần cứng (4,33Tr/box) + Chi phí server direct", "Biên gộp tổng thể cải thiện từ 29% lên 62%", "Mục 5.3 BoM chi tiết", "Kiểm soát tốt"),
    ("Chi phí Vận hành (OPEX & Nhân sự, Mkt, R&D)", 710.0, 1300.0, 1850.0, "=SUM(B{r}:D{r})", "Lương đội ngũ + Cloud Server + Mkt/Sales + R&D", "Tối ưu hóa quy mô khi mở rộng", "Mục 1.4 & 5.5", "Thực tế và an toàn"),
    ("TỔNG CHI PHÍ (COGS + OPEX)", 980.0, 2230.0, 3860.0, "=SUM(B{r}:D{r})", "Tổng toàn bộ dòng tiền chi ra trong năm", "Khớp 100% số liệu P507-509 Thuyết minh", "Khớp 100% P507-509", "Đã cân đối vốn gọi"),
    ("DÒNG TIỀN THUẦN TRONG NĂM (NET CASHFLOW)", -600.0, -290.0, 1500.0, "=SUM(B{r}:D{r})", "Tổng Doanh thu - Tổng Chi phí", "Năm 1 & 2 âm dòng tiền để xây dựng mạng lưới", "Khớp 100% P511-513", "Quy luật Startup"),
    ("DÒNG TIỀN LŨY KẾ (CUMULATIVE CASHFLOW)", -600.0, -890.0, 610.0, 610.0, "Dòng tiền thuần tích lũy qua từng năm", "Điểm hòa vốn xuất hiện vào đầu Năm 3", "Khớp 100% P515-517", "Cơ sở gọi 2.5 Tỷ")
]

for row_data in pnl_rows:
    metric, y1, y2, y3, tot, formula_desc, churn_note, doc_ref, eval_text = row_data
    
    ws.cell(row=current_row, column=1, value=metric).alignment = align_left
    
    # Check if formula for total
    if isinstance(tot, str) and "{r}" in tot:
        tot_val = tot.format(r=current_row)
    else:
        tot_val = tot
        
    c_y1 = ws.cell(row=current_row, column=2, value=y1)
    c_y2 = ws.cell(row=current_row, column=3, value=y2)
    c_y3 = ws.cell(row=current_row, column=4, value=y3)
    c_tot = ws.cell(row=current_row, column=5, value=tot_val)
    
    for c_num, val in [(c_y1, y1), (c_y2, y2), (c_y3, y3), (c_tot, tot_val)]:
        c_num.alignment = align_right
        if isinstance(val, float) or (isinstance(val, str) and val.startswith("=")):
            c_num.number_format = '#,##0.0 "Tr"'
        elif isinstance(val, int):
            c_num.number_format = '#,##0'
            
    ws.cell(row=current_row, column=6, value=formula_desc).alignment = align_left
    ws.cell(row=current_row, column=7, value=churn_note).alignment = align_left
    ws.cell(row=current_row, column=8, value=doc_ref).alignment = align_center
    ws.cell(row=current_row, column=9, value=eval_text).alignment = align_center
    
    is_bold_row = any(k in metric for k in ["TỔNG", "LŨY KẾ", "THUẦN"])
    for c_idx in range(1, 10):
        cell_obj = ws.cell(row=current_row, column=c_idx)
        cell_obj.border = border_all_thin
        cell_obj.font = cell_bold_font if is_bold_row else cell_font
        if is_bold_row:
            cell_obj.fill = fill_zebra
    ws.row_dimensions[current_row].height = 22
    current_row += 1

current_row += 1

# ----------------------------------------------------
# BẢNG B5: KẾ HOẠCH SỬ DỤNG VỐN GỌI SEED ROUND (2,5 TỶ VNĐ)
# ----------------------------------------------------
ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=9)
b5_title = ws.cell(row=current_row, column=1, value="BẢNG B5: KẾ HOẠCH PHÂN BỔ VÀ SỬ DỤNG VỐN GỌI VÒNG HẠT GIỐNG (SEED ROUND: 2.500.000.000 VNĐ)")
b5_title.font = section_header_font
b5_title.fill = fill_table_header
b5_title.alignment = Alignment(horizontal='left', vertical='center', indent=1)
for c in range(1, 10):
    ws.cell(row=current_row, column=c).border = border_all_thin
ws.row_dimensions[current_row].height = 25
current_row += 1

b5_headers = ["Trụ cột Phân bổ Vốn", "Tỷ lệ (%)", "Số tiền (VNĐ)", "Mục tiêu & Hạng mục Chi tiêu Chi tiết", "Mốc Giải ngân (Milestones)", "Kết quả Nghiệm thu Dự kiến", "Thời gian Sử dụng Vốn", "Phụ trách Quản lý Quỹ", "Căn cứ Đề án"]
for c_idx, h in enumerate(b5_headers, 1):
    c = ws.cell(row=current_row, column=c_idx, value=h)
    c.font = col_header_font
    c.fill = fill_sub_table_header
    c.border = border_header
    c.alignment = align_center
ws.row_dimensions[current_row].height = 24
current_row += 1

seed_rows = [
    ("1. R&D / Sản phẩm & Phần cứng", "42.0%", 1050000000, "Hoàn thiện MVP, thiết kế mạch PCB công nghiệp, kiểm định chứng nhận an toàn, tối ưu mô hình TinyML & Dual ML Pipeline", "Q3/2026 - Q1/2027", "Lô 60 thiết bị chuẩn hóa thương mại + Model artifacts", "12 tháng đầu", "Nguyễn Hữu Đức Anh (AI Lead)", "Mục 1.4 & Mục 4.3"),
    ("2. Nhân sự Kỹ thuật & Vận hành", "28.0%", 700000000, "Duy trì phụ cấp 4 Co-founders toàn thời gian + thuê cố vấn chuyên gia an ninh mạng độc lập + 1 kỹ thuật viên triển khai", "Hàng tháng (Tháng 1-12)", "Đảm bảo vận hành hệ thống 24/7 và hỗ trợ khách hàng", "12 tháng đầu", "Ban Điều hành AERO", "Mục 1.4 & Mục 6.1"),
    ("3. Marketing & Phát triển Thị trường", "20.0%", 500000000, "Triển khai chương trình Pilot POC 5 đối tác, tham gia sự kiện Sáng tạo trẻ, viết Whitepaper, mở rộng 3 đại lý SI tại Hà Nội", "Q4/2026 - Q2/2027", "60 khách hàng trả phí đầu tiên + 3 đối tác phân phối", "18 tháng", "Phụ trách Kinh tế / All", "Mục 1.4 & Mục 5.4"),
    ("4. Dự phòng Rủi ro & Pháp lý", "10.0%", 250000000, "Chi phí đăng ký bản quyền SHTT, thành lập doanh nghiệp KH&CN, dự phòng biến động giá linh kiện và rủi ro thị trường", "Dự phòng linh hoạt", "Giấy phép SHTT + Đăng ký kinh doanh + Quỹ khẩn cấp", "24 tháng", "Đại diện Pháp luật AERO", "Mục 1.4 & Mục 4.4")
]

start_seed_row = current_row
for row_data in seed_rows:
    pillar, pct, amt, purpose, milestone, deliverable, timeline, manager, doc_ref = row_data
    ws.cell(row=current_row, column=1, value=pillar).alignment = align_left
    ws.cell(row=current_row, column=2, value=pct).alignment = align_center
    
    c_amt = ws.cell(row=current_row, column=3, value=amt)
    c_amt.alignment = align_right
    c_amt.number_format = '#,##0 "đ"'
    
    ws.cell(row=current_row, column=4, value=purpose).alignment = align_left
    ws.cell(row=current_row, column=5, value=milestone).alignment = align_center
    ws.cell(row=current_row, column=6, value=deliverable).alignment = align_left
    ws.cell(row=current_row, column=7, value=timeline).alignment = align_center
    ws.cell(row=current_row, column=8, value=manager).alignment = align_left
    ws.cell(row=current_row, column=9, value=doc_ref).alignment = align_center
    
    for c_idx in range(1, 10):
        ws.cell(row=current_row, column=c_idx).font = cell_font
        ws.cell(row=current_row, column=c_idx).border = border_all_thin
    ws.cell(row=current_row, column=1).font = cell_bold_font
    ws.row_dimensions[current_row].height = 26
    current_row += 1

# Total Seed Row
ws.cell(row=current_row, column=1, value="TỔNG VỐN GỌI VÒNG HẠT GIỐNG").alignment = align_center
ws.cell(row=current_row, column=2, value="100.0%").alignment = align_center
c_seed_tot = ws.cell(row=current_row, column=3, value=f"=SUM(C{start_seed_row}:C{current_row-1})")
c_seed_tot.alignment = align_right
c_seed_tot.number_format = '#,##0 "đ"'
ws.cell(row=current_row, column=4, value="Đảm bảo Runway đủ cho 24 tháng vận hành cho đến khi đạt điểm hòa vốn").alignment = align_left
ws.cell(row=current_row, column=5, value="Tháng 07/2026 - Tháng 06/2027").alignment = align_center
ws.cell(row=current_row, column=6, value="Điểm hòa vốn đạt được tại Tháng thứ 25 (~520 Box active)").alignment = align_left
ws.cell(row=current_row, column=7, value="Runway: 24 Tháng").alignment = align_center
ws.cell(row=current_row, column=8, value="Ban Điều hành AERO").alignment = align_left
ws.cell(row=current_row, column=9, value="Khớp 100% Mục 1.4").alignment = align_center

for c_idx in range(1, 10):
    c = ws.cell(row=current_row, column=c_idx)
    c.font = cell_bold_font
    c.fill = fill_total_row
    c.border = border_total
ws.row_dimensions[current_row].height = 26

# Save workbook
wb.save(EXCEL_PATH)
print(f"[SUCCESS] Da cap nhat hoan tat tab '{sheet_name}' trong {EXCEL_PATH}!")
