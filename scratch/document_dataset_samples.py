"""Append benchmark schema and literal first-five CSV records to the requested note."""
import ast
import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL"
NOTE = ROOT / "docs/A Linh/11_10_2026.md"


def literal_constant(path: Path, name: str) -> list[str]:
    for node in ast.parse(path.read_text(encoding="utf-8-sig")).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return ast.literal_eval(node.value)
    raise ValueError(name)


features = literal_constant(ROOT / "ml_engine/config/schema.py", "EDGE_IIOTSET_FEATURES")
categories = set()
for module, constant in (("http_application", "HTTP_CAT_COLS"), ("iot_protocols", "IOT_CAT_COLS"), ("tcp_transport", "TCP_CAT_COLS")):
    categories.update(literal_constant(ROOT / f"ml_engine/preprocessing/modules/{module}.py", constant))

samples = {}
for kind in ("ML", "DNN"):
    path = DATA / f"{kind}-EdgeIIoT-dataset.csv"
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source)
        header = next(reader)
        rows = [next(reader) for _ in range(5)]
    assert all(len(row) == len(header) for row in rows)
    assert set(features).issubset(header)
    samples[kind] = (header, rows)

def append_section() -> None:
    assert samples["ML"][0] == samples["DNN"][0]
    header = samples["ML"][0]
    metadata = set(header) - set(features) - {"Attack_label", "Attack_type"}
    assert len(features) == 56 and len(header) == 63 and len(metadata) == 5
    section = """## 6. Schema dữ liệu dùng để train và 5 dòng đầu hai bộ Edge-IIoTset

### 6.1. File nguồn và lựa chọn dataset trong code

Hai CSV đang có trong workspace là:

- [Bộ ML](../../ml_engine/datasets/Edge-IIoTset%20dataset/Selected%20dataset%20for%20ML%20and%20DL/ML-EdgeIIoT-dataset.csv).
- [Bộ DNN](../../ml_engine/datasets/Edge-IIoTset%20dataset/Selected%20dataset%20for%20ML%20and%20DL/DNN-EdgeIIoT-dataset.csv).

Hai file có **63 cột, cùng tên và cùng thứ tự header**. Đây là bản CSV local được đọc trực tiếp; không khẳng định chúng nguyên vẹn như bản phát hành gốc chỉ từ header và các dòng mẫu.

Trong [ml_engine/train.py](../../ml_engine/train.py), nếu chưa truyền đường dẫn dataset:

- Classifier thuộc `pytorch_deep`, `mlp`, `deep_learning`, `pytorch`, `dnn`, hoặc anomaly detector thuộc `deep_autoencoder`, `autoencoder`: ưu tiên bộ DNN nếu file tồn tại.
- Các trường hợp khác, hoặc bộ DNN không tồn tại: chọn bộ ML nếu file tồn tại.
- `--dataset` cho phép chỉ định file nguồn. Tên bộ ML/DNN không tạo ra hai schema feature khác nhau trong pipeline hiện tại.

### 6.2. Schema raw CSV và schema đầu vào model

| Thành phần | Số cột | Vai trò trong pipeline hiện tại |
| --- | ---: | --- |
| Network features | 56 | Đầu vào `X`; thứ tự canonical từ `EDGE_IIOTSET_FEATURES` |
| Metadata nguồn | 5 | `frame.time`, `ip.src_host`, `ip.dst_host`, `arp.dst.proto_ipv4`, `arp.src.proto_ipv4`; không đưa vào `X` |
| `Attack_label` | 1 | Nhãn nhị phân của benchmark: 0 Normal, 1 attack; không đưa vào `X` |
| `Attack_type` | 1 | Nhãn đa lớp `y` của loader hiện tại; không đưa vào `X` |
| **Tổng raw CSV** | **63** | Một dòng nguồn tương ứng một record packet đã trích xuất |

CSV không khai báo dtype cố định. Bảng dưới ghi **kiểu mà preprocessing hiện tại xử lý**, không suy dtype từ một dòng mẫu: numeric được parse thành số hữu hạn; categorical được giữ dạng chuỗi và biến đổi bằng preprocessing đã fit. Địa chỉ và thời gian nguồn chỉ dùng để đối chiếu/provenance, không phải feature. Không giả định `frame.time` đã là Unix timestamp: các mẫu ML/DNN bên dưới có biểu diễn khác nhau.

| Vị trí trong CSV (1-based) | Tên cột | Kiểu xử lý | Vai trò / vị trí trong vector X (1-based) |
| ---: | --- | --- | --- |
"""
    for index, name in enumerate(header, 1):
        if name in features:
            kind = "categorical/string" if name in categories else "numeric"
            role = f"Feature X[{features.index(name) + 1}]"
        elif name == "Attack_type":
            kind, role = "categorical/string", "Nhãn y, encode bằng label encoder"
        elif name == "Attack_label":
            kind, role = "binary 0/1", "Nhãn benchmark phụ, loại khỏi X"
        else:
            kind, role = "metadata nguồn", "Loại khỏi X"
        section += f"| {index} | `{name}` | {kind} | {role} |\n"
    section += """
**Hợp đồng training:** `load_raw_dataset()` chọn đủ 56 cột canonical, lấy `Attack_type` làm nhãn, kiểm tra numeric/label và loại exact duplicate feature+label trước khi split. Sau split, encoder/baseline/scaler chỉ fit trên train. `transform()` tạo ma trận numeric `(n_records, 56)` theo đúng thứ tự canonical để classifier/anomaly detector sử dụng; không thêm metadata hay nhãn vào vector. Anomaly detector dùng dữ liệu Normal của tập train.

Các trường categorical hiện có 13 cột; 43 feature còn lại là numeric. Các cách ghi zero như `"0"`, `"0.0"`, `"0x00000000"` được chuẩn hóa trước encoding nhằm tránh model học shortcut từ cách định dạng. Mẫu dưới đây là **raw CSV trước preprocessing**, nên giữ nguyên các biểu diễn này.

### 6.3. Năm record đầu của bộ ML

Nguồn: file **Bộ ML** ở mục 6.1. Khối CSV gồm header đầy đủ 63 cột + đúng 5 record đầu, theo thứ tự trong file; không sampling, shuffle, lọc duplicate hoặc chuẩn hóa giá trị. Cách đặt dấu nháy CSV có thể được serializer chuẩn hóa, nhưng nội dung từng cell được giữ nguyên, kể cả khoảng trắng.

"""
    for kind in ("ML", "DNN"):
        if kind == "DNN":
            section += """### 6.4. Năm record đầu của bộ DNN

Nguồn: file **Bộ DNN** ở mục 6.1. Header và 5 record được lấy theo cùng quy tắc ở mục 6.3.

"""
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(samples[kind][0])
        writer.writerows(samples[kind][1])
        serialized = buffer.getvalue()
        assert list(csv.reader(io.StringIO(serialized))) == [samples[kind][0], *samples[kind][1]]
        section += "```csv\n" + serialized + "```\n\n"
        if kind == "ML":
            section += "Năm dòng đầu đều có `Attack_label=1`, `Attack_type=MITM`; toàn bộ 56 feature có biểu diễn zero. Một số record lặp lại; chúng vẫn được giữ trong trích đoạn để phản ánh đúng nguồn trước deduplication. Metadata địa chỉ ở đây thuộc CSV benchmark, không phải capture live của người dùng.\n\n"
        else:
            section += "Năm dòng đầu đều có `Attack_label=0`, `Attack_type=Normal`. Có các trường TCP thực, MQTT CONNECT (`mqtt.msgtype=1`), CONNACK (`mqtt.msgtype=2`) và PUBLISH (`mqtt.msgtype=3`), với topic `Temperature_and_Humidity`. Đây chỉ là 5 dòng đầu, không đại diện cho phân phối toàn bộ bộ DNN.\n\n"
    section += """### 6.5. Ý nghĩa khi nối dữ liệu capture với benchmark

Để concat cho supervised training, cần đủ tên/ý nghĩa 56 feature và ground truth xác minh tương thích với `Attack_type`; chỉ cùng số cột chưa đủ. JSON host có thêm metadata thu thập nên phải chọn canonical features, không nối toàn bộ schema telemetry vào X. Cửa sổ ESP32 không đạt hợp đồng packet này. Năm dòng mẫu trên cũng không chứng minh độ chính xác của mô hình hoặc tính độc lập của train/test.

"""
    current = NOTE.read_text(encoding="utf-8")
    marker = "## 6. Phạm vi kiểm chứng của tài liệu"
    assert current.count(marker) == 1 and "### 6.1." not in current
    updated = current.replace(marker, section + "## 7. Phạm vi kiểm chứng của tài liệu")
    # Check every embedded CSV cell against the source records, not just row counts.
    import re
    blocks = re.findall(r"```csv\n(.*?)\n```", updated, re.S)
    assert len(blocks) == 2
    for kind, block in zip(("ML", "DNN"), blocks):
        assert list(csv.reader(io.StringIO(block))) == [samples[kind][0], *samples[kind][1]]
    assert len(categories & set(features)) == 13
    NOTE.write_text(updated, encoding="utf-8", newline="\n")
    print("Added 63-column schema and two verified 5-record CSV excerpts; source CSVs unchanged.")


if __name__ == "__main__":
    append_section()
