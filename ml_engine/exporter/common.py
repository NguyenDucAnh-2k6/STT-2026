"""
TinyML Common Exporter Utilities
=================================
Chứa các hàm định dạng số thực, ma trận và mảng byte FlatBuffer sang mã nguồn C.
"""

from typing import Any
import numpy as np


def _format_float(val: float) -> str:
    """Định dạng số thực với hậu tố 'f' cho C."""
    if np.isnan(val) or np.isinf(val):
        return "0.0f"
    return f"{float(val):.6f}f"


def _format_float_1d_array(arr: Any, indent: int = 4, per_line: int = 8) -> str:
    """Định dạng mảng 1D float thành code C."""
    items = [_format_float(x) for x in arr]
    lines = []
    prefix = " " * indent
    for i in range(0, len(items), per_line):
        lines.append(prefix + ", ".join(items[i:i + per_line]))
    return ",\n".join(lines)


def _format_float_2d_array(matrix: Any, indent: int = 4, per_line: int = 8) -> str:
    """Định dạng mảng 2D float thành code C."""
    rows = []
    prefix = " " * indent
    for row in matrix:
        items = [_format_float(x) for x in row]
        row_lines = []
        for i in range(0, len(items), per_line):
            row_lines.append(" " * (indent + 4) + ", ".join(items[i:i + per_line]))
        rows.append(f"{prefix}{{\n" + ",\n".join(row_lines) + f"\n{prefix}}}")
    return ",\n".join(rows)


def _c_factor(n: int) -> float:
    """Tính hàm chuẩn hóa độ dài đường đi trung bình c(n) của Isolation Forest."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


def format_bytes_as_c_array(byte_data: bytes, array_name: str, per_line: int = 12) -> str:
    """Định dạng mảng byte nhị phân FlatBuffer thành mảng C const unsigned char trong PROGMEM."""
    length = len(byte_data)
    hex_bytes = [f"0x{b:02x}" for b in byte_data]

    lines = []
    for i in range(0, length, per_line):
        chunk = hex_bytes[i:i + per_line]
        lines.append("    " + ", ".join(chunk))

    array_content = ",\n".join(lines)
    len_macro_name = array_name.upper() + "_LEN"

    return f"""// --- TensorFlow Lite Model FlatBuffer Binary: {array_name} ({length:,} bytes) ---
#define {len_macro_name} {length}

const unsigned char {array_name}[{length}] __attribute__((aligned(4))) = {{
{array_content}
}};
"""
