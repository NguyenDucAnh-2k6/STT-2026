"""
TinyML C Header Exporter
========================
Chỉ dẫn module:
- Module này chuyển đổi cấu trúc cây quyết định (Decision Tree) đã huấn luyện
  thành mã nguồn C thuần túy (C99 / C++ compatible inline functions).
- Đặc điểm của mã C sinh ra:
  + 100% Zero-RAM Dynamic Allocation: Không dùng malloc, không phụ thuộc thư viện ngoài.
  + Tốc độ thực thi siêu tốc: < 50 microseconds trên ESP32 240MHz.
  + Dễ dàng #include trực tiếp vào Arduino IDE, ESP-IDF hoặc PlatformIO.
- Đầu vào: DecisionTreeClassifier (hoặc wrapper của nó), danh sách tên đặc trưng, danh sách nhãn.
- Đầu ra: Tệp tin header 'tinyml_model.h'.
"""

import os
from typing import List, Optional, Any
from sklearn.tree import _tree, DecisionTreeClassifier

from ..config.schema import FEATURE_NAMES, LABEL_NAMES


def tree_to_c_code(
    tree_classifier: Any,
    feature_names: Optional[List[str]] = None,
    label_names: Optional[List[str]] = None
) -> str:
    """
    Đệ quy sinh mã nguồn C cấu trúc if/else tối ưu từ DecisionTreeClassifier.

    Parameters:
    -----------
    tree_classifier : DecisionTreeClassifier hoặc đối tượng có thuộc tính .tree_
        Mô hình cây đã được huấn luyện.
    feature_names : list[str], optional
        Danh sách 8 tên đặc trưng.
    label_names : list[str], optional
        Danh sách 5 tên nhãn tấn công.

    Returns:
    --------
    str:
        Đoạn mã logic if/else dạng C.
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES
    if label_names is None:
        label_names = LABEL_NAMES

    # Trích xuất estimator nếu là wrapper
    if hasattr(tree_classifier, "underlying_estimator"):
        tree_classifier = tree_classifier.underlying_estimator
    elif hasattr(tree_classifier, "model"):
        tree_classifier = tree_classifier.model

    tree_ = tree_classifier.tree_
    c_feature_names = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    lines = []

    def recurse(node: int, depth: int):
        indent = "    " * depth
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = c_feature_names[node]
            f_idx = feature_names.index(name)
            threshold = tree_.threshold[node]
            lines.append(f"{indent}if (features[{f_idx}] <= {threshold:.5f}f) {{ // {name} <= {threshold:.2f}")
            recurse(tree_.children_left[node], depth + 1)
            lines.append(f"{indent}}} else {{")
            recurse(tree_.children_right[node], depth + 1)
            lines.append(f"{indent}}}")
        else:
            # Leaf node
            val = tree_.value[node][0]
            pred_class = int(val.argmax())
            class_name = label_names[pred_class]
            is_anomaly = 0 if pred_class == 0 else 1
            confidence = float(val[pred_class] / val.sum())
            anomaly_score = 1.0 - confidence if is_anomaly == 0 else 0.5 + 0.5 * confidence

            lines.append(f"{indent}*out_class_idx = {pred_class}; // {class_name}")
            lines.append(f"{indent}*out_anomaly_score = {anomaly_score:.4f}f;")
            lines.append(f"{indent}return {is_anomaly};")

    recurse(0, 2)
    return "\n".join(lines)


def export_decision_tree_to_header(
    tree_classifier: Any,
    output_header_path: str,
    feature_names: Optional[List[str]] = None,
    label_names: Optional[List[str]] = None
) -> str:
    """
    Sinh hoàn chỉnh tệp tin C Header (.h) chứa logic suy luận TinyML.

    Parameters:
    -----------
    tree_classifier : Any
        Mô hình Decision Tree đã huấn luyện.
    output_header_path : str
        Đường dẫn file .h sẽ ghi.

    Returns:
    --------
    str:
        Đường dẫn tuyệt đối đến file header đã lưu.
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES
    if label_names is None:
        label_names = LABEL_NAMES

    c_logic = tree_to_c_code(tree_classifier, feature_names, label_names)

    labels_c_array = ",\n    ".join([f'"{name}"' for name in label_names])
    feature_doc = "\n".join([f" *   [{idx}] {feat}" for idx, feat in enumerate(feature_names)])

    header_content = f"""/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
{feature_doc}
 */

#ifndef TINYML_MODEL_H
#define TINYML_MODEL_H

#ifdef __cplusplus
extern "C" {{
#endif

// Danh sach ten nhan tan cong
static const char* TINYML_LABEL_NAMES[] = {{
    {labels_c_array}
}};

/**
 * @brief Chay suy luan phat hien bat thuong luu luong truc tiep tren chip ESP32
 * @param features Mang float 8 phan tu chua dac trung luu luong
 * @param out_class_idx Con tro nhan chi so lop tan cong (0 -> 4)
 * @param out_anomaly_score Con tro nhan diem nguy hiem [0.0 -> 1.0]
 * @return int 0: Normal, 1: Anomaly (Phat hien tan cong)
 */
static inline int tinyml_predict_anomaly(
    const float* features,
    int* out_class_idx,
    float* out_anomaly_score
) {{
    if (!features || !out_class_idx || !out_anomaly_score) return -1;

{c_logic}
}}

/**
 * @brief Lay ten chuoi mo ta tan cong tu chi so lop
 */
static inline const char* tinyml_get_threat_name(int class_idx) {{
    if (class_idx >= 0 && class_idx < {len(label_names)}) {{
        return TINYML_LABEL_NAMES[class_idx];
    }}
    return "Unknown";
}}

#ifdef __cplusplus
}}
#endif

#endif // TINYML_MODEL_H
"""

    os.makedirs(os.path.dirname(output_header_path), exist_ok=True)
    with open(output_header_path, "w", encoding="utf-8") as f:
        f.write(header_content)

    return os.path.abspath(output_header_path)
