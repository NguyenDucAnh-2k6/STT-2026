#!/usr/bin/env python3
"""
TinyML C Header Exporter for ESP32 / Embedded Edge Nodes
=========================================================
Chuyển đổi cây quyết định / mô hình phân loại đã huấn luyện sang mã nguồn C thuần túy (C Header).
Cho phép nhúng trực tiếp mô hình vào firmware ESP32 (Phase 2), thực hiện suy luận 100% on-device
với thời gian thực thi < 50 microseconds và tiêu thụ 0MB RAM phụ trợ!
"""

import os
import sys
import joblib
from sklearn.tree import _tree

FEATURE_NAMES = [
    "packet_rate",       # idx 0
    "byte_rate",         # idx 1
    "avg_packet_size",   # idx 2
    "syn_ratio",         # idx 3
    "ack_ratio",         # idx 4
    "udp_ratio",         # idx 5
    "icmp_ratio",        # idx 6
    "unique_dst_ports"   # idx 7
]

LABEL_NAMES = ["Normal", "SYN_Flood", "Port_Scan", "Volumetric_DDoS", "Data_Exfiltration"]

def tree_to_c_code(tree, feature_names, label_names):
    """Đệ quy sinh mã nguồn C if/else tối ưu từ cấu trúc Decision Tree."""
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    lines = []
    
    def recurse(node, depth):
        indent = "    " * depth
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
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
            pred_class = val.argmax()
            class_name = label_names[pred_class]
            is_anomaly = 0 if pred_class == 0 else 1
            confidence = val[pred_class] / val.sum()
            lines.append(f"{indent}*out_class_idx = {pred_class}; // {class_name}")
            lines.append(f"{indent}*out_anomaly_score = {1.0 - confidence if is_anomaly == 0 else 0.5 + 0.5*confidence:.4f}f;")
            lines.append(f"{indent}return {is_anomaly};")

    recurse(0, 2)
    return "\n".join(lines)

def export_to_header(output_header_path: str, clf_path: str):
    if not os.path.exists(clf_path):
        print(f"[ExportTinyML] Khong tim thay {clf_path}. Vui long train truoc!")
        sys.exit(1)

    clf = joblib.load(clf_path)
    c_logic = tree_to_c_code(clf, FEATURE_NAMES, LABEL_NAMES)

    header_content = f"""/**
 * ====================================================================
 * TINYML ON-DEVICE NETWORK ANOMALY DETECTION MODEL (AUTO-GENERATED)
 * Target: ESP32 / ESP32-S3 / ARM Cortex-M / Embedded Edge Gateways
 * ====================================================================
 * 
 * Features vector index:
 *   [0] packet_rate      (packets/sec)
 *   [1] byte_rate        (bytes/sec)
 *   [2] avg_packet_size  (bytes)
 *   [3] syn_ratio        (0.0 - 1.0)
 *   [4] ack_ratio        (0.0 - 1.0)
 *   [5] udp_ratio        (0.0 - 1.0)
 *   [6] icmp_ratio       (0.0 - 1.0)
 *   [7] unique_dst_ports (integer count)
 */

#ifndef TINYML_MODEL_H
#define TINYML_MODEL_H

#ifdef __cplusplus
extern "C" {{
#endif

// Danh sach ten nhan tan cong
static const char* TINYML_LABEL_NAMES[] = {{
    "Normal",
    "SYN_Flood",
    "Port_Scan",
    "Volumetric_DDoS",
    "Data_Exfiltration"
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
    if (class_idx >= 0 && class_idx <= 4) {{
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

    print(f"[ExportTinyML] Da sinh thanh cong C Header tai: {output_header_path}")

def main():
    base_dir = os.path.dirname(__file__)
    clf_path = os.path.join(base_dir, "models", "attack_classifier.joblib")
    
    # Xuất ra cả 2 nơi: thư mục models và thư mục firmware esp32
    dest1 = os.path.join(base_dir, "models", "tinyml_model.h")
    dest2 = os.path.join(os.path.dirname(base_dir), "firmware", "esp32_probe", "tinyml_model.h")
    
    export_to_header(dest1, clf_path)
    export_to_header(dest2, clf_path)
    print("[ExportTinyML] Hoan tat! Ban co the #include \"tinyml_model.h\" truc tiep vao code ESP32.")

if __name__ == "__main__":
    main()
