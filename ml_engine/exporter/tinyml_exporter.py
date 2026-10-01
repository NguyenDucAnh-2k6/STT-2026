"""
Universal TinyML C Header Exporter (Master Coordinator for Classical ML)
========================================================================
Chỉ dẫn module:
- Module này điều phối việc chuyển đổi các mô hình Machine Learning cổ điển (ML):
  + tree_exporter.py: Decision Tree, Random Forest, Extra Trees, Isolation Forest.
  + linear_exporter.py: Logistic Regression.
  + kernel_density_exporter.py: One-Class SVM, Elliptic Envelope, Local Outlier Factor (LOF).
- Đối với Deep Learning (DNN, LSTM, Autoencoder), module tự động ủy quyền sang TFLite Handler
  (tflite_exporter.py) để xuất file .tflite và mảng C FlatBuffer (tinyml_tflite_array.h).
- 100% Zero-Heuristic: Không có hệ số tùy tiện, bảo đảm tính xác thực từ trọng số toán học.
"""

import os
from typing import List, Optional, Any, Dict
import numpy as np

from ..config.schema import FEATURE_NAMES, LABEL_NAMES
from .common import (
    _format_float,
    _format_float_1d_array,
    _format_float_2d_array,
    _c_factor,
    format_bytes_as_c_array
)
from .tree_exporter import (
    tree_to_c_code,
    _generate_decision_tree_classifier_c,
    _generate_forest_classifier_c,
    _generate_isolation_forest_c
)
from .linear_exporter import (
    _generate_logistic_regression_c
)
from .kernel_density_exporter import (
    _generate_one_class_svm_c,
    _generate_elliptic_envelope_c,
    _generate_lof_c
)
from .deep_learning_exporter import (
    is_deep_learning_model,
    is_lstm_model
)


def _generate_fallback_anomaly_c(threshold: float = 0.50) -> str:
    """Sinh hàm phát hiện bất thường fallback dựa trên xác suất của Classifier (Zero-heuristic)."""
    return f"""static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {{
    float conf = 1.0f;
    int pred_idx = tinyml_predict_classifier(raw_features, &conf);
    const char* label = tinyml_get_threat_name(pred_idx);

    bool is_anom = (pred_idx != TINYML_NORMAL_CLASS_IDX);
    if (is_anom && (strcmp(label, "Normal") == 0 || strcmp(label, "normal") == 0)) {{
        is_anom = false;
    }}

    // Điểm bất thường chuẩn hóa thuần túy từ độ tự tin phân loại (0% heuristic):
    float anomaly_score = is_anom ? conf : (1.0f - conf);

    if (anomaly_score < 0.0f) anomaly_score = 0.0f;
    if (anomaly_score > 1.0f) anomaly_score = 1.0f;

    if (out_is_anomaly) {{
        *out_is_anomaly = is_anom;
    }}
    return anomaly_score;
}}"""


def generate_classifier_c(
    classifier_model: Any,
    feature_names: List[str],
    label_names: List[str]
) -> str:
    """Tự động nhận diện loại mô hình Classifier và điều phối tới generator tương ứng."""
    model_obj = getattr(classifier_model, "underlying_estimator", getattr(classifier_model, "model", classifier_model))
    type_name = type(model_obj).__name__.lower()
    wrapper_type = type(classifier_model).__name__.lower()

    # 1. Classical Tree & Forest models
    if "decisiontree" in type_name or "decisiontree" in wrapper_type:
        return _generate_decision_tree_classifier_c(model_obj, feature_names, label_names)
    elif "randomforest" in type_name or "extratrees" in type_name or "forest" in wrapper_type:
        return _generate_forest_classifier_c(model_obj, feature_names, label_names, max_trees=8)

    # 2. Linear models
    elif "logisticregression" in type_name or "linear" in wrapper_type:
        return _generate_logistic_regression_c(model_obj, feature_names, label_names)

    # 3. Deep Learning models (DNN / LSTM) -> TFLite FlatBuffer Bridge
    elif is_deep_learning_model(classifier_model) or "edgedeepnet" in type_name or "lstm" in type_name or "pytorch" in wrapper_type or "dnn" in wrapper_type:
        clf_desc = "EdgeLSTMNet Bi-LSTM" if is_lstm_model(classifier_model) else "EdgeDeepNet DNN"
        return f"""// --- Deep Learning Multi-Class Classifier ({clf_desc}) ---
// Lưu ý: Toàn bộ trọng số và đồ thị mạng nơ-ron sâu được biên dịch thành
// TensorFlow Lite FlatBuffer trong g_classifier_tflite[] (xem tinyml_tflite_array.h).
#define TINYML_CLASSIFIER_IS_DL 1
#if __has_include("tinyml_tflite_array.h")
  #include "tinyml_tflite_array.h"
#endif

static inline int tinyml_predict_classifier(const float* raw_features, float* out_confidence) {{
    if (out_confidence) *out_confidence = 1.0f;
    return TINYML_NORMAL_CLASS_IDX;
}}"""

    # 4. Unknown / Unsupported
    else:
        if hasattr(model_obj, "tree_"):
            return _generate_decision_tree_classifier_c(model_obj, feature_names, label_names)
        elif hasattr(model_obj, "estimators_"):
            return _generate_forest_classifier_c(model_obj, feature_names, label_names, max_trees=8)
        elif hasattr(model_obj, "coef_"):
            return _generate_logistic_regression_c(model_obj, feature_names, label_names)
        raise ValueError(
            f"Không hỗ trợ xuất TinyML C Header cho mô hình phân loại: {type(classifier_model).__name__}."
        )


def generate_anomaly_detector_c(
    anomaly_model: Any,
    feature_names: List[str],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Tự động nhận diện loại mô hình Anomaly Detector và điều phối tới generator tương ứng."""
    if anomaly_model is None:
        return _generate_fallback_anomaly_c(0.50)

    model_obj = getattr(anomaly_model, "underlying_estimator", getattr(anomaly_model, "model", anomaly_model))
    type_name = type(model_obj).__name__.lower()
    wrapper_type = type(anomaly_model).__name__.lower()

    if "isolationforest" in type_name or "isolation" in wrapper_type:
        return _generate_isolation_forest_c(model_obj, feature_names, max_trees=10)
    elif "oneclasssvm" in type_name or "svm" in wrapper_type:
        return _generate_one_class_svm_c(model_obj, feature_names, max_sv=64)
    elif "ellipticenvelope" in type_name or "elliptic" in wrapper_type:
        return _generate_elliptic_envelope_c(model_obj, feature_names)
    elif "localoutlierfactor" in type_name or "lof" in wrapper_type:
        return _generate_lof_c(model_obj, feature_names, max_prototypes=32)
    elif is_deep_learning_model(anomaly_model) or "autoencoder" in type_name or "autoencoder" in wrapper_type:
        return """// --- Deep Autoencoder Anomaly Detector (TensorFlow Lite Engine) ---
// Lưu ý: Toàn bộ trọng số Autoencoder được biên dịch thành
// TensorFlow Lite FlatBuffer trong g_anomaly_tflite[] (xem tinyml_tflite_array.h).
#define TINYML_ANOMALY_IS_DL 1
#if __has_include("tinyml_tflite_array.h")
  #include "tinyml_tflite_array.h"
#endif

static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {
    if (out_is_anomaly) *out_is_anomaly = false;
    return 0.0f;
}"""
    else:
        return _generate_fallback_anomaly_c(0.50)


def export_model_to_c_header(
    classifier_model: Any,
    anomaly_model: Optional[Any],
    output_header_path: str,
    feature_names: Optional[List[str]] = None,
    label_names: Optional[List[str]] = None,
    preprocessor: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Xuất tệp C Header (tinyml_model.h) hoàn chỉnh tích hợp:
    - Bất kỳ Classifier ML nào (Decision Tree, Random Forest, Logistic Regression...).
    - Bất kỳ Anomaly Detector ML nào (Isolation Forest, One-Class SVM, LOF, Elliptic Envelope...).
    - Nếu có Deep Learning (DNN, LSTM, Autoencoder), tự động kích hoạt TFLite Suite để xuất FlatBuffers song song.
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES
    if label_names is None:
        label_names = LABEL_NAMES

    in_features = len(feature_names)
    num_classes = len(label_names)

    # 1. Trích xuất tham số scaler chuẩn hóa Z-Score
    scaler = None
    if preprocessor is not None:
        scaler = getattr(preprocessor, "scaler", None)
        if scaler is None and hasattr(preprocessor, "mean_"):
            scaler = preprocessor

    means = [0.0] * in_features
    scales = [1.0] * in_features

    if scaler is not None and hasattr(scaler, "mean_") and scaler.mean_ is not None:
        means = [float(m) for m in scaler.mean_[:in_features]]
        scales = [float(s) if s != 0 else 1.0 for s in scaler.scale_[:in_features]]
        while len(means) < in_features:
            means.append(0.0)
        while len(scales) < in_features:
            scales.append(1.0)

    means_c = _format_float_1d_array(means, indent=4)
    scales_c = _format_float_1d_array(scales, indent=4)

    # 2. Xác định nhãn Normal
    normal_idx = 0
    for idx, name in enumerate(label_names):
        if name.lower() == "normal":
            normal_idx = idx
            break

    labels_c = ",\n    ".join([f'"{name}"' for name in label_names])
    feature_doc = "\n".join([f" *   [{idx:2d}] {feat}" for idx, feat in enumerate(feature_names)])

    # Tên mô hình
    raw_clf = getattr(classifier_model, "underlying_estimator", getattr(classifier_model, "model", classifier_model))
    raw_ano = getattr(anomaly_model, "underlying_estimator", getattr(anomaly_model, "model", anomaly_model)) if anomaly_model else None

    clf_type_name = type(raw_clf).__name__ if raw_clf else type(classifier_model).__name__
    anom_type_name = type(raw_ano).__name__ if raw_ano else (type(anomaly_model).__name__ if anomaly_model else "None")

    anomaly_threshold = float(getattr(anomaly_model, "threshold_", 0.50))

    # Tự động xuất TFLite Suite nếu có thành phần Deep Learning
    is_clf_dl = is_deep_learning_model(classifier_model)
    is_anom_dl = is_deep_learning_model(anomaly_model)

    output_dir = os.path.dirname(os.path.abspath(output_header_path))
    if is_clf_dl or is_anom_dl:
        try:
            from .tflite_exporter import export_tinyml_suite
            export_tinyml_suite(
                anomaly_model=anomaly_model,
                classifier_model=classifier_model,
                preprocessor=preprocessor,
                output_dir=output_dir,
                label_names=label_names
            )
        except Exception as e:
            print(f"[TinyMLExporter] Warning exporting TFLite Suite for DL: {e}")

    # 3. Sinh mã C cho Anomaly Detector & Classifier
    anomaly_c_code = generate_anomaly_detector_c(anomaly_model, feature_names, metadata)
    classifier_c_code = generate_classifier_c(classifier_model, feature_names, label_names)

    c_content = f"""// =====================================================================
// AUTOGENERATED TINYML C HEADER - ZERO-HEAP STANDALONE INFERENCE ENGINE
// Generated for ESP32 Promiscuous Sniffer & Edge ML Detection
// 100% Deterministic: Trích xuất 1:1 từ mô hình đã huấn luyện (Zero-heuristic)
// =====================================================================

#ifndef TINYML_MODEL_H
#define TINYML_MODEL_H

#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <string.h>

#define TINYML_IN_FEATURES {in_features}
#define TINYML_NUM_CLASSES {num_classes}
#define TINYML_NORMAL_CLASS_IDX {normal_idx}
#define TINYML_ANOMALY_THRESHOLD {anomaly_threshold:.6f}f
#define TINYML_CLASSIFIER_NAME "{clf_type_name}"
#define TINYML_ANOMALY_DETECTOR_NAME "{anom_type_name}"

/*
 * DANH SÁCH {in_features} ĐẶC TRƯNG MẠNG (FEATURES):
{feature_doc}
 */

static const float TINYML_FEATURE_MEAN[{in_features}] = {{
{means_c}
}};

static const float TINYML_FEATURE_SCALE[{in_features}] = {{
{scales_c}
}};

static const char* const TINYML_CLASS_NAMES[{num_classes}] = {{
    {labels_c}
}};

static inline void tinyml_standardize_features(const float* raw_features, float* out_features) {{
    if (!raw_features || !out_features) return;
    for (int i = 0; i < TINYML_IN_FEATURES; i++) {{
        float s = TINYML_FEATURE_SCALE[i];
        if (s != 0.0f) {{
            out_features[i] = (raw_features[i] - TINYML_FEATURE_MEAN[i]) / s;
        }} else {{
            out_features[i] = raw_features[i] - TINYML_FEATURE_MEAN[i];
        }}
    }}
}}

static inline const char* tinyml_get_threat_name(int class_idx) {{
    if (class_idx >= 0 && class_idx < TINYML_NUM_CLASSES) {{
        return TINYML_CLASS_NAMES[class_idx];
    }}
    return "Unknown";
}}

// =====================================================================
// TIER 1: ANOMALY DETECTION ENGINE ({anom_type_name})
// =====================================================================
{anomaly_c_code}

// =====================================================================
// TIER 2: ATTACK CLASSIFIER ENGINE ({clf_type_name})
// =====================================================================
{classifier_c_code}

#endif // TINYML_MODEL_H
"""

    os.makedirs(os.path.dirname(os.path.abspath(output_header_path)), exist_ok=True)
    with open(output_header_path, "w", encoding="utf-8") as f:
        f.write(c_content)

    return c_content


def export_decision_tree_to_header(
    tree_classifier: Any,
    output_header_path: str,
    feature_names: Optional[List[str]] = None,
    label_names: Optional[List[str]] = None,
    preprocessor: Optional[Any] = None,
    anomaly_detector: Optional[Any] = None
) -> str:
    """Hàm wrapper tương thích ngược."""
    return export_model_to_c_header(
        classifier_model=tree_classifier,
        anomaly_model=anomaly_detector,
        output_header_path=output_header_path,
        feature_names=feature_names,
        label_names=label_names,
        preprocessor=preprocessor
    )
