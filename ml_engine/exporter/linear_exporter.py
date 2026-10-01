"""
Linear Model Exporter for TinyML ESP32
=======================================
Chuyển đổi Logistic Regression thành tích vô hướng trọng số và hàm kích hoạt Softmax trên chip.
"""

from typing import List, Any
from .common import _format_float_1d_array, _format_float_2d_array


def _generate_logistic_regression_c(
    clf: Any,
    feature_names: List[str],
    label_names: List[str]
) -> str:
    """Sinh hàm phân loại cho Logistic Regression (Linear Logits + Softmax)."""
    raw_model = getattr(clf, "underlying_estimator", getattr(clf, "model", clf))
    coef = getattr(raw_model, "coef_", None)
    intercept = getattr(raw_model, "intercept_", None)

    num_classes = len(label_names)
    in_features = len(feature_names)

    if coef is None or intercept is None:
        raise ValueError(
            f"Mô hình Logistic Regression chưa được huấn luyện đầy đủ hoặc thiếu coef_/intercept_ "
            f"(coef={coef is not None}, intercept={intercept is not None})."
        )

    coef_c = _format_float_2d_array(coef, indent=4)
    intercept_c = _format_float_1d_array(intercept, indent=4)

    return f"""// --- Logistic Regression Weights & Biases ---
static const float TINYML_LR_COEF[{num_classes}][{in_features}] = {{
{coef_c}
}};

static const float TINYML_LR_INTERCEPT[{num_classes}] = {{
{intercept_c}
}};

static inline int tinyml_predict_classifier(const float* raw_features, float* out_confidence) {{
    if (!raw_features) return TINYML_NORMAL_CLASS_IDX;

    float features[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, features);

    float logits[TINYML_NUM_CLASSES];
    float max_logit = -1e9f;

    for (int c = 0; c < TINYML_NUM_CLASSES; c++) {{
        float dot = TINYML_LR_INTERCEPT[c];
        for (int j = 0; j < TINYML_IN_FEATURES; j++) {{
            dot += TINYML_LR_COEF[c][j] * features[j];
        }}
        logits[c] = dot;
        if (dot > max_logit) {{
            max_logit = dot;
        }}
    }}

    float exp_sum = 0.0f;
    float exp_vals[TINYML_NUM_CLASSES];
    for (int c = 0; c < TINYML_NUM_CLASSES; c++) {{
        float e = expf(logits[c] - max_logit);
        exp_vals[c] = e;
        exp_sum += e;
    }}

    int best_class = TINYML_NORMAL_CLASS_IDX;
    float max_prob = 0.0f;
    for (int c = 0; c < TINYML_NUM_CLASSES; c++) {{
        float p = (exp_sum > 0.0f) ? (exp_vals[c] / exp_sum) : 0.0f;
        if (p > max_prob) {{
            max_prob = p;
            best_class = c;
        }}
    }}

    if (out_confidence) {{
        *out_confidence = max_prob;
    }}
    return best_class;
}}"""
