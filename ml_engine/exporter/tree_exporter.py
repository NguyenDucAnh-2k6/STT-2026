"""
Tree-based Model Exporter for TinyML ESP32
===========================================
Chuyển đổi Decision Tree, Random Forest, Extra Trees và Isolation Forest
thành mã nguồn C if/else đệ quy tĩnh tối ưu, zero heap allocation.
"""

from typing import List, Optional, Any
from sklearn.tree import _tree

from ..config.schema import FEATURE_NAMES, LABEL_NAMES
from .common import _c_factor


def tree_to_c_code(
    tree_classifier: Any,
    feature_names: Optional[List[str]] = None,
    label_names: Optional[List[str]] = None,
    var_prefix: str = "",
    depth_offset: int = 1
) -> str:
    """Đệ quy sinh mã C if/else tối ưu từ một DecisionTreeClassifier."""
    if feature_names is None:
        feature_names = FEATURE_NAMES
    if label_names is None:
        label_names = LABEL_NAMES

    if hasattr(tree_classifier, "underlying_estimator"):
        tree_classifier = tree_classifier.underlying_estimator
    elif hasattr(tree_classifier, "model"):
        tree_classifier = tree_classifier.model

    tree_ = getattr(tree_classifier, "tree_", None)
    if tree_ is None:
        return "    pred_class = 0;\n    confidence = 1.0f;\n"

    c_feature_names = [
        feature_names[i] if i != _tree.TREE_UNDEFINED and i < len(feature_names) else f"feature_{i}"
        for i in tree_.feature
    ]

    lines = []

    def recurse(node: int, depth: int):
        indent = "    " * depth
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            f_idx = int(tree_.feature[node])
            name = c_feature_names[node]
            threshold = float(tree_.threshold[node])
            lines.append(f"{indent}if (features[{f_idx}] <= {threshold:.5f}f) {{ // {name} <= {threshold:.2f}")
            recurse(tree_.children_left[node], depth + 1)
            lines.append(f"{indent}}} else {{")
            recurse(tree_.children_right[node], depth + 1)
            lines.append(f"{indent}}}")
        else:
            val = tree_.value[node][0]
            pred_class = int(val.argmax())
            class_name = label_names[pred_class] if pred_class < len(label_names) else f"Class_{pred_class}"
            total_samples = float(val.sum())
            conf = float(val[pred_class] / total_samples) if total_samples > 0 else 1.0

            if var_prefix:
                lines.append(f"{indent}{var_prefix}_class = {pred_class}; // {class_name}")
                lines.append(f"{indent}{var_prefix}_conf = {conf:.4f}f;")
            else:
                lines.append(f"{indent}pred_class = {pred_class}; // {class_name}")
                lines.append(f"{indent}confidence = {conf:.4f}f;")

    recurse(0, depth_offset)
    return "\n".join(lines)


def _generate_decision_tree_classifier_c(
    clf: Any,
    feature_names: List[str],
    label_names: List[str]
) -> str:
    """Sinh hàm phân loại cho Decision Tree đơn lẻ."""
    body = tree_to_c_code(clf, feature_names, label_names, var_prefix="", depth_offset=1)
    return f"""static inline int tinyml_predict_classifier(const float* raw_features, float* out_confidence) {{
    if (!raw_features) return TINYML_NORMAL_CLASS_IDX;

    float features[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, features);

    int pred_class = TINYML_NORMAL_CLASS_IDX;
    float confidence = 1.0f;

{body}

    if (out_confidence) {{
        *out_confidence = confidence;
    }}
    return pred_class;
}}"""


def _generate_forest_classifier_c(
    clf: Any,
    feature_names: List[str],
    label_names: List[str],
    max_trees: int = 10
) -> str:
    """Sinh hàm phân loại cho Random Forest hoặc Extra Trees (Ensemble voting)."""
    raw_model = getattr(clf, "underlying_estimator", getattr(clf, "model", clf))
    estimators = getattr(raw_model, "estimators_", [])
    selected_trees = estimators[:max_trees] if estimators else []

    if not selected_trees:
        return _generate_decision_tree_classifier_c(clf, feature_names, label_names)

    num_trees = len(selected_trees)
    tree_funcs = []
    tree_calls = []

    for t_idx, est in enumerate(selected_trees):
        func_name = f"tinyml_rf_tree_{t_idx}"
        code = tree_to_c_code(est, feature_names, label_names, var_prefix="t", depth_offset=1)
        tree_funcs.append(f"""static inline void {func_name}(const float* features, float* votes) {{
    int t_class = TINYML_NORMAL_CLASS_IDX;
    float t_conf = 1.0f;
{code}
    if (t_class >= 0 && t_class < TINYML_NUM_CLASSES) {{
        votes[t_class] += t_conf;
    }}
}}""")
        tree_calls.append(f"    {func_name}(features, votes);")

    funcs_code = "\n\n".join(tree_funcs)
    calls_code = "\n".join(tree_calls)

    return f"""// --- Random Forest / Extra Trees Ensemble ({num_trees} Trees) ---
{funcs_code}

static inline int tinyml_predict_classifier(const float* raw_features, float* out_confidence) {{
    if (!raw_features) return TINYML_NORMAL_CLASS_IDX;

    float features[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, features);

    float votes[TINYML_NUM_CLASSES] = {{0.0f}};

{calls_code}

    int best_class = TINYML_NORMAL_CLASS_IDX;
    float max_votes = -1.0f;
    float total_votes = 0.0f;

    for (int c = 0; c < TINYML_NUM_CLASSES; c++) {{
        total_votes += votes[c];
        if (votes[c] > max_votes) {{
            max_votes = votes[c];
            best_class = c;
        }}
    }}

    if (out_confidence) {{
        *out_confidence = (total_votes > 0.0f) ? (max_votes / total_votes) : 1.0f;
    }}
    return best_class;
}}"""


def _generate_isolation_forest_c(
    iso_model: Any,
    feature_names: List[str],
    max_trees: int = 12
) -> str:
    """Sinh hàm phát hiện bất thường cho Isolation Forest (iTrees Path-Length)."""
    raw_model = getattr(iso_model, "underlying_estimator", getattr(iso_model, "model", iso_model))
    estimators = getattr(raw_model, "estimators_", [])
    selected_trees = estimators[:max_trees] if estimators else []

    if not selected_trees:
        return "// Fallback Isolation Forest\n"

    num_trees = len(selected_trees)
    max_samples = getattr(raw_model, "max_samples_", 256)
    c_n = _c_factor(max_samples)
    if c_n <= 0:
        c_n = 10.2372

    tree_funcs = []
    tree_calls = []

    for t_idx, est in enumerate(selected_trees):
        func_name = f"tinyml_itree_{t_idx}"
        tree_ = est.tree_
        lines = []

        def recurse(node: int, depth: int):
            indent = "    " * depth
            if tree_.feature[node] != _tree.TREE_UNDEFINED:
                f_idx = int(tree_.feature[node])
                threshold = float(tree_.threshold[node])
                lines.append(f"{indent}if (f[{f_idx}] <= {threshold:.5f}f) {{")
                recurse(tree_.children_left[node], depth + 1)
                lines.append(f"{indent}}} else {{")
                recurse(tree_.children_right[node], depth + 1)
                lines.append(f"{indent}}}")
            else:
                n_samples = int(tree_.n_node_samples[node])
                leaf_path = float(depth + _c_factor(n_samples))
                lines.append(f"{indent}return {leaf_path:.4f}f;")

        recurse(0, 1)
        body = "\n".join(lines)
        tree_funcs.append(f"""static inline float {func_name}(const float* f) {{
{body}
}}""")
        tree_calls.append(f"    sum_path += {func_name}(f);")

    funcs_code = "\n\n".join(tree_funcs)
    calls_code = "\n".join(tree_calls)

    return f"""// --- Isolation Forest Anomaly Detection Engine ({num_trees} iTrees) ---
#define TINYML_NUM_ITREES {num_trees}
#define TINYML_IFOREST_CN {c_n:.5f}f

{funcs_code}

static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {{
    if (!raw_features) return 0.0f;

    float f[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, f);

    float sum_path = 0.0f;
{calls_code}
    float avg_path = sum_path / (float)TINYML_NUM_ITREES;

    // Diem so bat thuong s = 2^(-E(h)/c(n))
    float anomaly_score = powf(2.0f, -avg_path / TINYML_IFOREST_CN);

    if (anomaly_score < 0.0f) anomaly_score = 0.0f;
    if (anomaly_score > 1.0f) anomaly_score = 1.0f;

    bool is_anom = (anomaly_score >= TINYML_ANOMALY_THRESHOLD);
    if (out_is_anomaly) {{
        *out_is_anomaly = is_anom;
    }}
    return anomaly_score;
}}"""
