"""
Kernel and Density-based Anomaly Exporters for TinyML ESP32
============================================================
Chuyển đổi One-Class SVM (RBF Kernel), Elliptic Envelope (Mahalanobis Distance)
và Local Outlier Factor (Novelty K-Prototypes Density) thành mã nguồn C.
"""

from typing import List, Any
import numpy as np

from .common import _format_float_1d_array, _format_float_2d_array


def _generate_one_class_svm_c(
    ocsvm_model: Any,
    feature_names: List[str],
    max_sv: int = 64
) -> str:
    """Sinh hàm phát hiện bất thường cho One-Class SVM (RBF Kernel Support Vectors)."""
    raw_model = getattr(ocsvm_model, "underlying_estimator", getattr(ocsvm_model, "model", ocsvm_model))
    sv = getattr(raw_model, "support_vectors_", None)
    dual_coef = getattr(raw_model, "dual_coef_", None)
    gamma = getattr(raw_model, "_gamma", 0.1)
    intercept = getattr(raw_model, "intercept_", [0.0])[0]

    if sv is None or dual_coef is None:
        return "// Fallback OCSVM\n"

    n_sv = sv.shape[0]
    in_features = len(feature_names)

    # Nếu số lượng support vector quá lớn, giữ lại top max_sv có trọng số lớn nhất
    if n_sv > max_sv:
        top_idx = np.argsort(np.abs(dual_coef[0]))[-max_sv:]
        sv = sv[top_idx]
        dual_coef = dual_coef[:, top_idx]
        n_sv = max_sv

    sv_c = _format_float_2d_array(sv, indent=4)
    coef_c = _format_float_1d_array(dual_coef[0], indent=4)

    return f"""// --- One-Class SVM Support Vectors & Kernel Parameters ---
#define TINYML_OCSVM_NUM_SV {n_sv}
#define TINYML_OCSVM_GAMMA {float(gamma):.6f}f
#define TINYML_OCSVM_INTERCEPT {float(intercept):.6f}f

static const float TINYML_OCSVM_SV[{n_sv}][{in_features}] = {{
{sv_c}
}};

static const float TINYML_OCSVM_COEF[{n_sv}] = {{
{coef_c}
}};

static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {{
    if (!raw_features) return 0.0f;

    float f[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, f);

    float decision_val = TINYML_OCSVM_INTERCEPT;
    for (int i = 0; i < TINYML_OCSVM_NUM_SV; i++) {{
        float dist_sq = 0.0f;
        for (int j = 0; j < TINYML_IN_FEATURES; j++) {{
            float diff = f[j] - TINYML_OCSVM_SV[i][j];
            dist_sq += diff * diff;
        }}
        decision_val += TINYML_OCSVM_COEF[i] * expf(-TINYML_OCSVM_GAMMA * dist_sq);
    }}

    // Scikit-learn One-Class SVM:
    // decision_val = sum(alpha_i * K(x_i, x)) - rho.
    // Inlier khi decision_val >= 0, Outlier (Bất thường) khi decision_val < 0.
    // Xác suất bất thường chuẩn hóa theo hàm Logistic Sigmoid chính quy (Zero-heuristic):
    // P(Anomaly) = 1 / (1 + exp(decision_val))
    // - Khi decision_val = 0 (tại ranh giới phân định): score = 0.50
    // - Khi decision_val < 0 (nằm sâu vùng bất thường): score > 0.50 tiến tới 1.0
    // - Khi decision_val > 0 (nằm an toàn trong vùng bình thường): score < 0.50 tiến về 0.0
    float anomaly_score = 1.0f / (1.0f + expf(decision_val));

    if (anomaly_score < 0.0f) anomaly_score = 0.0f;
    if (anomaly_score > 1.0f) anomaly_score = 1.0f;

    bool is_anom = (decision_val < 0.0f);
    if (out_is_anomaly) {{
        *out_is_anomaly = is_anom;
    }}
    return anomaly_score;
}}"""


def _generate_elliptic_envelope_c(
    ee_model: Any,
    feature_names: List[str]
) -> str:
    """Sinh hàm phát hiện bất thường cho Elliptic Envelope (Mahalanobis Distance)."""
    raw_model = getattr(ee_model, "underlying_estimator", getattr(ee_model, "model", ee_model))
    location = getattr(raw_model, "location_", None)
    precision = getattr(raw_model, "precision_", None)
    offset = getattr(raw_model, "offset_", -50.0)

    in_features = len(feature_names)
    if location is None or precision is None:
        return "// Fallback Elliptic Envelope\n"

    threshold_sq = float(-offset)
    if threshold_sq <= 0:
        threshold_sq = 50.0

    mean_c = _format_float_1d_array(location, indent=4)
    prec_c = _format_float_2d_array(precision, indent=4)

    return f"""// --- Elliptic Envelope (Gaussian Robust Mahalanobis Engine) ---
#define TINYML_EE_THRESH_SQ {threshold_sq:.5f}f

static const float TINYML_EE_MEAN[{in_features}] = {{
{mean_c}
}};

static const float TINYML_EE_PRECISION[{in_features}][{in_features}] = {{
{prec_c}
}};

static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {{
    if (!raw_features) return 0.0f;

    float f[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, f);

    float diff[TINYML_IN_FEATURES];
    for (int i = 0; i < TINYML_IN_FEATURES; i++) {{
        diff[i] = f[i] - TINYML_EE_MEAN[i];
    }}

    float mahal_sq = 0.0f;
    for (int i = 0; i < TINYML_IN_FEATURES; i++) {{
        float row = 0.0f;
        for (int j = 0; j < TINYML_IN_FEATURES; j++) {{
            row += diff[j] * TINYML_EE_PRECISION[i][j];
        }}
        mahal_sq += diff[i] * row;
    }}

    // Mahalanobis distance squared: d^2 = (x - mu)^T * Sigma^{-1} * (x - mu)
    // Ngưỡng phân định: TINYML_EE_THRESH_SQ = -offset_
    // Inlier khi mahal_sq <= THRESH_SQ, Outlier khi mahal_sq > THRESH_SQ.
    // Độ lệch chuẩn hóa so với ranh giới phân định:
    // z = (mahal_sq - TINYML_EE_THRESH_SQ) / (TINYML_EE_THRESH_SQ + 1e-4f)
    // Xác suất bất thường chuẩn hóa theo Sigmoid (Zero-heuristic):
    // - Khi mahal_sq == THRESH_SQ: z = 0 -> score = 0.50
    // - Khi mahal_sq > THRESH_SQ: z > 0 -> score > 0.50 tiến dần tới 1.0
    // - Khi mahal_sq < THRESH_SQ: z < 0 -> score < 0.50 tiến dần về 0.0
    bool is_anom = (mahal_sq > TINYML_EE_THRESH_SQ);
    float z = (mahal_sq - TINYML_EE_THRESH_SQ) / (TINYML_EE_THRESH_SQ + 1e-4f);
    float anomaly_score = 1.0f / (1.0f + expf(-2.0f * z));

    if (anomaly_score < 0.0f) anomaly_score = 0.0f;
    if (anomaly_score > 1.0f) anomaly_score = 1.0f;

    if (out_is_anomaly) {{
        *out_is_anomaly = is_anom;
    }}
    return anomaly_score;
}}"""


def _generate_lof_c(
    lof_model: Any,
    feature_names: List[str],
    max_prototypes: int = 32
) -> str:
    """Sinh hàm phát hiện bất thường cho Local Outlier Factor (Novelty Engine)."""
    raw_model = getattr(lof_model, "underlying_estimator", getattr(lof_model, "model", lof_model))
    fit_x = getattr(raw_model, "_fit_X", None)
    k_dist = getattr(raw_model, "_distances_fit_X_", None)
    lrd = getattr(raw_model, "_lrd", None)

    in_features = len(feature_names)
    if fit_x is None or lrd is None:
        return "// Fallback LOF\n"

    n_samples = fit_x.shape[0]
    if n_samples > max_prototypes:
        step = max(1, n_samples // max_prototypes)
        indices = np.arange(0, n_samples, step)[:max_prototypes]
        protos = fit_x[indices]
        protos_lrd = lrd[indices]
        protos_kdist = k_dist[indices, -1] if k_dist is not None else np.ones(len(indices))
    else:
        protos = fit_x
        protos_lrd = lrd
        protos_kdist = k_dist[:, -1] if k_dist is not None else np.ones(n_samples)

    offset = getattr(raw_model, "offset_", -1.5)
    thresh = float(-offset) if float(offset) < 0 else float(offset)
    if thresh <= 1.0:
        thresh = 1.5

    num_p = protos.shape[0]
    p_c = _format_float_2d_array(protos, indent=4)
    kdist_c = _format_float_1d_array(protos_kdist, indent=4)
    lrd_c = _format_float_1d_array(protos_lrd, indent=4)

    return f"""// --- Local Outlier Factor (Novelty K-Prototypes Engine) ---
#define TINYML_LOF_N_PROTO {num_p}
#define TINYML_LOF_K 5
#define TINYML_LOF_THRESH {thresh:.4f}f

static const float TINYML_LOF_PROTOS[{num_p}][{in_features}] = {{
{p_c}
}};

static const float TINYML_LOF_K_DIST[{num_p}] = {{
{kdist_c}
}};

static const float TINYML_LOF_LRD[{num_p}] = {{
{lrd_c}
}};

static inline float tinyml_predict_anomaly(const float* raw_features, bool* out_is_anomaly) {{
    if (!raw_features) return 0.0f;

    float f[TINYML_IN_FEATURES];
    tinyml_standardize_features(raw_features, f);

    float dists[TINYML_LOF_N_PROTO];
    for (int i = 0; i < TINYML_LOF_N_PROTO; i++) {{
        float d2 = 0.0f;
        for (int j = 0; j < TINYML_IN_FEATURES; j++) {{
            float diff = f[j] - TINYML_LOF_PROTOS[i][j];
            d2 += diff * diff;
        }}
        dists[i] = sqrtf(d2);
    }}

    int knn_idx[TINYML_LOF_K];
    bool used[TINYML_LOF_N_PROTO] = {{false}};
    for (int k = 0; k < TINYML_LOF_K; k++) {{
        int min_i = -1;
        float min_d = 1e9f;
        for (int i = 0; i < TINYML_LOF_N_PROTO; i++) {{
            if (!used[i] && dists[i] < min_d) {{
                min_d = dists[i];
                min_i = i;
            }}
        }}
        knn_idx[k] = (min_i >= 0) ? min_i : 0;
        if (min_i >= 0) used[min_i] = true;
    }}

    float reach_sum = 0.0f;
    for (int k = 0; k < TINYML_LOF_K; k++) {{
        int p = knn_idx[k];
        float rd = (dists[p] > TINYML_LOF_K_DIST[p]) ? dists[p] : TINYML_LOF_K_DIST[p];
        reach_sum += rd;
    }}
    float sample_lrd = (reach_sum > 1e-6f) ? ((float)TINYML_LOF_K / reach_sum) : 1.0f;

    float lof_sum = 0.0f;
    for (int k = 0; k < TINYML_LOF_K; k++) {{
        int p = knn_idx[k];
        lof_sum += TINYML_LOF_LRD[p] / sample_lrd;
    }}
    float lof_score = lof_sum / (float)TINYML_LOF_K;

    // Scikit-learn Novelty LOF:
    // lof_score = lof_sum / k.
    // Inlier khi lof_score <= TINYML_LOF_THRESH, Outlier khi lof_score > TINYML_LOF_THRESH.
    // Độ lệch chuẩn hóa so với ranh giới phân định:
    // z = (lof_score - TINYML_LOF_THRESH) / (TINYML_LOF_THRESH - 1.0f + 1e-4f);
    // Xác suất bất thường chuẩn hóa theo Sigmoid (Zero-heuristic):
    // - Khi lof_score == TINYML_LOF_THRESH: z = 0 -> score = 0.50
    // - Khi lof_score > TINYML_LOF_THRESH: z > 0 -> score > 0.50 tiến dần tới 1.0
    // - Khi lof_score = 1.0 (inlier lý tưởng): z = -1.0 -> score ≈ 0.119
    bool is_anom = (lof_score > TINYML_LOF_THRESH);
    float z = (lof_score - TINYML_LOF_THRESH) / (TINYML_LOF_THRESH - 1.0f + 1e-4f);
    float anomaly_score = 1.0f / (1.0f + expf(-2.0f * z));

    if (anomaly_score < 0.0f) anomaly_score = 0.0f;
    if (anomaly_score > 1.0f) anomaly_score = 1.0f;

    if (out_is_anomaly) {{
        *out_is_anomaly = is_anom;
    }}
    return anomaly_score;
}}"""
