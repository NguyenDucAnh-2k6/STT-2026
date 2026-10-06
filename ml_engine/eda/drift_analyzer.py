#!/usr/bin/env python3
"""
Data Drift & Context Shift Exploratory Data Analysis (EDA)
=========================================================
Phân tích chuyên sâu hiện tượng lệch ngữ cảnh (Context Drift / Covariate Shift)
giữa bộ dữ liệu chuẩn phòng thí nghiệm (Edge-IIoTset) và dữ liệu thực tế thu thập từ
các phiên vận hành của thiết bị biên trong Data Lakehouse (Parquet):

1. Đo lường định lượng các chỉ số sai khác phân phối:
   - Kolmogorov-Smirnov (KS-test) thống kê và p-value.
   - Wasserstein Distance (Earth Mover's Distance).
   - Population Stability Index (PSI - Chuẩn giám sát mô hình công nghiệp).
2. Chiếu không gian đa chiều PCA 2D:
   - So sánh vị trí cụm (Cluster Manifold) giữa Edge-IIoTset Normal, Data Lake Normal, và Tấn công.
3. Đánh giá tác động Báo động giả (False Alarm Rate) lên mô hình học máy:
   - Kiểm chứng xem nếu chỉ huấn luyện trên Edge-IIoTset thì bao nhiêu % dữ liệu thực tế bị gắn nhãn nhầm là Bất thường.
4. Xuất bộ biểu đồ trực quan hóa cao cấp vào: ml_engine/eda/charts/drift/
"""

import os
import sys
import glob
import json
import time
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Đảm bảo UTF-8 an toàn trên Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing import EdgeTrafficPreprocessor


def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_buckets: int = 10) -> float:
    """
    Tính chỉ số Population Stability Index (PSI) đo mức độ dịch chuyển phân phối:
    PSI < 0.10: Không có độ lệch đáng kể (No Shift).
    0.10 <= PSI < 0.25: Độ lệch trung bình (Moderate Shift).
    PSI >= 0.25: Độ lệch nghiêm trọng (Significant Drift / Covariate Shift).
    """
    expected = expected[np.isfinite(expected)]
    actual = actual[np.isfinite(actual)]

    if len(expected) < 10 or len(actual) < 10:
        return 0.0

    if np.all(expected == expected[0]) and np.all(actual == actual[0]):
        return 0.0 if expected[0] == actual[0] else 1.0

    percentiles = np.linspace(0, 100, num_buckets + 1)
    try:
        bins = np.percentile(expected, percentiles)
        bins = np.unique(bins)
        if len(bins) < 2:
            bins = np.linspace(np.min(expected) - 1e-5, np.max(expected) + 1e-5, num_buckets + 1)
    except Exception:
        bins = np.linspace(np.min(expected) - 1e-5, np.max(expected) + 1e-5, num_buckets + 1)

    bins[0] = -np.inf
    bins[-1] = np.inf

    expected_counts, _ = np.histogram(expected, bins=bins)
    actual_counts, _ = np.histogram(actual, bins=bins)

    eps = 1e-4
    expected_pct = (expected_counts / len(expected)) + eps
    actual_pct = (actual_counts / len(actual)) + eps

    expected_pct /= np.sum(expected_pct)
    actual_pct /= np.sum(actual_pct)

    psi_val = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
    return float(psi_val)


def run_drift_eda(
    sample_ratio: float = 0.15,
    output_charts_dir: str = "ml_engine/eda/charts/drift",
    report_json_path: str = "ml_engine/eda/charts/drift/drift_report.json"
):
    print("\n" + "=" * 76)
    print("      AERO ML ENGINE: PHÂN TÍCH CONTEXT DRIFT & COVARIATE SHIFT      ")
    print("=" * 76)

    out_dir = os.path.join(ROOT_DIR, output_charts_dir)
    os.makedirs(out_dir, exist_ok=True)

    # 1. Nạp toàn bộ dữ liệu Parquet từ Data Lakehouse
    print("[1/5] Đang nạp toàn bộ các file Parquet từ Data Lakehouse...")
    parquet_files = glob.glob(os.path.join(ROOT_DIR, "data_lake", "raw", "**", "*.parquet"), recursive=True)
    if not parquet_files:
        print("[Lỗi] Không tìm thấy file parquet nào trong data_lake/raw/")
        return

    lake_dfs = []
    for pf in parquet_files:
        try:
            df_part = pd.read_parquet(pf)
            lake_dfs.append(df_part)
        except Exception:
            pass

    df_lake_all = pd.concat(lake_dfs, ignore_index=True)
    print(f"  -> Đã nạp thành công {len(parquet_files)} file Parquet với tổng số {len(df_lake_all):,} bản ghi.")

    # Lọc các bản ghi Normal trong Data Lake (Lưu lượng mạng thực tế môi trường xung quanh)
    df_lake_normal = df_lake_all[(df_lake_all["is_attack"] == 0) | (df_lake_all["ground_truth_scenario"].str.lower() == "normal")].copy()
    print(f"  -> Bản ghi lưu lượng bình thường (Real Benign Baseline): {len(df_lake_normal):,} bản ghi.")

    # 2. Nạp dữ liệu chuẩn Edge-IIoTset (Benchmark) qua Stratified Sampling
    print("\n[2/5] Đang nạp tập dữ liệu chuẩn Edge-IIoTset (Benchmark) qua Stratified Sampling...")
    edge_csv_path = os.path.join(ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset", "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv")
    if not os.path.exists(edge_csv_path):
        print(f"[Lỗi] Không tìm thấy file Edge-IIoTset tại: {edge_csv_path}")
        return

    # Nạp preprocessor
    prep_path = os.path.join(ROOT_DIR, "ml_engine", "models", "decision_tree_isolation_forest", "preprocessor.joblib")
    if os.path.exists(prep_path):
        preprocessor = EdgeTrafficPreprocessor.load(prep_path)
    else:
        preprocessor = EdgeTrafficPreprocessor()

    df_edge_full = pd.read_csv(edge_csv_path, low_memory=False)
    print(f"  -> File gốc có {len(df_edge_full):,} dòng. Đang lấy mẫu phân tầng {sample_ratio*100:.0f}%...")
    target_col = "Attack_type" if "Attack_type" in df_edge_full.columns else "Attack_label"
    _, df_edge_sample = train_test_split(df_edge_full, test_size=sample_ratio, random_state=42, stratify=df_edge_full[target_col])
    df_edge_sample = df_edge_sample.reset_index(drop=True)

    df_edge_normal = df_edge_sample[df_edge_sample["Attack_label"] == 0].copy()
    df_edge_attack = df_edge_sample[df_edge_sample["Attack_label"] == 1].copy()
    print(f"  -> Mẫu phân tầng: {len(df_edge_normal):,} Normal, {len(df_edge_attack):,} Attack.")

    # 3. Nâng chiều dữ liệu Data Lakehouse sang không gian 56 đặc trưng qua EdgeTrafficPreprocessor
    print("\n[3/5] Nâng chiều dữ liệu Data Lakehouse sang không gian 56 đặc trưng qua EdgeTrafficPreprocessor...")
    expanded_rows = [preprocessor.extract_features(r.to_dict()).iloc[0] for _, r in df_lake_normal.iterrows()]
    df_lake_56 = pd.DataFrame(expanded_rows)

    feature_names = preprocessor.feature_names

    # Chuyển đổi dữ liệu sang ma trận số đã chuẩn hóa qua preprocessor
    X_edge_norm = preprocessor.transform(df_edge_normal)
    X_lake_norm = preprocessor.transform(df_lake_56)
    X_edge_att = preprocessor.transform(df_edge_attack)

    # 4. Tính toán các chỉ số Context Drift & Covariate Shift
    print("\n[4/5] Tính toán các chỉ số thống kê trôi dạt phân phối (PSI, KS-Test, Wasserstein)...")
    drift_metrics = []
    for i, feat in enumerate(feature_names):
        vec_edge = X_edge_norm[:, i]
        vec_lake = X_lake_norm[:, i]

        ks_stat, ks_pval = stats.ks_2samp(vec_edge, vec_lake)
        w_dist = stats.wasserstein_distance(vec_edge, vec_lake)
        psi = calculate_psi(vec_edge, vec_lake, num_buckets=10)

        if psi < 0.10:
            status = "NO_SHIFT"
        elif psi < 0.25:
            status = "MODERATE_SHIFT"
        else:
            status = "SIGNIFICANT_DRIFT"

        drift_metrics.append({
            "feature": feat,
            "psi": round(psi, 4),
            "ks_statistic": round(float(ks_stat), 4),
            "ks_pvalue": float(ks_pval),
            "wasserstein_dist": round(float(w_dist), 4),
            "status": status,
            "edge_mean": round(float(np.mean(vec_edge)), 4),
            "edge_std": round(float(np.std(vec_edge)), 4),
            "lake_mean": round(float(np.mean(vec_lake)), 4),
            "lake_std": round(float(np.std(vec_lake)), 4)
        })

    df_drift = pd.DataFrame(drift_metrics).sort_values(by="psi", ascending=False)

    print("\n[*] TOP 10 ĐẶC TRƯNG BỊ LỆCH NGỮ CẢNH (CONTEXT DRIFT) MẠNH NHẤT:")
    print(f"  {'ĐẶC TRƯNG':<24} | {'PSI':<8} | {'KS-STAT':<8} | {'MEAN EDGE':<12} | {'MEAN LAKE':<12} | {'MỨC ĐỘ DRIFT'}")
    print("  " + "-" * 82)
    for _, row in df_drift.head(10).iterrows():
        print(f"  {row['feature']:<24} | {row['psi']:<8.4f} | {row['ks_statistic']:<8.4f} | {row['edge_mean']:<12.2f} | {row['lake_mean']:<12.2f} | {row['status']}")

    # 5. Phân tích tác động lên Điểm bất thường (False Positive Impact)
    iso_path = os.path.join(ROOT_DIR, "ml_engine", "models", "decision_tree_isolation_forest", "isolation_forest.joblib")

    false_alarm_analysis = {}
    scores_edge = np.zeros(len(X_edge_norm))
    scores_lake = np.zeros(len(X_lake_norm))
    edge_fp_rate = 5.0
    lake_fp_rate = 0.0

    if os.path.exists(iso_path):
        iso_model = joblib.load(iso_path)
        preds_edge = iso_model.predict(X_edge_norm)
        edge_fp_rate = (np.sum(preds_edge == -1) / len(preds_edge)) * 100.0
        scores_edge = iso_model.score_samples(X_edge_norm)

        preds_lake = iso_model.predict(X_lake_norm)
        lake_fp_rate = (np.sum(preds_lake == -1) / len(preds_lake)) * 100.0
        scores_lake = iso_model.score_samples(X_lake_norm)

        false_alarm_analysis = {
            "edge_normal_false_positive_pct": round(edge_fp_rate, 2),
            "lake_normal_false_positive_pct": round(lake_fp_rate, 2),
            "mean_score_edge_normal": round(float(np.mean(scores_edge)), 4),
            "mean_score_lake_normal": round(float(np.mean(scores_lake)), 4)
        }

        print("\n[*] TÁC ĐỘNG CỦA DRIFT LÊN MÔ HÌNH HỌC MÁY (ISOLATION FOREST):")
        print(f"  - Tỷ lệ báo động giả trên tập phòng lab (Edge-IIoTset Normal): {edge_fp_rate:.2f}%")
        print(f"  - TỶ LỆ BÁO ĐỘNG GIẢ TRÊN MẠNG THẬT (Data Lake Normal):      {lake_fp_rate:.2f}%")
        print(f"  --> KẾT LUẬN: Nếu không có cơ chế Hybrid Retraining, {lake_fp_rate:.1f}% lưu lượng bình thường thực tế sẽ bị bắt nhầm!")

    # 6. Vẽ bộ 4 biểu đồ trực quan hóa cao cấp (High-Quality Visualization Suite)
    print("\n[5/5] Đang vẽ bộ 4 biểu đồ phân tích EDA Context Drift...")

    sns.set_theme(style="whitegrid")
    plt.rcParams["font.sans-serif"] = "DejaVu Sans"

    # --- BIỂU ĐỒ 1: PCA 2D Manifold Distribution Shift ---
    plt.figure(figsize=(10, 7), dpi=150)
    scaler_pca = StandardScaler()
    n_sample_plot = min(len(X_edge_norm), len(X_lake_norm), 3000)
    X_all_stacked = np.vstack([
        X_edge_norm[:n_sample_plot],
        X_lake_norm[:n_sample_plot],
        X_edge_att[:n_sample_plot]
    ])
    X_all_norm = scaler_pca.fit_transform(X_all_stacked)

    pca = PCA(n_components=2, random_state=42)
    pca_res = pca.fit_transform(X_all_norm)

    pca_edge = pca_res[:n_sample_plot]
    pca_lake = pca_res[n_sample_plot:2*n_sample_plot]
    pca_att = pca_res[2*n_sample_plot:]

    plt.scatter(pca_edge[:, 0], pca_edge[:, 1], c="#2ecc71", alpha=0.35, s=20, label=f"Edge-IIoTset Normal (Lab Baseline, N={n_sample_plot})")
    plt.scatter(pca_lake[:, 0], pca_lake[:, 1], c="#f39c12", alpha=0.60, s=28, marker="^", label=f"Data Lake Parquet (Real Wi-Fi, N={n_sample_plot})")
    plt.scatter(pca_att[:, 0], pca_att[:, 1], c="#e74c3c", alpha=0.25, s=18, marker="x", label=f"Edge-IIoTset Attacks (Threats, N={n_sample_plot})")

    var_exp = pca.explained_variance_ratio_ * 100
    plt.title(f"PCA 2D Manifold Shift: Edge-IIoTset vs Real-world Data Lake\n(PC1: {var_exp[0]:.1f}%, PC2: {var_exp[1]:.1f}% Variance Explained)", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel(f"Principal Component 1 ({var_exp[0]:.1f}%)", fontsize=11)
    plt.ylabel(f"Principal Component 2 ({var_exp[1]:.1f}%)", fontsize=11)
    plt.legend(loc="upper right", frameon=True, shadow=True)
    plt.tight_layout()
    chart1_path = os.path.join(out_dir, "01_pca_distribution_shift.png")
    plt.savefig(chart1_path)
    plt.close()
    print(f"  -> [Chart 1] {chart1_path}")

    # --- BIỂU ĐỒ 2: Feature PSI Drift Ranking ---
    plt.figure(figsize=(12, 6), dpi=150)
    top_psi = df_drift.head(15).copy()
    colors = ["#e74c3c" if p >= 0.25 else "#f39c12" if p >= 0.10 else "#2ecc71" for p in top_psi["psi"]]

    plt.barh(top_psi["feature"][::-1], top_psi["psi"][::-1], color=colors[::-1], height=0.65)
    plt.axvline(x=0.10, color="#f39c12", linestyle="--", linewidth=1.5, label="Ngưỡng Moderate Shift (PSI = 0.10)")
    plt.axvline(x=0.25, color="#e74c3c", linestyle="--", linewidth=1.5, label="Ngưỡng Significant Drift (PSI = 0.25)")

    plt.title("Xếp hạng Mức độ Trôi dạt Phân phối (PSI - Population Stability Index)\nTop 15 Đặc trưng Mạng lệch nhất giữa Lab và Mạng Thực tế", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Chỉ số PSI (Càng cao càng lệch dữ liệu)", fontsize=11)
    plt.ylabel("Đặc trưng Mạng", fontsize=11)
    plt.legend(loc="lower right", frameon=True)
    plt.tight_layout()
    chart2_path = os.path.join(out_dir, "02_feature_psi_drift_ranking.png")
    plt.savefig(chart2_path)
    plt.close()
    print(f"  -> [Chart 2] {chart2_path}")

    # --- BIỂU ĐỒ 3: KDE Density Comparison for Top Drifting Features ---
    fig, axes = plt.subplots(2, 3, figsize=(15, 8), dpi=150)
    top_6_feats = df_drift.head(6)["feature"].tolist()

    for idx, feat in enumerate(top_6_feats):
        ax = axes[idx // 3, idx % 3]
        f_idx = feature_names.index(feat)
        v_edge = X_edge_norm[:, f_idx]
        v_lake = X_lake_norm[:, f_idx]

        sns.kdeplot(v_edge, ax=ax, label="Edge-IIoTset Normal (Lab)", color="#2ecc71", fill=True, alpha=0.3, linewidth=2)
        sns.kdeplot(v_lake, ax=ax, label="Data Lake (Real-world)", color="#e67e22", fill=True, alpha=0.3, linewidth=2)

        feat_psi = df_drift.loc[df_drift['feature'] == feat, 'psi'].values[0]
        ax.set_title(f"{feat}\n(PSI = {feat_psi:.3f})", fontsize=11, fontweight="bold")
        ax.set_ylabel("Mật độ xác suất", fontsize=9)
        ax.set_xlabel("Giá trị chuẩn hóa (Z-Score)", fontsize=9)
        if idx == 0:
            ax.legend(fontsize=8)

    plt.suptitle("So sánh Mật độ Phân phối Xác suất (KDE): Dữ liệu Lab vs Mạng Thực tế", fontsize=14, fontweight="bold", y=1.00)
    plt.tight_layout()
    chart3_path = os.path.join(out_dir, "03_density_comparison_kde.png")
    plt.savefig(chart3_path)
    plt.close()
    print(f"  -> [Chart 3] {chart3_path}")

    # --- BIỂU ĐỒ 4: Anomaly Score Drift & False Positive Impact ---
    if false_alarm_analysis:
        plt.figure(figsize=(10, 6), dpi=150)
        sns.kdeplot(scores_edge, color="#2ecc71", fill=True, alpha=0.35, linewidth=2.5, label=f"Edge Normal (Lab Baseline, FP = {edge_fp_rate:.1f}%)")
        sns.kdeplot(scores_lake, color="#e74c3c", fill=True, alpha=0.40, linewidth=2.5, label=f"Data Lake Normal (Real Wi-Fi, FP = {lake_fp_rate:.1f}%)")

        threshold_val = float(np.percentile(scores_edge, 100 - edge_fp_rate)) if len(scores_edge) > 0 else 0.5
        plt.axvline(x=threshold_val, color="#c0392b", linestyle=":", linewidth=2, label=f"Ngưỡng Anomaly ({threshold_val:.3f})")

        plt.title(f"Tác động của Context Drift lên Điểm Dị biệt (Isolation Forest Anomaly Scores)\nMinh chứng tỷ lệ Báo động giả tăng vọt từ {edge_fp_rate:.1f}% lên {lake_fp_rate:.1f}% nếu không có Hybrid Training", fontsize=12, fontweight="bold", pad=12)
        plt.xlabel("Điểm Anomaly Score (Càng thấp càng dị biệt/bất thường)", fontsize=11)
        plt.ylabel("Mật độ phân phối", fontsize=11)
        plt.legend(loc="upper left", frameon=True, shadow=True)
        plt.tight_layout()
        chart4_path = os.path.join(out_dir, "04_anomaly_score_impact.png")
        plt.savefig(chart4_path)
        plt.close()
        print(f"  -> [Chart 4] {chart4_path}")

    # 7. Xuất Báo cáo Kết quả (JSON Summary Report)
    total_feats = len(df_drift)
    sig_count = int(np.sum(df_drift["status"] == "SIGNIFICANT_DRIFT"))
    mod_count = int(np.sum(df_drift["status"] == "MODERATE_SHIFT"))
    no_count = int(np.sum(df_drift["status"] == "NO_SHIFT"))

    report_summary = {
        "timestamp": int(time.time()),
        "total_lake_parquet_files": len(parquet_files),
        "total_lake_records": len(df_lake_all),
        "total_lake_normal_records": len(df_lake_normal),
        "features_analyzed": total_feats,
        "drift_summary": {
            "significant_drift_count": sig_count,
            "significant_drift_pct": round(sig_count / total_feats * 100, 2),
            "moderate_shift_count": mod_count,
            "moderate_shift_pct": round(mod_count / total_feats * 100, 2),
            "no_shift_count": no_count,
            "no_shift_pct": round(no_count / total_feats * 100, 2)
        },
        "false_alarm_analysis": false_alarm_analysis,
        "top_drifting_features": df_drift.head(10).to_dict(orient="records"),
        "charts": [
            "01_pca_distribution_shift.png",
            "02_feature_psi_drift_ranking.png",
            "03_density_comparison_kde.png",
            "04_anomaly_score_impact.png"
        ]
    }

    full_json_path = os.path.join(ROOT_DIR, report_json_path)
    with open(full_json_path, "w", encoding="utf-8") as f:
        json.dump(report_summary, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Đã xuất file báo cáo phân tích toàn diện ra: {full_json_path}")
    print("=" * 76 + "\n")

    return report_summary


if __name__ == "__main__":
    run_drift_eda()
