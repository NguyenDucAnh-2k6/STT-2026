#!/usr/bin/env python3
"""
Edge AI Network Security - Comprehensive Exploratory Data Analysis (EDA) Lab Tool
==================================================================================
Cung cấp bộ phân tích dữ liệu EDA chia tách 2 phân hệ chuyên biệt:
1. Chế độ Tĩnh / Dữ liệu bảng (--mode static):
   - Xuất vào thư mục: ml_engine/eda/charts/static/
   - 01_attack_distribution.png: Phân bố 15 loại tấn công & Tỷ lệ nhị phân.
   - 02_missing_values.png: Tỷ lệ khuyết thiếu dữ liệu và độ thưa (Sparsity).
   - 03_categorical_class_discrimination.png: Khả năng phân biệt các lớp tấn công của đặc trưng rời rạc (Cramér's V & Conditional Heatmaps).
   - 04_feature_boxplots.png: Phân vị Boxplots & IQR theo từng loại tấn công.
   - 05_kde_distributions.png: Mật độ xác suất liên tục KDE (Normal vs Attack).
   - 06_correlation_matrix.png: Ma trận tương quan Pearson.
   - 07_mutual_information.png: Xếp hạng thông tin tương hỗ phi tuyến (Mutual Info).
   - 08_outliers_tabular.png: Trực quan hóa ngoại lai không gian tĩnh (PCA 2D + Isolation Forest).

2. Chế độ Chuỗi thời gian (--mode timeseries):
   - Xuất vào thư mục: ml_engine/eda/charts/timeseries/
   - 01_timeseries_anomalies_timeline.png: Dòng thời gian sliding window với dải động mu +/- 2*sigma và gai ngoại lai.
   - 02_phase_space_dynamics.png: Không gian pha động học (Sliding Window Mean vs Instantaneous Delta).
   - 03_temporal_autocorrelation.png: Hàm tự tương quan (ACF) qua các bước trễ thời gian (lags).
   - 04_window_variance_drift.png: Độ lệch chuẩn và biên độ động (Rolling Variance & Window Drift).
   - 05_sliding_window_outlier_scores.png: Điểm số ngoại lai theo cửa sổ trượt phân tách trạng thái ổn định vs bùng nổ tấn công.

Cú pháp sử dụng:
    python ml_engine/eda/analyzer.py --mode static --dataset ML
    python ml_engine/eda/analyzer.py --mode timeseries --dataset DL
    python ml_engine/eda/analyzer.py --mode all --dataset ML
"""

import os
import sys
import time
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)
import argparse
from typing import Optional, List, Tuple, Dict, Any

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import chi2_contingency
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Đảm bảo UTF-8 an toàn trên Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

DATASET_MAP = {
    "ML": os.path.join(
        ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
        "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv"
    ),
    "DL": os.path.join(
        ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
        "Selected dataset for ML and DL", "DNN-EdgeIIoT-dataset.csv"
    )
}
DEFAULT_OUTPUT_DIR = os.path.join(ROOT_DIR, "ml_engine", "eda", "charts")

# Thiết lập phong cách đồ họa Cyber SOC Dark Theme
plt.style.use('dark_background')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#1e293b'
plt.rcParams['axes.linewidth'] = 1.0
plt.rcParams['grid.color'] = '#1e293b'
plt.rcParams['grid.linestyle'] = '--'
plt.rcParams['grid.alpha'] = 0.5


def compute_cramers_v(x: pd.Series, y: pd.Series) -> float:
    """Tính toán chỉ số liên kết Cramér's V (bias-corrected) đo lường khả năng phân biệt lớp của đặc trưng rời rạc."""
    ct = pd.crosstab(x, y)
    if ct.shape[0] <= 1 or ct.shape[1] <= 1:
        return 0.0
    try:
        from scipy.stats import contingency
        val = contingency.association(ct, method='cramer')
        return float(val) if not np.isnan(val) else 0.0
    except Exception:
        chi2 = chi2_contingency(ct)[0]
        n = ct.sum().sum()
        if n <= 1:
            return 0.0
        phi2 = chi2 / n
        r, k = ct.shape
        phi2corr = max(0.0, phi2 - ((k - 1.0) * (r - 1.0)) / (n - 1.0))
        rcorr = r - ((r - 1.0) ** 2) / (n - 1.0)
        kcorr = k - ((k - 1.0) ** 2) / (n - 1.0)
        min_dim = min(kcorr - 1.0, rcorr - 1.0)
        if min_dim <= 0.0:
            return 0.0
        return float(np.sqrt(phi2corr / min_dim))


class EdgeDataAnalyzer:
    """Bộ công cụ phân tích khám phá dữ liệu (EDA) đa chế độ cho Edge AI Security."""

    def __init__(
        self,
        dataset_type: str = "ML",
        output_dir: str = DEFAULT_OUTPUT_DIR,
        mode: str = "static",
        random_state: int = 42
    ):
        self.dataset_type = dataset_type.upper()
        self.dataset_path = DATASET_MAP.get(self.dataset_type, DATASET_MAP["ML"])
        self.base_output_dir = output_dir
        self.mode = mode.lower()
        self.random_state = random_state

        self.df: Optional[pd.DataFrame] = None
        self.feature_cols: List[str] = []
        self.target_col: str = "Attack_type"
        self.binary_col: str = "Attack_label"

    def load_data(self) -> pd.DataFrame:
        """Nạp dữ liệu từ CSV benchmark tương ứng với flag --dataset."""
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Không tìm thấy tập dữ liệu tại: {self.dataset_path}")

        print(f"\n[EDA Analyzer] Đang nạp dataset [{self.dataset_type}] từ:\n  -> {self.dataset_path}")
        df = pd.read_csv(self.dataset_path, low_memory=False)
        total_rows = len(df)
        print(f"  -> Kích thước tập dữ liệu: {total_rows:,} dòng x {df.shape[1]} cột")

        target = "Attack_type" if "Attack_type" in df.columns else df.columns[-1]
        self.target_col = target

        # Tách các cột rò rỉ metadata (IP, time, labels)
        leak_cols = ["frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "Attack_label", "Attack_type", "label"]
        self.feature_cols = [c for c in df.columns if c not in leak_cols]

        self.df = df
        return df

    # =========================================================================
    # CÁC BIỂU ĐỒ CHẾ ĐỘ TĨNH / TABULAR (STATIC MODE)
    # =========================================================================

    def plot_attack_distribution(self, out_dir: str) -> str:
        """1. Biểu đồ phân bố các lớp tấn công & tỷ lệ nhị phân Normal vs Attack."""
        print("[Static 1/8] Đang vẽ 01_attack_distribution.png...")
        df = self.df
        counts = df[self.target_col].value_counts()
        total = len(df)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), facecolor='#091017', gridspec_kw={'width_ratios': [2, 1]})
        ax1.set_facecolor('#0d1722')
        ax2.set_facecolor('#0d1722')

        # Bar chart
        palette = ['#10b981' if x == 'Normal' else '#ef4444' if 'DDoS' in x else '#f59e0b' if 'Scan' in x else '#a855f7' for x in counts.index]
        bars = ax1.barh(np.arange(len(counts)), counts.values, color=palette, edgecolor='#ffffff', alpha=0.85, height=0.65)
        ax1.set_yticks(np.arange(len(counts)))
        ax1.set_yticklabels(counts.index, fontsize=10.5, fontweight='bold', color='#cbd5e1')
        ax1.invert_yaxis()
        ax1.set_xlabel('Số lượng mẫu (Samples)', fontsize=11, color='#94a3b8', labelpad=8)
        ax1.set_title('Phân Bố Chi Tiết 14 Lớp Tấn Công & Lưu Lượng Bình Thường (Normal)', fontsize=12.5, fontweight='bold', color='#38bdf8', pad=12)
        ax1.grid(axis='x', alpha=0.3)

        for bar in bars:
            w = bar.get_width()
            ax1.text(w + max(5, total * 0.005), bar.get_y() + bar.get_height() / 2, f"{int(w):,} ({w / total * 100:.1f}%)",
                     va='center', ha='left', fontsize=9, color='#f1f5f9', fontweight='bold')

        # Pie chart binary
        binary_counts = df["Attack_label"].value_counts() if "Attack_label" in df.columns else pd.Series([counts.get("Normal", 0), total - counts.get("Normal", 0)], index=[0, 1])
        norm_cnt = binary_counts.get(0, 0)
        atk_cnt = binary_counts.get(1, 0)
        ax2.pie([norm_cnt, atk_cnt], labels=['Normal', 'Threat/Attack'], autopct='%1.1f%%',
                startangle=140, colors=['#10b981', '#ef4444'],
                wedgeprops=dict(width=0.45, edgecolor='#091017', linewidth=2),
                textprops=dict(color='#ffffff', fontweight='bold', fontsize=11))
        ax2.set_title('Tỷ Lệ Nhị Phân (Normal vs Attack)', fontsize=12.5, fontweight='bold', color='#38bdf8', pad=12)

        plt.tight_layout()
        out_path = os.path.join(out_dir, "01_attack_distribution.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_missing_values(self, out_dir: str) -> str:
        """2. Trực quan hóa giá trị khuyết (Missing Values & Sparsity)."""
        print("[Static 2/8] Đang vẽ 02_missing_values.png...")
        df = self.df
        null_counts = df.isnull().sum()
        cols_with_null = null_counts[null_counts > 0]

        fig, ax = plt.subplots(figsize=(13, 6), facecolor='#091017')
        ax.set_facecolor('#0d1722')

        if len(cols_with_null) == 0:
            features_sample = self.feature_cols[:25]
            sparsity = (df[features_sample] == 0).mean() * 100
            ax.bar(range(len(features_sample)), sparsity.values, color='#06b6d4', edgecolor='#ffffff', alpha=0.85, width=0.6)
            ax.set_xticks(range(len(features_sample)))
            ax.set_xticklabels(features_sample, rotation=45, ha='right', fontsize=9, color='#cbd5e1')
            ax.set_ylabel('Tỷ lệ giá trị Bằng Không (Sparsity %)', fontsize=11, color='#94a3b8')
            ax.set_title('Độ Thưa Đặc Trưng Mạng (Sparsity / Zero Values) - [Dataset 100% Hoàn Chỉnh, 0% Null]', fontsize=12.5, fontweight='bold', color='#38bdf8', pad=14)
            ax.grid(axis='y', alpha=0.3)
            ax.set_ylim(0, 105)
        else:
            ax.barh(range(len(cols_with_null)), cols_with_null.values, color='#f43f5e', edgecolor='#ffffff', alpha=0.85)
            ax.set_yticks(range(len(cols_with_null)))
            ax.set_yticklabels(cols_with_null.index, fontsize=9.5, color='#cbd5e1')
            ax.set_xlabel('Số lượng giá trị Missing (Nulls)', fontsize=11, color='#94a3b8')
            ax.set_title('Các Cột Chứa Giá Trị Khuyết (Missing Values Analysis)', fontsize=12.5, fontweight='bold', color='#38bdf8', pad=14)
            ax.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        out_path = os.path.join(out_dir, "02_missing_values.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_categorical_class_discrimination(self, out_dir: str) -> str:
        """
        3. Khảo sát khả năng phân biệt lớp tấn công của các đặc trưng rời rạc / phân loại:
        - Bảng xếp hạng Cramér's V đo lường độ liên kết thống kê với Attack Classes.
        - Bản đồ nhiệt phân bố xác suất có điều kiện P(Attack Class | Category) cho các đặc trưng tiêu biểu.
        """
        print("[Static 3/8] Đang vẽ 03_categorical_class_discrimination.png...")
        df = self.df

        # Tìm các cột rời rạc/phân loại
        cat_cols = [c for c in self.feature_cols if 2 <= df[c].nunique() <= 30]
        if not cat_cols:
            cat_cols = [c for c in self.feature_cols if df[c].nunique() <= 50][:10]

        # Tính Cramér's V cho từng đặc trưng phân loại
        cramer_dict = {}
        for c in cat_cols:
            cramer_dict[c] = compute_cramers_v(df[c].astype(str), df[self.target_col])

        cramer_series = pd.Series(cramer_dict).sort_values(ascending=False).head(12)

        fig = plt.figure(figsize=(16, 11), facecolor='#091017')
        gs = fig.add_gridspec(2, 2, height_ratios=[1.0, 1.25], hspace=0.38, wspace=0.25)
        ax_rank = fig.add_subplot(gs[0, :])
        ax_http = fig.add_subplot(gs[1, 0])
        ax_tcp = fig.add_subplot(gs[1, 1])

        ax_rank.set_facecolor('#0d1722')
        ax_http.set_facecolor('#0d1722')
        ax_tcp.set_facecolor('#0d1722')

        # 1. Top Panel: Xếp hạng Cramér's V
        y_pos = np.arange(len(cramer_series))
        norm_v = plt.Normalize(vmin=0.2, vmax=0.8)
        colors = [plt.cm.viridis(norm_v(v)) for v in cramer_series.values]
        bars = ax_rank.barh(y_pos, cramer_series.values, color=colors, edgecolor='#ffffff', alpha=0.85, height=0.6)
        ax_rank.set_yticks(y_pos)
        ax_rank.set_yticklabels(cramer_series.index, fontsize=10, fontweight='bold', color='#cbd5e1')
        ax_rank.invert_yaxis()
        ax_rank.set_xlabel("Chỉ số Cramér's V (Độ Phân Tách Lớp Tấn Công: 0 = Không liên hệ, 1 = Phân biệt hoàn hảo)", fontsize=10.5, color='#94a3b8', labelpad=8)
        ax_rank.set_title("Xếp Hạng Khả Năng Phân Biệt Các Lớp Tấn Công Của Đặc Trưng Phân Loại (Cramér's V Association)", fontsize=12.5, fontweight='bold', color='#38bdf8', pad=12)
        ax_rank.grid(axis='x', alpha=0.3)
        ax_rank.axvline(0.5, color='#f59e0b', linestyle='--', linewidth=1.2, alpha=0.7, label='Ngưỡng liên kết rất mạnh (V >= 0.50)')
        ax_rank.legend(loc='lower right', fontsize=9.5)

        for bar in bars:
            w = bar.get_width()
            ax_rank.text(w + 0.01, bar.get_y() + bar.get_height() / 2, f"V = {w:.3f}",
                         va='center', ha='left', fontsize=9, color='#f1f5f9', fontweight='bold')

        # 2. Bottom-Left Panel: P(Attack | http.request.method)
        target_cat1 = "http.request.method" if "http.request.method" in df.columns else (cramer_series.index[0] if len(cramer_series) > 0 else self.feature_cols[0])
        ct1 = pd.crosstab(df[target_cat1].astype(str), df[self.target_col], normalize='index') * 100
        # Chỉ giữ các cột tấn công có xuất hiện đáng kể
        active_cols1 = ct1.columns[(ct1 > 2).any(axis=0)]
        ct1_filtered = ct1[active_cols1]

        sns.heatmap(ct1_filtered, annot=True, fmt=".1f", cmap="magma", ax=ax_http, cbar=False,
                    linewidths=0.5, linecolor='#091017', annot_kws={"size": 8.5, "weight": "bold"})
        ax_http.set_title(f"Xác Suất Điều Kiện: P(Attack | {target_cat1}) [%]", fontsize=11.5, fontweight='bold', color='#38bdf8', pad=10)
        ax_http.set_xlabel("Loại Tấn Công (Attack Type)", fontsize=9.5, color='#94a3b8')
        ax_http.set_ylabel(f"Giá Trị Danh Mục ({target_cat1})", fontsize=9.5, color='#94a3b8')
        ax_http.tick_params(colors='#cbd5e1', labelsize=8.5)
        plt.setp(ax_http.get_xticklabels(), rotation=35, ha='right')

        # 3. Bottom-Right Panel: P(Attack | tcp.flags / tcp.connection.syn)
        target_cat2 = "tcp.flags" if "tcp.flags" in df.columns else (cramer_series.index[1] if len(cramer_series) > 1 else self.feature_cols[1])
        ct2 = pd.crosstab(df[target_cat2].astype(str), df[self.target_col], normalize='index') * 100
        active_cols2 = ct2.columns[(ct2 > 2).any(axis=0)]
        ct2_filtered = ct2[active_cols2]

        sns.heatmap(ct2_filtered, annot=True, fmt=".1f", cmap="mako", ax=ax_tcp, cbar=False,
                    linewidths=0.5, linecolor='#091017', annot_kws={"size": 8, "weight": "bold"})
        ax_tcp.set_title(f"Xác Suất Điều Kiện: P(Attack | {target_cat2}) [%]", fontsize=11.5, fontweight='bold', color='#38bdf8', pad=10)
        ax_tcp.set_xlabel("Loại Tấn Công (Attack Type)", fontsize=9.5, color='#94a3b8')
        ax_tcp.set_ylabel(f"Giá Trị Danh Mục ({target_cat2})", fontsize=9.5, color='#94a3b8')
        ax_tcp.tick_params(colors='#cbd5e1', labelsize=8.5)
        plt.setp(ax_tcp.get_xticklabels(), rotation=35, ha='right')

        plt.suptitle("Phân Tích Năng Lực Phân Tách Lớp Của Các Đặc Trưng Rời Rạc (Categorical Discrimination Power)", fontsize=13.5, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "03_categorical_class_discrimination.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_boxplots(self, out_dir: str) -> str:
        """4. Biểu đồ Boxplot khảo sát phân vị và ngoại lai theo nhóm tấn công (hỗ trợ symlog chống sụp đổ hộp)."""
        print("[Static 4/8] Đang vẽ 04_feature_boxplots.png...")
        df = self.df
        # Sử dụng các đặc trưng liên tục thực sự có phương sai, không dùng cờ nhị phân (0/1)
        key_features = [
            ("tcp.len", "Độ Dài Gói Tin TCP (Bytes)", True),
            ("tcp.srcport", "Cổng Nguồn TCP (Port Number)", False),
            ("udp.stream", "Chỉ Số Luồng UDP (UDP Stream Index)", True),
            ("http.content_length", "Độ Dài Nội Dung HTTP (Bytes)", True)
        ]
        available_features = [(f, desc, log_sc) for f, desc, log_sc in key_features if f in df.columns]
        if len(available_features) < 4:
            available_features = [(c, c, False) for c in self.feature_cols[:4]]

        fig, axes = plt.subplots(2, 2, figsize=(16, 11), facecolor='#091017')
        axes = axes.flatten()

        top_attacks = list(df[self.target_col].value_counts().head(7).index)
        sub_df = df[df[self.target_col].isin(top_attacks)].copy()

        for idx, (col, desc, use_log) in enumerate(available_features[:4]):
            ax = axes[idx]
            ax.set_facecolor('#0d1722')
            data_to_plot = [pd.to_numeric(sub_df[sub_df[self.target_col] == atk][col], errors='coerce').dropna().values for atk in top_attacks]

            bplot = ax.boxplot(
                data_to_plot,
                patch_artist=True,
                medianprops=dict(color='#00f0ff', linewidth=2),
                flierprops=dict(marker='o', markersize=3, markerfacecolor='#ff0055', alpha=0.5, markeredgecolor='none'),
                whiskerprops=dict(color='#94a3b8', linewidth=1.2),
                capprops=dict(color='#94a3b8', linewidth=1.2)
            )

            colors = ['#10b981' if a == 'Normal' else '#8b5cf6' for a in top_attacks]
            for patch, color in zip(bplot['boxes'], colors):
                patch.set_facecolor(color)
                patch.set_alpha(0.65)
                patch.set_edgecolor('#ffffff')

            if use_log:
                # Áp dụng thang đo đối xứng symlog để hiển thị rõ hộp ngay cả khi có ngoại lai cực lớn hoặc nhiều giá trị 0
                ax.set_yscale('symlog', linthresh=10.0)
                ax.set_ylabel('Giá trị (Thang đo đối xứng Symlog)', fontsize=9.5, color='#94a3b8')
            else:
                ax.set_ylabel('Giá trị tuyến tính (Linear)', fontsize=9.5, color='#94a3b8')

            ax.set_xticklabels(top_attacks, rotation=35, ha='right', fontsize=9, color='#cbd5e1')
            ax.set_title(f"{desc} ({col})", fontsize=11, fontweight='bold', color='#38bdf8')
            ax.grid(axis='y', alpha=0.3)

        plt.suptitle("Boxplots Phân Vị & Điểm Ngoại Lai (Quartiles & Outliers) - [Thang Đo Symlog Khắc Phục Sụp Hộp]", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "04_feature_boxplots.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_kde_distributions(self, out_dir: str) -> str:
        """5. Biểu đồ đường cong mật độ xác suất KDE so sánh Normal vs Attacks (xử lý zero-variance & log-scale)."""
        print("[Static 5/8] Đang vẽ 05_kde_distributions.png...")
        df = self.df
        kde_candidates = [
            ("tcp.len", "TCP Packet Length (Bytes)", True),
            ("tcp.srcport", "TCP Source Port Number", False),
            ("udp.stream", "UDP Stream Identifier", True),
            ("http.content_length", "HTTP Content Length (Bytes)", True)
        ]
        available_kdes = [(f, d, log_tr) for f, d, log_tr in kde_candidates if f in df.columns]
        if len(available_kdes) < 4:
            available_kdes = [(c, c, False) for c in self.feature_cols[:4]]

        fig, axes = plt.subplots(2, 2, figsize=(16, 10), facecolor='#091017')
        axes = axes.flatten()

        is_normal = (df[self.target_col] == "Normal")

        for idx, (col, desc, use_log) in enumerate(available_kdes[:4]):
            ax = axes[idx]
            ax.set_facecolor('#0d1722')

            raw_norm = pd.to_numeric(df[is_normal][col], errors='coerce').dropna()
            raw_atk = pd.to_numeric(df[~is_normal][col], errors='coerce').dropna()

            # Nếu dữ liệu trải rộng qua nhiều bậc độ lớn, dùng log10(x + 1) để hình chuông KDE trải rộng tự nhiên
            if use_log:
                norm_vals = np.log10(np.maximum(0, raw_norm) + 1.0)
                atk_vals = np.log10(np.maximum(0, raw_atk) + 1.0)
                x_label_txt = f"log10({col} + 1)"
            else:
                norm_vals = raw_norm
                atk_vals = raw_atk
                x_label_txt = col

            # Xử lý trường hợp Normal Traffic có phương sai bằng 0 (ví dụ http.content_length = 0 ở 100% mẫu normal)
            if norm_vals.std() < 1e-6 or len(norm_vals.unique()) <= 1:
                const_val = float(norm_vals.iloc[0]) if len(norm_vals) > 0 else 0.0
                ax.axvline(const_val, color='#10b981', linestyle='--', linewidth=2.5,
                           label=f'Normal Traffic: 100% Đồng Nhất ({const_val:.1f})')
            else:
                sns.kdeplot(norm_vals, ax=ax, color='#10b981', label='Normal Traffic', fill=True, alpha=0.35, linewidth=2)

            if atk_vals.std() >= 1e-6 and len(atk_vals.unique()) > 1:
                sns.kdeplot(atk_vals, ax=ax, color='#ff0055', label='Attack Traffic', fill=True, alpha=0.25, linewidth=2)
            else:
                const_atk = float(atk_vals.iloc[0]) if len(atk_vals) > 0 else 0.0
                ax.axvline(const_atk, color='#ff0055', linestyle=':', linewidth=2.0, label=f'Attack Traffic: Hằng Số ({const_atk:.1f})')

            ax.set_title(f"Mật Độ Phân Phối (KDE): {desc}", fontsize=11, fontweight='bold', color='#38bdf8')
            ax.set_xlabel(x_label_txt, fontsize=9.5, color='#94a3b8')
            ax.set_ylabel('Mật độ xác suất (Density)', fontsize=9.5, color='#94a3b8')
            ax.legend(loc='upper right', fontsize=9)
            ax.grid(True, alpha=0.25)

        plt.suptitle("Đường Cong Mật Độ Phân Phối Xác Suất (KDE: Normal vs Attack) - [Đã Log-Scale & Fix Zero Variance]", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "05_kde_distributions.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path


    def plot_correlation_matrix(self, out_dir: str) -> str:
        """6. Ma trận tương quan (Pearson Correlation Heatmap)."""
        print("[Static 6/8] Đang vẽ 06_correlation_matrix.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        variances = df[numeric_cols].var().sort_values(ascending=False)
        selected_cols = list(variances.head(15).index)

        plot_df = df[selected_cols].copy()
        if "Attack_label" in df.columns:
            plot_df["Attack_label"] = df["Attack_label"].astype(float)

        corr = plot_df.corr()

        fig, ax = plt.subplots(figsize=(13, 10), facecolor='#091017')
        ax.set_facecolor('#0d1722')

        sns.heatmap(
            corr,
            annot=True,
            fmt=".2f",
            cmap="coolwarm",
            vmin=-0.4,
            vmax=1.0,
            linewidths=0.5,
            linecolor='#091017',
            cbar_kws={"shrink": 0.8},
            ax=ax,
            annot_kws={"size": 8.5}
        )
        ax.set_title('Ma Trận Tương Quan Pearson (Feature Correlation Matrix Heatmap)', fontsize=13, fontweight='bold', color='#38bdf8', pad=15)
        plt.xticks(rotation=45, ha='right', color='#cbd5e1', fontsize=9)
        plt.yticks(color='#cbd5e1', fontsize=9)

        plt.tight_layout()
        out_path = os.path.join(out_dir, "06_correlation_matrix.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_mutual_information(self, out_dir: str) -> str:
        """7. Xếp hạng tầm ảnh hưởng đặc trưng qua Mutual Information Classif."""
        print("[Static 7/8] Đang tính toán & vẽ 07_mutual_information.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        sub_sample = min(8000, len(df))
        sub_df = df.groupby(self.target_col, group_keys=False).apply(
            lambda g: g.sample(max(2, int(len(g) * sub_sample / len(df))), random_state=self.random_state)
        ).reset_index(drop=True)

        X_sub = sub_df[numeric_cols].fillna(0)
        y_sub = LabelEncoder().fit_transform(sub_df[self.target_col])

        mi_scores = mutual_info_classif(X_sub, y_sub, random_state=self.random_state)
        mi_series = pd.Series(mi_scores, index=numeric_cols).sort_values(ascending=False).head(20)

        fig, ax = plt.subplots(figsize=(12, 8), facecolor='#091017')
        ax.set_facecolor('#0d1722')

        y_pos = np.arange(len(mi_series))
        bars = ax.barh(y_pos, mi_series.values, color='#00f0ff', edgecolor='#ffffff', alpha=0.85, height=0.65)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(mi_series.index, fontsize=9.5, fontweight='bold', color='#cbd5e1')
        ax.invert_yaxis()
        ax.set_xlabel('Mutual Information Score (Độ liên đới thông tin tương hỗ)', fontsize=11, color='#94a3b8', labelpad=8)
        ax.set_title('Top 20 Đặc Trưng Có Thông Tin Tương Hỗ Cao Nhất Với Nhãn Tấn Công (Mutual Info)', fontsize=12.5, fontweight='bold', color='#38bdf8', pad=14)
        ax.grid(axis='x', alpha=0.3)

        for bar in bars:
            w = bar.get_width()
            ax.text(w + 0.005, bar.get_y() + bar.get_height() / 2, f"{w:.3f}",
                    va='center', ha='left', fontsize=9, color='#f1f5f9', fontweight='bold')

        plt.tight_layout()
        out_path = os.path.join(out_dir, "07_mutual_information.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_outliers_tabular(self, out_dir: str) -> str:
        """8. Trực quan hóa Ngoại lai / Bất thường chế độ Thông thường (Tabular Outliers via PCA & Isolation Forest)."""
        print("[Static 8/8] Đang vẽ 08_outliers_tabular.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        sub_sample = min(5000, len(df))
        sub_df = df.sample(sub_sample, random_state=self.random_state).reset_index(drop=True)
        X_vals = sub_df[numeric_cols].fillna(0).values
        X_scaled = StandardScaler().fit_transform(X_vals)

        iso = IsolationForest(contamination=0.08, random_state=self.random_state, n_jobs=-1)
        outlier_preds = iso.fit_predict(X_scaled)
        anomaly_scores = -iso.score_samples(X_scaled)

        pca = PCA(n_components=2, random_state=self.random_state)
        X_pca = pca.fit_transform(X_scaled)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), facecolor='#091017')
        ax1.set_facecolor('#0d1722')
        ax2.set_facecolor('#0d1722')

        inlier_mask = (outlier_preds == 1)
        outlier_mask = (outlier_preds == -1)

        ax1.scatter(X_pca[inlier_mask, 0], X_pca[inlier_mask, 1], c='#00ff9d', alpha=0.45, s=20, label='Mẫu Bình Thường (Inliers)')
        ax1.scatter(X_pca[outlier_mask, 0], X_pca[outlier_mask, 1], c='#ff0055', alpha=0.9, s=45, edgecolors='#ffffff', linewidth=0.5, label='Ngoại Lai Tiềm Ẩn (Flagged Outliers)')
        ax1.set_title(f"PCA 2D: Cụm Dữ Liệu & Điểm Ngoại Lai (Isolation Forest - {outlier_mask.sum()} Outliers)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax1.set_xlabel(f"PCA Component 1 ({pca.explained_variance_ratio_[0]*100:.1f}%)", fontsize=9.5, color='#94a3b8')
        ax1.set_ylabel(f"PCA Component 2 ({pca.explained_variance_ratio_[1]*100:.1f}%)", fontsize=9.5, color='#94a3b8')
        ax1.legend(loc='upper right', fontsize=9.5)
        ax1.grid(True, alpha=0.25)

        sc = ax2.scatter(X_pca[:, 0], X_pca[:, 1], c=anomaly_scores, cmap='inferno', alpha=0.75, s=25)
        cbar = plt.colorbar(sc, ax=ax2, shrink=0.85)
        cbar.set_label('Chỉ số Bất Thường (Raw Anomaly Score)', color='#cbd5e1', fontsize=9.5)
        cbar.ax.yaxis.set_tick_params(color='#cbd5e1')
        plt.setp(plt.getp(cbar.ax.axes, 'yticklabels'), color='#cbd5e1')

        ax2.set_title("Bản Đồ Nhiệt Điểm Bất Thường Trên Không Gian Giảm Chiều PCA", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax2.set_xlabel(f"PCA Component 1 ({pca.explained_variance_ratio_[0]*100:.1f}%)", fontsize=9.5, color='#94a3b8')
        ax2.set_ylabel(f"PCA Component 2 ({pca.explained_variance_ratio_[1]*100:.1f}%)", fontsize=9.5, color='#94a3b8')
        ax2.grid(True, alpha=0.25)

        plt.suptitle("Trực Quan Hóa Điểm Ngoại Lai & Bất Thường - Chế Độ Tĩnh (Tabular Outliers)", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "08_outliers_tabular.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    # =========================================================================
    # CÁC BIỂU ĐỒ CHẾ ĐỘ CHUỖI THỜI GIAN (TIME-SERIES MODE)
    # =========================================================================

    def plot_timeseries_anomalies_timeline(self, out_dir: str, window_size: int = 10) -> str:
        """1. Phát hiện xung bất thường dọc theo chuỗi thời gian (Rolling Bands & Outlier Spikes)."""
        print("[TimeSeries 1/5] Đang vẽ 01_timeseries_anomalies_timeline.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        target_feat = "tcp.len" if "tcp.len" in df.columns else numeric_cols[0]
        series = df[target_feat].fillna(0).values[:600]

        rolling_mean = pd.Series(series).rolling(window=window_size, min_periods=1).mean().values
        rolling_std = pd.Series(series).rolling(window=window_size, min_periods=1).std().fillna(0).values

        upper_band = rolling_mean + 2.0 * rolling_std
        lower_band = np.maximum(0, rolling_mean - 2.0 * rolling_std)
        outlier_spikes = (series > upper_band) | (series < lower_band)

        fig, ax = plt.subplots(figsize=(15, 6), facecolor='#091017')
        ax.set_facecolor('#0d1722')

        timesteps = np.arange(len(series))
        ax.plot(timesteps, series, color='#38bdf8', label=f'Chuỗi Lưu Lượng ({target_feat})', linewidth=1.5, alpha=0.85)
        ax.plot(timesteps, rolling_mean, color='#00ff9d', label=f'Rolling Mean (W={window_size})', linestyle='--', linewidth=1.5)
        ax.fill_between(timesteps, lower_band, upper_band, color='#00ff9d', alpha=0.12, label=r'Dải Ngưỡng Bình Thường ($\mu \pm 2\sigma$)')

        ax.scatter(timesteps[outlier_spikes], series[outlier_spikes], color='#ff0055', s=45, zorder=5, edgecolors='#ffffff', linewidth=0.8, label=f'Xung Ngoại Lai ({outlier_spikes.sum()} Spikes)')

        ax.set_title(f"Dòng Thời Gian Bất Thường Dọc Theo Chuỗi Lưu Lượng Mạng (Time-Series Outliers Timeline)", fontsize=12.5, fontweight='bold', color='#38bdf8', pad=12)
        ax.set_xlabel('Bước Thời Gian (Time Steps / Consecutive Flow Windows)', fontsize=10, color='#94a3b8')
        ax.set_ylabel(f'Cường Độ Lưu Lượng ({target_feat})', fontsize=10, color='#94a3b8')
        ax.legend(loc='upper right', fontsize=9.5)
        ax.grid(True, alpha=0.25)

        plt.tight_layout()
        out_path = os.path.join(out_dir, "01_timeseries_anomalies_timeline.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_phase_space_dynamics(self, out_dir: str, window_size: int = 10) -> str:
        """2. Quỹ đạo không gian pha (Phase Space: Window Mean vs Instantaneous Delta)."""
        print("[TimeSeries 2/5] Đang vẽ 02_phase_space_dynamics.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        target_feat = "tcp.len" if "tcp.len" in df.columns else numeric_cols[0]
        series = df[target_feat].fillna(0).values[:800]

        rolling_mean = pd.Series(series).rolling(window=window_size, min_periods=1).mean().values
        deltas = np.abs(np.diff(series, prepend=series[0]))
        rolling_std = pd.Series(series).rolling(window=window_size, min_periods=1).std().fillna(0).values
        outlier_spikes = (series > rolling_mean + 2.0 * rolling_std)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), facecolor='#091017')
        ax1.set_facecolor('#0d1722')
        ax2.set_facecolor('#0d1722')

        # Scatter 1: Phase Space Attractor
        ax1.scatter(rolling_mean[~outlier_spikes], deltas[~outlier_spikes], c='#00ff9d', alpha=0.5, s=25, label='Trạng Thái Ổn Định (Steady Normal Flow)')
        ax1.scatter(rolling_mean[outlier_spikes], deltas[outlier_spikes], c='#ff0055', alpha=0.9, s=50, edgecolors='#ffffff', linewidth=0.6, label='Quỹ Đạo Bất Thường (Chaotic Turbulence)')
        ax1.set_title("Không Gian Pha Động Học (Window Mean vs Instantaneous Delta)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax1.set_xlabel('Trung Bình Cửa Sổ (Window Rolling Mean)', fontsize=9.5, color='#94a3b8')
        ax1.set_ylabel('Độ Biến Thiên Tức Thời (|Delta|)', fontsize=9.5, color='#94a3b8')
        ax1.legend(loc='upper right', fontsize=9.5)
        ax1.grid(True, alpha=0.25)

        # Scatter 2: Mean vs Window Volatility (Std)
        sc = ax2.scatter(rolling_mean, rolling_std, c=deltas, cmap='plasma', alpha=0.75, s=25)
        cbar = plt.colorbar(sc, ax=ax2, shrink=0.85)
        cbar.set_label('Cường Độ Biến Động (|Delta|)', color='#cbd5e1', fontsize=9)
        cbar.ax.yaxis.set_tick_params(color='#cbd5e1')
        plt.setp(plt.getp(cbar.ax.axes, 'yticklabels'), color='#cbd5e1')

        ax2.set_title("Tương Quan Biến Động: Window Rolling Mean vs Rolling Std", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax2.set_xlabel('Trung Bình Cửa Sổ (Window Rolling Mean)', fontsize=9.5, color='#94a3b8')
        ax2.set_ylabel('Độ Lệch Chuẩn Cửa Sổ (Window Rolling Std)', fontsize=9.5, color='#94a3b8')
        ax2.grid(True, alpha=0.25)

        plt.suptitle("Động Học Phi Tuyến Không Gian Pha Cửa Sổ Trượt (Time-Series Phase Space Dynamics)", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "02_phase_space_dynamics.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_temporal_autocorrelation(self, out_dir: str, max_lags: int = 40) -> str:
        """3. Hàm tự tương quan (Autocorrelation Function - ACF) qua các bước trễ thời gian."""
        print("[TimeSeries 3/5] Đang vẽ 03_temporal_autocorrelation.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        target_feat = "tcp.len" if "tcp.len" in df.columns else numeric_cols[0]
        series = pd.Series(df[target_feat].fillna(0).values[:1500])

        autocorr_values = [series.autocorr(lag=i) for i in range(1, max_lags + 1)]
        lags = np.arange(1, max_lags + 1)

        fig, ax = plt.subplots(figsize=(14, 6), facecolor='#091017')
        ax.set_facecolor('#0d1722')

        # Dải ngưỡng tin cậy 95% Bartlett
        conf = 1.96 / np.sqrt(len(series))
        ax.axhline(conf, color='#f59e0b', linestyle='--', linewidth=1.2, alpha=0.7, label='Ngưỡng Tin Cậy 95% (+/- 1.96 / sqrt(N))')
        ax.axhline(-conf, color='#f59e0b', linestyle='--', linewidth=1.2, alpha=0.7)
        ax.axhline(0, color='#64748b', linestyle='-', linewidth=1.0)

        # Bar stem plot cho ACF
        markerline, stemlines, baseline = ax.stem(lags, autocorr_values, linefmt='#38bdf8', markerfmt='o', basefmt=' ')
        plt.setp(stemlines, 'linewidth', 1.8)
        plt.setp(markerline, 'color', '#00f0ff', 'markersize', 5)

        ax.set_title(f"Hàm Tự Tương Quan Chuỗi Thời Gian (Autocorrelation Function - ACF: {target_feat})", fontsize=12.5, fontweight='bold', color='#38bdf8', pad=12)
        ax.set_xlabel('Bước Trễ Thời Gian (Lag Steps k)', fontsize=10, color='#94a3b8')
        ax.set_ylabel('Hệ Số Tự Tương Quan r(k)', fontsize=10, color='#94a3b8')
        ax.set_ylim(-0.5, 1.05)
        ax.legend(loc='upper right', fontsize=9.5)
        ax.grid(True, alpha=0.25)

        plt.tight_layout()
        out_path = os.path.join(out_dir, "03_temporal_autocorrelation.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_window_variance_drift(self, out_dir: str, window_size: int = 15) -> str:
        """4. Độ lệch chuẩn và biên độ đỉnh-đáy (Rolling Variance & Window PTP Drift) phát hiện chuyển đổi pha tấn công."""
        print("[TimeSeries 4/5] Đang vẽ 04_window_variance_drift.png...")
        df = self.df
        numeric_cols = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c])]

        target_feat = "tcp.len" if "tcp.len" in df.columns else numeric_cols[0]
        series = pd.Series(df[target_feat].fillna(0).values[:800])

        rolling_std = series.rolling(window=window_size, min_periods=1).std().fillna(0).values
        rolling_max = series.rolling(window=window_size, min_periods=1).max().values
        rolling_min = series.rolling(window=window_size, min_periods=1).min().values
        rolling_ptp = rolling_max - rolling_min

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 8), facecolor='#091017', sharex=True)
        ax1.set_facecolor('#0d1722')
        ax2.set_facecolor('#0d1722')

        timesteps = np.arange(len(series))

        ax1.plot(timesteps, rolling_std, color='#a855f7', linewidth=1.6, label=f'Độ Lệch Chuẩn Động (Rolling Std, W={window_size})')
        ax1.fill_between(timesteps, 0, rolling_std, color='#a855f7', alpha=0.15)
        ax1.set_title("Biến Thiên Phương Sai Lưu Lượng Qua Các Cửa Sổ Trượt (Rolling Variance Drift)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax1.set_ylabel('Rolling Std', fontsize=9.5, color='#94a3b8')
        ax1.legend(loc='upper right', fontsize=9)
        ax1.grid(True, alpha=0.25)

        ax2.plot(timesteps, rolling_ptp, color='#f59e0b', linewidth=1.6, label=f'Biên Độ Đỉnh-Đáy Cửa Sổ (Window Peak-to-Peak / PTP, W={window_size})')
        ax2.fill_between(timesteps, 0, rolling_ptp, color='#f59e0b', alpha=0.15)
        ax2.set_title("Biên Độ Dao Động Tức Thời Của Cửa Sổ Trượt (Window Amplitude Drift)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax2.set_xlabel('Bước Thời Gian (Time Steps)', fontsize=10, color='#94a3b8')
        ax2.set_ylabel('Peak-to-Peak Range', fontsize=9.5, color='#94a3b8')
        ax2.legend(loc='upper right', fontsize=9)
        ax2.grid(True, alpha=0.25)

        plt.suptitle("Độ Lệch Chuẩn & Biên Độ Động Học Cửa Sổ Trượt (Time-Series Variance Drift)", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "04_window_variance_drift.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path

    def plot_sliding_window_outlier_scores(self, out_dir: str, window_size: int = 10) -> str:
        """5. Điểm số bất thường theo cửa sổ trượt phân tách trạng thái bình thường vs bùng nổ tấn công."""
        print("[TimeSeries 5/5] Đang vẽ 05_sliding_window_outlier_scores.png...")
        df = self.df
        # Chọn các đặc trưng lưu lượng động có độ biến thiên thực sự
        active_features = ["tcp.len", "tcp.flags", "tcp.srcport", "tcp.dstport", "udp.stream", "http.content_length"]
        available_feats = [f for f in active_features if f in df.columns]
        if len(available_feats) < 2:
            available_feats = [c for c in self.feature_cols if pd.api.types.is_numeric_dtype(df[c]) and df[c].std() > 0][:4]

        # Xây dựng chuỗi thời gian chuyển tiếp thực tế: 400 mẫu Normal tiếp nối bởi 400 mẫu Tấn công
        normal_samples = df[df[self.target_col] == "Normal"]
        attack_samples = df[df[self.target_col] != "Normal"]

        n_norm = min(400, len(normal_samples))
        n_atk = min(400, len(attack_samples))

        seq_df = pd.concat([
            normal_samples.iloc[:n_norm],
            attack_samples.iloc[:n_atk]
        ]).reset_index(drop=True)

        matrix = seq_df[available_feats].apply(pd.to_numeric, errors='coerce').fillna(0).values.astype(float)

        # Tính toán sliding window mean và delta vector
        rolling_means = pd.DataFrame(matrix).rolling(window=window_size, min_periods=1).mean().values
        rolling_stds = pd.DataFrame(matrix).rolling(window=window_size, min_periods=1).std().fillna(0).values
        dyn_matrix = np.hstack([rolling_means, rolling_stds])

        # Huấn luyện Isolation Forest trên 300 mẫu Normal đầu để học baseline
        iso = IsolationForest(contamination=0.1, random_state=self.random_state)
        iso.fit(dyn_matrix[:max(50, int(n_norm * 0.75))])

        # Tính điểm bất thường cho toàn bộ chuỗi chuyển tiếp (Điểm càng cao -> càng bất thường)
        raw_anomaly = -iso.score_samples(dyn_matrix)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), facecolor='#091017')
        ax1.set_facecolor('#0d1722')
        ax2.set_facecolor('#0d1722')

        timesteps = np.arange(len(raw_anomaly))
        threshold = np.percentile(raw_anomaly[:n_norm], 95)

        # Panel 1: Dòng thời gian chuyển tiếp với vùng màu Ground Truth
        ax1.axvspan(0, n_norm, color='#10b981', alpha=0.1, label='Giai Đoạn Bình Thường (Normal Baseline)')
        ax1.axvspan(n_norm, len(timesteps), color='#ef4444', alpha=0.12, label='Giai Đoạn Bùng Nổ Tấn Công (Attack Bursts)')

        ax1.plot(timesteps, raw_anomaly, color='#38bdf8', linewidth=1.5, alpha=0.85, label='Window Anomaly Score')
        ax1.axhline(threshold, color='#f59e0b', linestyle='--', linewidth=1.5, label=f'Ngưỡng Phát Hiện Baseline (95th% Normal = {threshold:.3f})')
        ax1.fill_between(timesteps, threshold, raw_anomaly, where=(raw_anomaly > threshold), color='#ef4444', alpha=0.35, label='Vùng Cảnh Báo Xâm Nhập (IDS Trigger Zone)')

        ax1.set_title("Biến Thiên Chỉ Số Bất Thường Qua Cửa Sổ Trượt (Normal -> Attack Stream)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax1.set_xlabel('Bước Thời Gian (Consecutive Time Windows)', fontsize=9.5, color='#94a3b8')
        ax1.set_ylabel('Chỉ Số Bất Thường (Window Anomaly Score)', fontsize=9.5, color='#94a3b8')
        ax1.legend(loc='upper left', fontsize=8.5)
        ax1.grid(True, alpha=0.25)

        # Panel 2: Histogram / KDE Bimodal phân tách rõ ràng 2 cụm Normal vs Attack
        norm_scores = raw_anomaly[:n_norm]
        atk_scores = raw_anomaly[n_norm:]

        sns.histplot(norm_scores, ax=ax2, color='#10b981', bins=25, kde=True, stat="density", alpha=0.5, label='Normal Window Scores')
        sns.histplot(atk_scores, ax=ax2, color='#ef4444', bins=25, kde=True, stat="density", alpha=0.5, label='Attack Window Scores')
        ax2.axvline(threshold, color='#f59e0b', linestyle='--', linewidth=1.5, label='Ngưỡng Quyết Định')

        ax2.set_title("Phân Bố Xác Suất 2 Đỉnh Tách Biệt (Bimodal Density: Normal vs Attack)", fontsize=11.5, fontweight='bold', color='#38bdf8')
        ax2.set_xlabel('Chỉ Số Bất Thường (Window Anomaly Score)', fontsize=9.5, color='#94a3b8')
        ax2.set_ylabel('Mật Độ Xác Suất (Density)', fontsize=9.5, color='#94a3b8')
        ax2.legend(loc='upper right', fontsize=8.5)
        ax2.grid(True, alpha=0.25)

        plt.suptitle("Đánh Giá Năng Lực Phát Hiện Bất Thường Cửa Sổ Trượt (Sliding Window Anomaly Scoring)", fontsize=13, fontweight='bold', color='#ffffff', y=0.98)
        plt.tight_layout()
        out_path = os.path.join(out_dir, "05_sliding_window_outlier_scores.png")
        plt.savefig(out_path, dpi=250, facecolor=fig.get_facecolor())
        plt.close()
        return out_path


    # =========================================================================
    # ĐIỀU PHỐI THỰC THI (EXECUTION CONTROLLER)
    # =========================================================================

    def run(self) -> Dict[str, str]:
        """Thực thi phân tích EDA tương ứng với giá trị của --mode ('static', 'timeseries', hoặc 'all')."""
        self.load_data()
        generated_charts = {}

        run_static = self.mode in ("static", "all")
        run_ts = self.mode in ("timeseries", "all")

        if run_static:
            static_dir = os.path.join(self.base_output_dir, "static")
            os.makedirs(static_dir, exist_ok=True)
            print(f"\n" + "=" * 75)
            print(f" [PHÂN HỆ EDA 1/2] KHỞI CHẠY CHẾ ĐỘ TĨNH (STATIC TABULAR EDA)")
            print(f"  * Thư mục đích: {static_dir}")
            print("=" * 75)

            generated_charts["static_01_attack_distribution"] = self.plot_attack_distribution(static_dir)
            generated_charts["static_02_missing_values"] = self.plot_missing_values(static_dir)
            generated_charts["static_03_categorical_discrimination"] = self.plot_categorical_class_discrimination(static_dir)
            generated_charts["static_04_feature_boxplots"] = self.plot_boxplots(static_dir)
            generated_charts["static_05_kde_distributions"] = self.plot_kde_distributions(static_dir)
            generated_charts["static_06_correlation_matrix"] = self.plot_correlation_matrix(static_dir)
            generated_charts["static_07_mutual_information"] = self.plot_mutual_information(static_dir)
            generated_charts["static_08_outliers_tabular"] = self.plot_outliers_tabular(static_dir)

        if run_ts:
            ts_dir = os.path.join(self.base_output_dir, "timeseries")
            os.makedirs(ts_dir, exist_ok=True)
            print(f"\n" + "=" * 75)
            print(f" [PHÂN HỆ EDA 2/2] KHỞI CHẠY CHẾ ĐỘ CHUỖI THỜI GIAN (TIME-SERIES EDA)")
            print(f"  * Thư mục đích: {ts_dir}")
            print("=" * 75)

            generated_charts["ts_01_anomalies_timeline"] = self.plot_timeseries_anomalies_timeline(ts_dir)
            generated_charts["ts_02_phase_space_dynamics"] = self.plot_phase_space_dynamics(ts_dir)
            generated_charts["ts_03_temporal_autocorrelation"] = self.plot_temporal_autocorrelation(ts_dir)
            generated_charts["ts_04_window_variance_drift"] = self.plot_window_variance_drift(ts_dir)
            generated_charts["ts_05_sliding_window_outliers"] = self.plot_sliding_window_outlier_scores(ts_dir)

        print("\n" + "=" * 75)
        print(" [HOÀN TẤT] QUY TRÌNH PHÂN TÍCH KHÁM PHÁ DỮ LIỆU (EDA) ĐÃ XUẤT THÀNH CÔNG!")
        if run_static:
            print(f"  * Thư mục Static     : {os.path.join(self.base_output_dir, 'static')}")
        if run_ts:
            print(f"  * Thư mục TimeSeries : {os.path.join(self.base_output_dir, 'timeseries')}")
        print("=" * 75 + "\n")

        return generated_charts


def run_comprehensive_eda(
    dataset_type: str = "ML",
    mode: str = "static",
    output_dir: str = DEFAULT_OUTPUT_DIR
) -> Dict[str, str]:
    """Hàm tiện ích chạy nhanh toàn bộ EDA pipeline."""
    analyzer = EdgeDataAnalyzer(dataset_type=dataset_type, output_dir=output_dir, mode=mode)
    return analyzer.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Edge AI Exploratory Data Analysis (EDA) Lab Tool")
    parser.add_argument(
        "--mode",
        type=str,
        default="static",
        choices=["static", "timeseries", "all"],
        help="Chế độ phân tích: 'static' (dữ liệu bảng/tĩnh xuất vào charts/static) hoặc 'timeseries' (chuỗi thời gian xuất vào charts/timeseries)"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="ML",
        choices=["ML", "DL", "ml", "dl"],
        help="Tập dữ liệu Edge-IIoTset: 'ML' (ML-EdgeIIoT-dataset.csv) hoặc 'DL' (DNN-EdgeIIoT-dataset.csv)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="Thư mục gốc xuất biểu đồ (mặc định: ml_engine/eda/charts)"
    )
    args = parser.parse_args()

    run_comprehensive_eda(
        dataset_type=args.dataset,
        mode=args.mode,
        output_dir=args.output_dir
    )
