#!/usr/bin/env python3
"""
Time-Series & Sliding Window Formulation Module
===============================================
Module trích xuất chuỗi thời gian (Sliding Window Temporal Dynamics) phục vụ:
1. Tạo tensor 3D (M, W, D) cho mô hình Deep Learning tuần hoàn (PyTorch LSTM/GRU).
2. Trích xuất vector đặc trưng động lực học (Window Dynamic Features) cho các thuật toán
   dạng cây (Decision Tree, XGBoost, LightGBM, CatBoost, Random Forest).
3. Đánh giá và so sánh định lượng tính hiệu quả giữa:
   - Mô hình điểm tĩnh (Tabular Static Point-in-Time)
   - Mô hình chuỗi thời gian (Time-Series Dynamic Features)
"""

import numpy as np
import pandas as pd
from typing import Tuple, List, Optional, Dict, Any


def create_sliding_windows(
    X: np.ndarray,
    y: Optional[np.ndarray] = None,
    window_size: int = 10,
    step: int = 1
) -> Tuple[np.ndarray, Optional[np.ndarray]]:
    """
    Tạo các cửa sổ trượt thời gian từ ma trận đặc trưng 2D.

    Parameters:
    -----------
    X : np.ndarray
        Ma trận đặc trưng gốc có kích thước (N, D).
    y : Optional[np.ndarray]
        Vector nhãn mục tiêu (N,).
    window_size : int
        Độ dài cửa sổ trượt W (số bước thời gian). Mặc định: 10.
    step : int
        Bước trượt (stride). Mặc định: 1.

    Returns:
    --------
    Tuple[np.ndarray, Optional[np.ndarray]]:
        - X_seq: Tensor 3D có kích thước (M, W, D).
        - y_seq: Vector nhãn tương ứng tại thời điểm cuối của cửa sổ (M,).
    """
    N, D = X.shape
    if N < window_size:
        raise ValueError(f"Số lượng mẫu ({N}) nhỏ hơn kích thước cửa sổ trượt ({window_size})!")

    M = (N - window_size) // step + 1
    X_seq = np.zeros((M, window_size, D), dtype=X.dtype)
    y_seq = np.zeros(M, dtype=y.dtype) if y is not None else None

    for i in range(M):
        start_idx = i * step
        end_idx = start_idx + window_size
        X_seq[i] = X[start_idx:end_idx]
        if y is not None:
            y_seq[i] = y[end_idx - 1]

    return X_seq, y_seq


def extract_window_dynamic_features(
    X_windows: np.ndarray,
    base_feature_names: Optional[List[str]] = None
) -> Tuple[np.ndarray, List[str]]:
    """
    Biến đổi tensor 3D (M, W, D) thành ma trận 2D giàu đặc trưng động lực học
    giúp các mô hình dạng cây (XGBoost, DecisionTree, GBDT) học được quy luật biến thiên thời gian.

    Các đặc trưng trích xuất trên mỗi chiều đặc trưng d:
    1. x_latest: Giá trị tức thời tại thời điểm hiện tại t.
    2. x_mean: Trung bình trượt trong cửa sổ W.
    3. x_std: Độ lệch chuẩn trượt (đo lường độ bất ổn định / burst traffic).
    4. x_delta_step: Vận tốc biến thiên tức thời (x_t - x_{t-1}).
    5. x_delta_window: Độ thay đổi tổng thể toàn cửa sổ (x_t - x_{t-W+1}).
    6. x_ptp: Biên độ dao động cực đại (Peak-to-Peak = Max - Min).

    Returns:
    --------
    Tuple[np.ndarray, List[str]]:
        - X_dynamic: Ma trận (M, D * 6).
        - dynamic_feature_names: Danh sách tên đặc trưng mở rộng.
    """
    M, W, D = X_windows.shape

    # 1. Latest value at step t
    x_latest = X_windows[:, -1, :]

    # 2. Mean across window
    x_mean = np.mean(X_windows, axis=1)

    # 3. Standard deviation across window
    x_std = np.std(X_windows, axis=1)

    # 4. Instantaneous delta (x_t - x_{t-1})
    x_delta_step = X_windows[:, -1, :] - X_windows[:, -2, :] if W >= 2 else np.zeros_like(x_latest)

    # 5. Total window delta (x_t - x_{t-W+1})
    x_delta_window = X_windows[:, -1, :] - X_windows[:, 0, :]

    # 6. Peak-to-peak amplitude (max - min)
    x_ptp = np.ptp(X_windows, axis=1)

    # Ghép toàn bộ thành ma trận đặc trưng động lực học
    X_dynamic = np.hstack([
        x_latest,
        x_mean,
        x_std,
        x_delta_step,
        x_delta_window,
        x_ptp
    ])

    dynamic_names = []
    if base_feature_names and len(base_feature_names) == D:
        for prefix, arr in [
            ("cur", x_latest),
            ("mean", x_mean),
            ("std", x_std),
            ("d_step", x_delta_step),
            ("d_win", x_delta_window),
            ("ptp", x_ptp)
        ]:
            for name in base_feature_names:
                dynamic_names.append(f"{name}_{prefix}")
    else:
        for p in ["cur", "mean", "std", "d_step", "d_win", "ptp"]:
            for d in range(D):
                dynamic_names.append(f"f{d}_{p}")

    return X_dynamic, dynamic_names
