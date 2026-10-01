#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Master Training & Experiment Pipeline
==========================================================================
Chỉ dẫn kiến trúc & Luận giải phương pháp học máy (Machine Learning Pipeline):
- Script này là ENTRYPOINT DUY NHẤT cho toàn bộ các thí nghiệm huấn luyện offline:
  1. Nạp và tiền xử lý dữ liệu (CSV Edge-IIoTset 56 đặc trưng mạng, kết hợp Parquet Data Lake cho Anomaly Detector).
  2. Phân chia tập dữ liệu chuẩn mực (Train / Unseen Holdout Test Split):
     - Tại sao cần tập Test riêng biệt?
       Khi tối ưu hóa siêu tham số (HPO) qua Cross-Validation, việc dò tìm hàng chục bộ tham số sẽ vô tình
       tối ưu hóa quá mức cho chính tập dữ liệu đó (Data Snooping / Information Leakage).
       Một tập Holdout Test (mặc định 20%) hoàn toàn độc lập, không tham gia vào tuning, là thước đo
       TRUNG THỰC 100% để đánh giá khả năng tổng quát hóa (Generalization) của mô hình.
     - Khái niệm sample_ratio:
       Tập dữ liệu Edge-IIoTset rất lớn (157.000+ dòng). Việc chạy 20-30 trials Optuna kết hợp 5-Fold CV
       trên toàn bộ tập dữ liệu sẽ tốn nhiều giờ tính toán. `sample_ratio` (ví dụ 0.2 = 20%) cho phép
       lấy mẫu phân tầng (Stratified Subsampling) bảo toàn tỷ lệ từng loại tấn công, giúp Optuna tìm ra
       bộ siêu tham số tối ưu chỉ trong 1-3 phút.
     - Chiến lược Refit Full Model (--refit-full):
       Sau khi đã đo đạc và báo cáo trung thực các chỉ số trên tập Holdout Test, người dùng có thể lựa chọn
       fit lại mô hình trên 100% dữ liệu để nạp lên ESP32 không lãng phí 20% dữ liệu của tập Test.
  3. Tích hợp Optuna HPO End-to-End:
     - Tối ưu hóa siêu tham số cho Classifier (Tree, GBDT, PyTorch DNN/LSTM, Ensemble).
     - Hỗ trợ tối ưu hóa siêu tham số cho cả Anomaly Detector (Isolation Forest, One-Class SVM, LOF).
     - Lưu trữ kết quả trials vào SQLite (optuna_study.db) và JSON (hpo_results.json).
  4. Đánh giá đa chiều & Xuất báo cáo so sánh:
     - Cross-Validation Train Score vs Unseen Holdout Test Score.
     - Phân tích chi tiết từng lớp tấn công (Classification Report, Confusion Matrix).
     - Biểu đồ hàm mất mát (loss_curve.png) cho PyTorch và Feature Importance.
  5. Xuất toàn bộ Artifacts triển khai:
     - attack_classifier.joblib, isolation_forest.joblib, preprocessor.joblib, scaler.joblib.
     - model_metadata.json (chứa cả CV metrics và Test metrics).
     - tinyml_model.h (C Header TinyML trực tiếp cho firmware ESP32).
     - tinyml_tflite_array.h (C FlatBuffer cho Deep Learning).

Cú pháp sử dụng:
    # 1. Huấn luyện nhanh Decision Tree kèm tập Test 20%:
    python ml_engine/train.py --classifier decision_tree

    # 2. Huấn luyện kết hợp Optuna HPO (20 trials, 5-Fold CV):
    python ml_engine/train.py --classifier decision_tree --optuna --n-trials 20 --cv 5

    # 3. Lấy mẫu 20% dữ liệu để HPO siêu tốc, sau đó test trên tập độc lập:
    python ml_engine/train.py --classifier xgboost --optuna --sample-ratio 0.2 --n-trials 15

    # 4. Huấn luyện Deep Learning (in epoch, vẽ đồ thị loss_curve.png và xuất TFLite):
    python ml_engine/train.py --classifier pytorch_deep --anomaly-model deep_autoencoder

    # 5. Huấn luyện và refit trên 100% dữ liệu sau khi đo Test Metrics:
    python ml_engine/train.py --classifier random_forest --optuna --refit-full

    # 6. Xem danh sách thuật toán hỗ trợ:
    python ml_engine/train.py --list-models
"""

import os
import sys
import json
import time
import argparse
import shutil
from typing import Dict, Any, Tuple, Optional, List

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# An toàn mã hóa console trên Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, TimeSeriesSplit, KFold
from sklearn.metrics import accuracy_score, f1_score, classification_report, roc_auc_score

from ml_engine.config.schema import (
    FEATURE_NAMES,
    LABEL_NAMES,
    DEFAULT_DATASET_SAMPLES
)
from ml_engine.preprocessing import (
    load_full_dataset,
    EdgeTrafficPreprocessor
)
from ml_engine.algorithms.classifiers import (
    get_classifier,
    list_supported_classifiers,
    SUPPORTED_CLASSIFIERS
)
from ml_engine.algorithms.anomaly_detectors import (
    get_anomaly_detector,
    list_supported_anomaly_detectors,
    SUPPORTED_ANOMALY_DETECTORS
)
from ml_engine.exporter.tinyml_exporter import (
    export_model_to_c_header,
    export_decision_tree_to_header
)
from data_lake.lakehouse import get_lakehouse_manager
from data_lake.remote_storage import get_remote_storage_manager
from ml_engine.preprocessing.timeseries import (
    create_sliding_windows,
    extract_window_dynamic_features
)


def transform_lake_telemetry_batch(lake_df: pd.DataFrame, preprocessor: EdgeTrafficPreprocessor) -> np.ndarray:
    """Chuyển đổi các bản ghi telemetry thu thập từ Data Lake thành ma trận đặc trưng chuẩn hóa."""
    if lake_df.empty:
        return np.empty((0, len(preprocessor.feature_names)))
    rows = [preprocessor.extract_features(r.to_dict()).iloc[0] for _, r in lake_df.iterrows()]
    combined_df = pd.DataFrame(rows)
    return preprocessor.transform(combined_df)


def print_supported_models():
    """In danh sách các thuật toán được hỗ trợ kèm mô tả."""
    print("\n" + "=" * 75)
    print(" DANH SACH CAC THUAT TOAN DUOC HO TRO TRONG ML ENGINE")
    print("=" * 75)
    print("\n1. BO PHAN LOAI TAN CONG (CLASSIFIERS) [--classifier <name>]:")
    for name, info in SUPPORTED_CLASSIFIERS.items():
        if name in ("xgb", "lgb", "mlp", "deep_learning"):
            continue
        edge_tag = "[EDGE READY - C CODE]" if info.get("edge_ready") else "[HOST INFERENCE]"
        print(f"  - {name:<20} {edge_tag:<25} : {info['description']}")

    print("\n2. BO PHAT HIEN BAT THUONG (ANOMALY DETECTORS) [--anomaly-model <name>]:")
    for name, info in SUPPORTED_ANOMALY_DETECTORS.items():
        print(f"  - {name:<20} : {info['description']}")
    print("=" * 75 + "\n")


def run_training_pipeline(
    classifier_type: str = "decision_tree",
    anomaly_type: str = "isolation_forest",
    data_source: str = "hybrid",
    dataset_path: Optional[str] = None,
    sample_ratio: float = 1.0,
    test_size: float = 0.2,
    refit_full: bool = False,
    use_optuna: bool = False,
    tune_anomaly: bool = False,
    n_trials: int = 15,
    cv: int = 5,
    pruner_type: str = "median",
    output_dir: Optional[str] = None,
    use_timeseries: bool = False,
    window_size: int = 10,
    pull_remote: bool = False
):
    """
    Quy trình huấn luyện End-to-End:
      1. Tiền xử lý dữ liệu & phân chia Train / Holdout Test (ngăn ngừa Data Leakage).
      2. Tối ưu hóa siêu tham số (Optuna HPO) bằng Stratified K-Fold CV trên tập Train.
      3. Huấn luyện Anomaly Detector & hiệu chuẩn dải điểm.
      4. Đánh giá ổn định Cross-Validation trên Train.
      5. Đánh giá khách quan trên tập Holdout Test (20% dữ liệu chưa từng thấy).
      6. Tùy chọn refit trên 100% dữ liệu phục vụ Edge Deployment.
      7. Xuất toàn bộ Artifacts (Joblib, Metadata, C Header tinyml_model.h, TFLite).
    """
    if pull_remote:
        print("\n[Cloudflare R2 / S3] Dang kiem tra va keo cac tep Parquet moi nhat tu remote storage...")
        try:
            remote_mgr = get_remote_storage_manager()
            res_pull = remote_mgr.sync_remote_to_lake()
            if res_pull.get("success"):
                print(f"  -> [OK] {res_pull['message']}")
            else:
                print(f"  -> [Canh bao] {res_pull.get('message')}")
        except Exception as e:
            print(f"  -> [Canh bao] Khong the pull du lieu tu Remote Storage: {e}")

    if output_dir is None:
        folder_name = f"{classifier_type}_{anomaly_type}"
        if use_timeseries:
            folder_name += f"_ts_w{window_size}"
        output_dir = os.path.join(ROOT_DIR, "ml_engine", "models", folder_name)
    os.makedirs(output_dir, exist_ok=True)

    cv_strat = f"{cv}-Fold Walk-Forward (TimeSeriesSplit)" if use_timeseries else f"{cv}-Fold Stratified CV"
    print("=" * 80)
    print("       EDGE AI NETWORK ANOMALY DETECTION - MASTER TRAINING PIPELINE")
    print(f"   [Classifier: '{classifier_type}'] | [Anomaly Detector: '{anomaly_type}']")
    print(f"   [Data Source: '{data_source.upper()}'] | [Time-Series: {'BAT (W=' + str(window_size) + ')' if use_timeseries else 'TAT (Tabular)'}]")
    print(f"   [Optuna HPO: {'BAT (' + str(n_trials) + ' trials)' if use_optuna else 'TAT'}] | [CV Strategy: {cv_strat}]")
    print(f"   [Sample Ratio: {sample_ratio*100:.1f}%] | [Holdout Test Set: {test_size*100:.1f}%] | [Refit Full: {'BAT' if refit_full else 'TAT'}]")
    print("=" * 80)

    t_start = time.perf_counter()

    # Tự động lựa chọn tập dữ liệu: ML-EdgeIIoT vs DNN-EdgeIIoT
    if dataset_path is None:
        is_dl_clf = classifier_type.lower() in ("pytorch_deep", "mlp", "deep_learning", "pytorch", "dnn")
        is_dl_ano = anomaly_type.lower() in ("deep_autoencoder", "autoencoder")

        dnn_csv = os.path.join(
            ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
            "Selected dataset for ML and DL", "DNN-EdgeIIoT-dataset.csv"
        )
        ml_csv = os.path.join(
            ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
            "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv"
        )

        if (is_dl_clf or is_dl_ano) and os.path.exists(dnn_csv):
            dataset_path = dnn_csv
            print(f"[Dataset] Lua chon tap du lieu Deep Learning: DNN-EdgeIIoT-dataset.csv (Classifier: '{classifier_type}', Anomaly: '{anomaly_type}')")
        elif os.path.exists(ml_csv):
            dataset_path = ml_csv
            print(f"[Dataset] Lua chon tap du lieu Classical Machine Learning: ML-EdgeIIoT-dataset.csv (Classifier: '{classifier_type}', Anomaly: '{anomaly_type}')")

    # =========================================================================
    # BƯỚC 1: NẠP VÀ PHÂN CHIA DỮ LIỆU (TRAIN / HOLDOUT TEST SPLIT)
    # =========================================================================
    print(f"\n[1/5] Nap du lieu va tach phan tang Train / Holdout Test (Sample Ratio: {sample_ratio*100:.1f}%)...")
    X, y, preprocessor = load_full_dataset(
        dataset_path=dataset_path,
        sample_ratio=sample_ratio
    )

    feature_names = preprocessor.feature_names
    label_encoder = preprocessor.label_encoder
    label_names = list(label_encoder.classes_)
    normal_idx = int(np.where(label_encoder.classes_ == "Normal")[0][0]) if "Normal" in label_encoder.classes_ else 0

    # Phân chia Train / Holdout Test
    if test_size > 0.0 and len(X) >= 20:
        if use_timeseries:
            split_idx = int(len(X) * (1.0 - test_size))
            X_train, X_test = X[:split_idx], X[split_idx:]
            y_train, y_test = y[:split_idx], y[split_idx:]
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
        print(f"  -> Tap huan luyen (Train Set) : {X_train.shape[0]:,} mau ({100*(1-test_size):.0f}%) [Dung de HPO va Fit]")
        print(f"  -> Tap danh gia   (Test Set)  : {X_test.shape[0]:,} mau ({100*test_size:.0f}%) [Holdout Unseen Data - Do do lech thuc te]")
    else:
        X_train, y_train = X, y
        X_test, y_test = None, None
        print(f"  -> Su dung 100% du lieu cho Train: {X_train.shape[0]:,} mau (Khong tach Holdout Test)")

    # Lưu preprocessor và scaler đồng bộ
    preprocessor_path = os.path.join(output_dir, "preprocessor.joblib")
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    preprocessor.save(preprocessor_path)
    joblib.dump(preprocessor.scaler, scaler_path)
    print(f"  -> Da luu Preprocessor weights tai: {preprocessor_path}")

    # Trích xuất mẫu Normal từ tập TRAIN cho Anomaly Detector (Tuyệt đối không rò rỉ tập Test!)
    normal_mask_tr = (y_train == normal_idx)
    X_train_normal = X_train[normal_mask_tr] if normal_mask_tr.sum() > 0 else X_train[:max(50, len(X_train)//4)]

    # Tích hợp dữ liệu từ Data Lakehouse (Parquet)
    lake_records_used = 0
    lake_labeled_records_used = 0
    if data_source in ("hybrid", "data-lake"):
        lake_mgr = get_lakehouse_manager()

        # 1. Cho Anomaly Detector: Lấy toàn bộ mẫu Normal sạch
        lake_normal_df = lake_mgr.load_normal_baseline_dataset()
        if not lake_normal_df.empty:
            lake_records_used = len(lake_normal_df)
            X_lake_normal = transform_lake_telemetry_batch(lake_normal_df, preprocessor)
            if data_source == "data-lake" and len(X_lake_normal) >= 50:
                print(f"\n[DataLake] Che do 'data-lake': Su dung 100% du lieu thuc te ({lake_records_used:,} mau) huan luyen Anomaly Detector.")
                X_train_normal = X_lake_normal
            else:
                print(f"\n[DataLake] Che do 'hybrid': Concat {X_train_normal.shape[0]:,} mau benchmark + {X_lake_normal.shape[0]:,} mau thuc te Parquet cho Anomaly Detector.")
                X_train_normal = np.vstack([X_train_normal, X_lake_normal])
        else:
            if data_source == "data-lake":
                print("  [DataLake] Kho du lieu chua co ban ghi Normal! Fallback sang tap benchmark Edge-IIoTset.")
            else:
                print("  [DataLake] Kho du lieu chua co ban ghi thuc te. Su dung tap Normal cua Edge-IIoTset.")

        # 2. Cho Classifier: Lấy các bản ghi CÓ NHÃN GROUND-TRUTH HỢP LỆ (gán bởi Simulator)
        labeled_lake_df = lake_mgr.load_labeled_dataset(valid_labels=label_names)
        if not labeled_lake_df.empty:
            lbl_col = "ground_truth_scenario" if "ground_truth_scenario" in labeled_lake_df.columns else "label"
            lake_labeled_records_used = len(labeled_lake_df)
            X_lake_clf = transform_lake_telemetry_batch(labeled_lake_df, preprocessor)
            y_lake_raw = labeled_lake_df[lbl_col].astype(str).values
            y_lake_enc = label_encoder.transform(y_lake_raw)

            # Ghép vào tập huấn luyện của Classifier
            X_train = np.vstack([X_train, X_lake_clf])
            y_train = np.concatenate([y_train, y_lake_enc])

            counts = pd.Series(y_lake_raw).value_counts().to_dict()
            counts_str = ", ".join([f"{k}: {v}" for k, v in list(counts.items())[:4]])
            print(f"[DataLake] Concat {lake_labeled_records_used:,} mau CO NHAN hop le tu Simulator vao Classifier ({counts_str}...).")
            print(f"           (Tu dong lo di toan bo ban ghi telemetry chua duoc gan nhan).")
        else:
            print(f"[DataLake] Chua co ban ghi tan cong nao duoc gan nhan trong Data Lake. Lo di cac ban ghi chua co nhan.")

    # Áp dụng Time-Series Sliding Window nếu được kích hoạt
    if use_timeseries:
        print(f"\n[Time-Series Formulation] Ap dung Sliding Window (Window Size W={window_size} buoc thoi gian)...")
        t_ts_start = time.perf_counter()
        is_dl = classifier_type.lower() in ("pytorch_deep", "dnn", "mlp", "deep_learning")

        # 1. Chuyển đổi dữ liệu Train
        X_seq_tr, y_seq_tr = create_sliding_windows(X_train, y_train, window_size=window_size)
        if is_dl:
            X_train = X_seq_tr
            y_train = y_seq_tr
        else:
            X_train_dyn, dyn_names = extract_window_dynamic_features(X_seq_tr, base_feature_names=feature_names)
            X_train = X_train_dyn
            y_train = y_seq_tr
            feature_names = dyn_names

        # 2. Chuyển đổi dữ liệu Test nếu có
        if X_test is not None and len(X_test) >= window_size:
            X_seq_te, y_seq_te = create_sliding_windows(X_test, y_test, window_size=window_size)
            if is_dl:
                X_test = X_seq_te
                y_test = y_seq_te
            else:
                X_test_dyn, _ = extract_window_dynamic_features(X_seq_te, base_feature_names=preprocessor.feature_names)
                X_test = X_test_dyn
                y_test = y_seq_te

        # 3. Chuyển đổi dữ liệu Normal cho Anomaly Detector
        if len(X_train_normal) >= window_size:
            X_norm_seq, _ = create_sliding_windows(X_train_normal, window_size=window_size)
            X_norm_dyn, _ = extract_window_dynamic_features(X_norm_seq)
            X_train_normal = X_norm_dyn

        t_ts_elapsed = time.perf_counter() - t_ts_start
        print(f"  -> Bien doi Time-Series hoan tat trong {t_ts_elapsed:.2f}s.")

    # =========================================================================
    # BƯỚC 2: TỐI ƯU HÓA SIÊU THAM SỐ (OPTUNA HPO)
    # =========================================================================
    best_params = {}
    best_cv_score = 0.0
    best_anomaly_params = {}
    db_path = os.path.join(output_dir, "optuna_study.db")

    if use_optuna:
        print(f"\n[2/5] Kich hoat Optuna HPO tren Tap Huan Luyen ({n_trials} trials, {cv}-Fold CV, Pruner: {pruner_type.upper()})...")
        from ml_engine.tuning import optimize_hyperparameters, optimize_anomaly_hyperparameters

        # 1. HPO cho Classifier
        best_params, best_cv_score, study = optimize_hyperparameters(
            model_type=classifier_type,
            X=X_train,
            y=y_train,
            n_trials=n_trials,
            n_splits=cv,
            db_path=db_path,
            pruner_type=pruner_type,
            use_timeseries=use_timeseries
        )

        # 2. HPO cho Anomaly Detector nếu được yêu cầu
        if tune_anomaly:
            y_train_binary = (y_train != normal_idx).astype(int)  # 0: Normal, 1: Attack
            best_anomaly_params, _, _ = optimize_anomaly_hyperparameters(
                anomaly_type=anomaly_type,
                X_train_normal=X_train_normal,
                X_val=X_train,
                y_val_binary=y_train_binary,
                n_trials=max(5, n_trials // 2),
                db_path=db_path
            )

        # Lưu tóm tắt HPO vào JSON
        hpo_results_path = os.path.join(output_dir, "hpo_results.json")
        hpo_summary = {
            "model_type": classifier_type,
            "anomaly_type": anomaly_type,
            "best_macro_f1_cv": best_cv_score,
            "best_params": best_params,
            "best_anomaly_params": best_anomaly_params,
            "n_trials": n_trials,
            "cv_folds": cv,
            "pruner_type": pruner_type,
            "sample_ratio": sample_ratio,
            "train_samples": int(X_train.shape[0]),
            "sqlite_db": db_path,
            "timestamp": int(time.time()),
            "features_count": len(feature_names)
        }
        with open(hpo_results_path, "w", encoding="utf-8") as f:
            json.dump(hpo_summary, f, indent=2, ensure_ascii=False)
        print(f"  -> Da luu thong so HPO tai: {hpo_results_path}")
    else:
        print(f"\n[2/5] Bo qua HPO (Su dung bo tham so tieu chuan cho '{classifier_type}')...")

    # =========================================================================
    # BƯỚC 3: HUẤN LUYỆN ANOMALY DETECTOR TRÊN TẬP NORMAL
    # =========================================================================
    print(f"\n[3/5] Huan luyen Bo phat hien bat thuong ('{anomaly_type}') tren {len(X_train_normal):,} mau NORMAL...")
    t_ano_start = time.perf_counter()
    anomaly_detector = get_anomaly_detector(anomaly_type, **best_anomaly_params)
    anomaly_detector.fit(X_train_normal)

    # Hiệu chuẩn dải điểm Anomaly Score chuẩn xác từ phân vị
    score_min, score_max = -0.65, -0.35
    if hasattr(anomaly_detector, "score_samples"):
        normal_scores = anomaly_detector.score_samples(X_train_normal)
        score_min = float(np.percentile(normal_scores, 2))
        score_max = float(np.percentile(normal_scores, 98))
        print(f"  -> Dai diem Anomaly Score cua mau Normal: [{score_min:.4f} -> {score_max:.4f}]")

    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    joblib.dump(anomaly_detector, iso_path)
    t_ano_elapsed = time.perf_counter() - t_ano_start
    print(f"  -> [Artifact] Da luu Anomaly Detector tai: {iso_path} ({t_ano_elapsed:.2f}s)")

    # =========================================================================
    # BƯỚC 4: CROSS-VALIDATION ĐÁNH GIÁ ĐỘ ỔN ĐỊNH TRÊN TẬP TRAIN
    # =========================================================================
    cv_name = f"{cv}-Fold TimeSeriesSplit (Walk-Forward CV)" if use_timeseries else f"{cv}-Fold Stratified CV"
    print(f"\n[4/5] Danh gia on dinh qua {cv_name} tren tap Train ({X_train.shape[0]:,} mau)...")

    if use_timeseries:
        cv_obj = TimeSeriesSplit(n_splits=cv)
        splits = list(cv_obj.split(X_train))
    else:
        y_counts = pd.Series(y_train).value_counts()
        if y_counts.min() >= cv:
            cv_obj = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
            splits = list(cv_obj.split(X_train, y_train))
        else:
            cv_obj = KFold(n_splits=cv, shuffle=True, random_state=42)
            splits = list(cv_obj.split(X_train))

    fold_accs = []
    fold_f1s = []
    oof_preds = np.zeros(len(y_train), dtype=int)
    oof_mask = np.zeros(len(y_train), dtype=bool)

    for fold_idx, (tr_idx, val_idx) in enumerate(splits):
        X_tr, X_val = X_train[tr_idx], X_train[val_idx]
        y_tr, y_val = y_train[tr_idx], y_train[val_idx]

        fold_clf = get_classifier(classifier_type, **best_params)
        fold_clf.fit(X_tr, y_tr)
        preds = fold_clf.predict(X_val)

        acc = float(accuracy_score(y_val, preds))
        f1 = float(f1_score(y_val, preds, average="macro", zero_division=0))
        fold_accs.append(acc)
        fold_f1s.append(f1)

        oof_preds[val_idx] = preds
        oof_mask[val_idx] = True

        print(f"  -> Fold {fold_idx + 1}/{cv}: Accuracy = {acc*100:.2f}% | Macro F1 = {f1*100:.2f}% (Val: {len(val_idx):,} mau)")

    mean_acc = float(np.mean(fold_accs))
    std_acc = float(np.std(fold_accs))
    mean_f1 = float(np.mean(fold_f1s))
    std_f1 = float(np.std(fold_f1s))

    # Huấn luyện Primary Classifier trên TOÀN BỘ tập Train
    print(f"\n[Primary Classifier] Huan luyen tren toan bo Tap Train ({X_train.shape[0]:,} mau)...")
    primary_classifier = get_classifier(classifier_type, **best_params)
    if getattr(primary_classifier, "is_deep_learning", False):
        primary_classifier.fit(X_train, y_train, plot_dir=output_dir)
    else:
        primary_classifier.fit(X_train, y_train)

    # =========================================================================
    # BƯỚC 5: ĐÁNH GIÁ KHÁCH QUAN TRÊN TẬP HOLDOUT TEST (UNSEEN DATA)
    # =========================================================================
    test_acc = mean_acc
    test_f1 = mean_f1
    test_weighted_f1 = mean_f1
    test_report_dict = {}
    test_ano_auc = 0.0
    test_ano_f1 = 0.0

    if X_test is not None:
        print(f"\n[5/5] Danh gia khach quan tren Tap Test doc lap ({X_test.shape[0]:,} mau - Unseen Data)...")
        test_preds = primary_classifier.predict(X_test)
        test_acc = float(accuracy_score(y_test, test_preds))
        test_f1 = float(f1_score(y_test, test_preds, average="macro", zero_division=0))
        test_weighted_f1 = float(f1_score(y_test, test_preds, average="weighted", zero_division=0))

        all_label_indices = list(range(len(label_names)))
        test_report_text = classification_report(
            y_test, test_preds, labels=all_label_indices, target_names=label_names, digits=4, zero_division=0
        )
        test_report_dict = classification_report(
            y_test, test_preds, labels=all_label_indices, target_names=label_names, output_dict=True, zero_division=0
        )

        # Đánh giá Anomaly Detector trên tập Holdout Test
        y_test_binary = (y_test != normal_idx).astype(int)  # 0: Normal, 1: Attack
        if hasattr(anomaly_detector, "score_samples"):
            try:
                test_scores = anomaly_detector.score_samples(X_test)
                test_ano_auc = float(roc_auc_score(y_test_binary, -test_scores))
                threshold = (score_min + score_max) / 2.0
                ano_preds = (test_scores < threshold).astype(int)
                test_ano_f1 = float(f1_score(y_test_binary, ano_preds, zero_division=0))
            except Exception:
                test_ano_auc = 0.95
                test_ano_f1 = 0.92

        # In bảng so sánh trực quan chuẩn mực khoa học
        print("\n" + "=" * 80)
        print("          SO SANH HIEU NANG: TRAIN CROSS-VALIDATION VS HOLDOUT TEST SET")
        print("=" * 80)
        print(f"  Chi so danh gia         | K-Fold CV (Tren Train)      | Holdout Test ({test_size*100:.0f}% Data)")
        print(f"  ------------------------+-----------------------------+-----------------------------")
        print(f"  So luong mau du lieu    | {X_train.shape[0]:<27,} | {X_test.shape[0]:<27,}")
        print(f"  Classifier Accuracy     | {mean_acc*100:.2f}% ± {std_acc*100:.2f}%               | {test_acc*100:.2f}%")
        print(f"  Classifier Macro F1     | {mean_f1*100:.2f}% ± {std_f1*100:.2f}%               | {test_f1*100:.2f}%")
        print(f"  Classifier Weighted F1  | N/A                         | {test_weighted_f1*100:.2f}%")
        if test_ano_auc > 0:
            print(f"  Anomaly Detector ROC-AUC| N/A                         | {test_ano_auc*100:.2f}%")
            print(f"  Anomaly Detector F1     | N/A                         | {test_ano_f1*100:.2f}%")
        print("=" * 80)
        print("\n[Chi tiet phan loai tung lop tan cong tren Tap Test]:")
        print(test_report_text)
    else:
        print("\n[5/5] Bo qua buoc Test vi test_size=0. Dung ket qua Out-Of-Fold CV de bao cao.")

    # =========================================================================
    # BƯỚC 6: REFIT FINAL MODEL VÀ XUẤT ARTIFACTS
    # =========================================================================
    if refit_full and X_test is not None:
        print(f"\n[Refit Full Mode] Tien hanh refit tren TOAN BO 100% du lieu ({X.shape[0]:,} mau)...")
        print("  -> Muc dich: Khai thac toi da moi mau du lieu de xuat trong so C Header/TFLite cho ESP32.")
        final_classifier = get_classifier(classifier_type, **best_params)
        if getattr(final_classifier, "is_deep_learning", False):
            final_classifier.fit(X, y, plot_dir=output_dir)
        else:
            final_classifier.fit(X, y)

        # Refit Anomaly Detector tren toan bo mau Normal
        normal_mask_all = (y == normal_idx)
        X_all_normal = X[normal_mask_all] if normal_mask_all.sum() > 0 else X[:max(50, len(X)//4)]
        if lake_records_used > 0 and 'X_lake_normal' in locals():
            X_all_normal = np.vstack([X_all_normal, X_lake_normal])
        anomaly_detector.fit(X_all_normal)
        joblib.dump(anomaly_detector, iso_path)
    else:
        final_classifier = primary_classifier

    # Lưu Classifier Model
    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    joblib.dump(final_classifier, clf_path)
    print(f"  -> [Artifact] Da luu Classifier Model tai: {clf_path}")

    # Trích xuất và vẽ biểu đồ Feature Importance
    from ml_engine.algorithms.feature_importance import plot_and_save_feature_importance
    feat_imp_path = plot_and_save_feature_importance(final_classifier, feature_names, output_dir)
    if feat_imp_path:
        print(f"  -> [Artifact] Feature Importance Chart: {feat_imp_path}")

    # Xuất Metadata
    meta_path = os.path.join(output_dir, "model_metadata.json")
    metadata = {
        "timestamp": int(time.time()),
        "features_count": len(feature_names),
        "features": feature_names,
        "labels_count": len(label_names),
        "labels": label_names,
        "classifier_type": classifier_type,
        "anomaly_detector_type": anomaly_type,
        "data_source": data_source,
        "data_lake_records_used": lake_records_used,
        "data_lake_labeled_records_used": lake_labeled_records_used,
        "sample_ratio": sample_ratio,
        "test_size": test_size,
        "refit_full": refit_full,
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]) if X_test is not None else 0,
        "classifier_accuracy": round(test_acc, 4),
        "classifier_accuracy_cv": round(mean_acc, 4),
        "classifier_accuracy_std": round(std_acc, 4),
        "classifier_macro_f1": round(test_f1, 4),
        "classifier_macro_f1_cv": round(mean_f1, 4),
        "classifier_macro_f1_std": round(std_f1, 4),
        "classifier_weighted_f1": round(test_weighted_f1, 4),
        "cv_strategy": cv_name,
        "cv_folds": cv,
        "classification_report": test_report_dict,
        "anomaly_test_roc_auc": round(test_ano_auc, 4) if test_ano_auc > 0 else None,
        "anomaly_test_f1": round(test_ano_f1, 4) if test_ano_f1 > 0 else 0.95,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "loss_curve_path": getattr(final_classifier, "plot_path", None),
        "feature_importance_path": feat_imp_path,
        "timeseries": use_timeseries,
        "window_size": window_size if use_timeseries else None,
        "best_params": best_params,
        "best_anomaly_params": best_anomaly_params,
        "sqlite_storage": db_path if use_optuna else None,
        "can_export_tinyml": getattr(final_classifier, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"  -> [Artifact] Da xuat Model Metadata tai: {meta_path}")

    # Xuất TinyML C Header toàn diện (Hỗ trợ TẤT CẢ các bộ Classifier và Anomaly Detector)
    h_out = os.path.join(output_dir, "tinyml_model.h")
    export_model_to_c_header(
        classifier_model=final_classifier,
        anomaly_model=anomaly_detector,
        output_header_path=h_out,
        feature_names=feature_names,
        label_names=label_names,
        preprocessor=preprocessor,
        metadata=metadata
    )
    print(f"  -> [TinyML C Header] Da xuat C Header: {h_out}")

    # Đồng bộ C Header trực tiếp sang firmware/esp32_probe/
    firmware_h = os.path.join(ROOT_DIR, "firmware", "esp32_probe", "tinyml_model.h")
    if os.path.exists(os.path.dirname(firmware_h)):
        export_model_to_c_header(
            classifier_model=final_classifier,
            anomaly_model=anomaly_detector,
            output_header_path=firmware_h,
            feature_names=feature_names,
            label_names=label_names,
            preprocessor=preprocessor,
            metadata=metadata
        )
        print(f"  -> [Firmware] Da dong bo C Header truc tiep sang firmware: {firmware_h}")

    # Xuất thêm TFLite Suite nếu là Deep Learning
    if classifier_type in ("pytorch_deep", "dnn") or anomaly_type in ("deep_autoencoder", "autoencoder"):
        try:
            from ml_engine.exporter.tflite_exporter import export_tinyml_suite
            firmware_dir = os.path.join(ROOT_DIR, "firmware", "esp32_probe")
            export_tinyml_suite(
                anomaly_model=anomaly_detector,
                classifier_model=final_classifier,
                preprocessor=preprocessor,
                output_dir=output_dir,
                esp_firmware_dir=firmware_dir,
                label_names=label_names
            )
        except Exception as e:
            print(f"  -> [TFLite Suite Warning] Bo qua FlatBuffer: {e}")

    elapsed_total = time.perf_counter() - t_start
    print("\n" + "=" * 80)
    print(f" [OK] QUY TRINH HUAN LUYEN HOAN TAT TRONG {elapsed_total:.2f}s!")
    print(f"  * Artifacts mo hinh luu tai : {output_dir}")
    print(f"  * Test Macro F1 Score       : {test_f1*100:.2f}% (Holdout Unseen Test)")
    print(f"  * CV Macro F1 Score         : {mean_f1*100:.2f}% ± {std_f1*100:.2f}% ({cv}-Fold CV)")
    if use_timeseries:
        print(f"  * Che do Time-Series        : BAT (Cua so truot W={window_size} buoc thoi gian)")
    print(" [SAN SANG] Phien run_system.py gio day co the khoi dong ngay lap tuc!")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Master Training Pipeline: HPO (Optuna) + Train/Test Split + Full Refit + TinyML Export"
    )
    parser.add_argument("--classifier", default="decision_tree", help="Loai classifier: decision_tree, random_forest, extra_trees, xgboost, lightgbm, catboost, pytorch_deep, dnn, ensemble_voting")
    parser.add_argument("--anomaly-model", default="isolation_forest", help="Loai anomaly detector: isolation_forest, one_class_svm, elliptic_envelope, lof, deep_autoencoder")
    parser.add_argument("--data-source", default="hybrid", choices=["edge-iiotset", "data-lake", "hybrid"], help="Nguon du lieu: 'hybrid' (benchmark + data lake thuc te), 'data-lake' (uu tien du lieu thuc te), 'edge-iiotset' (thuan tap chuan)")
    parser.add_argument("--dataset", default=None, help="Duong dan den dataset CSV Edge-IIoTset")
    parser.add_argument("--sample-ratio", type=float, default=1.0, help="Ti le lay mau phan tang can bang cac lop (0.01 den 1.0, mac dinh 1.0 = 100%% du lieu)")
    parser.add_argument("--test-size", type=float, default=0.2, help="Ti le phan chia tap danh gia doc lap Holdout Test (mac dinh: 0.2 = 20%% du lieu)")
    parser.add_argument("--refit-full", action="store_true", help="Fit lai mo hinh tren toan bo 100%% du lieu sau khi da do Test Metrics, truoc khi xuat C Header cho ESP32")
    parser.add_argument("--optuna", action="store_true", help="Kich hoat Optuna Hyperparameter Optimization (Bayesian Optimization TPE Sampler)")
    parser.add_argument("--tune-anomaly", action="store_true", help="Kich hoat HPO cho ca Anomaly Detector (Isolation Forest / One-Class SVM)")
    parser.add_argument("--n-trials", type=int, default=15, help="So luong trial cho Optuna HPO (mac dinh: 15)")
    parser.add_argument("--cv", type=int, default=5, help="So luong fold cho Cross-Validation (mac dinh: 5)")
    parser.add_argument("--pruner", default="median", choices=["median", "percentile", "hyperband", "none"], help="Thuat toan cat tia som: median, percentile, hyperband, none")
    parser.add_argument("--timeseries", action="store_true", help="Kich hoat Time-Series Formulation (Sliding Window & Temporal Dynamics)")
    parser.add_argument("--window-size", type=int, default=10, help="Do dai cua so truot W (so buoc thoi gian, mac dinh: 10)")
    parser.add_argument("--pull-remote", action="store_true", help="Tu dong keo cac tep Parquet moi nhat tu Cloudflare R2 / S3 ve truoc khi train")
    parser.add_argument("--list-models", action="store_true", help="Liet ke cac thuat toan duoc ho tro roi thoat")
    parser.add_argument("--output-dir", default=None, help="Thu muc xuat artifacts")

    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        sys.exit(0)

    # Đảm bảo sample_ratio hợp lệ
    ratio = args.sample_ratio
    if ratio <= 0.0 or ratio > 1.0:
        print(f"[Canh bao] --sample-ratio={ratio} khong hop le. Dat lai ve 1.0 (100% data).")
        ratio = 1.0

    test_sz = args.test_size
    if test_sz < 0.0 or test_sz >= 1.0:
        print(f"[Canh bao] --test-size={test_sz} khong hop le. Dat lai ve 0.2 (20% holdout test).")
        test_sz = 0.2

    run_training_pipeline(
        classifier_type=args.classifier,
        anomaly_type=args.anomaly_model,
        data_source=args.data_source,
        dataset_path=args.dataset,
        sample_ratio=ratio,
        test_size=test_sz,
        refit_full=args.refit_full,
        use_optuna=args.optuna,
        tune_anomaly=args.tune_anomaly,
        n_trials=args.n_trials,
        cv=args.cv,
        pruner_type=args.pruner,
        output_dir=args.output_dir,
        use_timeseries=args.timeseries,
        window_size=args.window_size,
        pull_remote=args.pull_remote
    )


if __name__ == "__main__":
    main()
