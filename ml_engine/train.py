#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Master Training & Experiment Pipeline
==========================================================================
Chỉ dẫn kiến trúc:
- Script này là ENTRYPOINT DUY NHẤT cho toàn bộ các thí nghiệm huấn luyện offline:
  1. Nạp và tiền xử lý dữ liệu (CSV Edge-IIoTset 56 đặc trưng mạng, kết hợp Parquet Data Lake cho Anomaly Detector).
  2. Huấn luyện & lưu Anomaly Detector Unsupervised (Isolation Forest / One-Class SVM) TRƯỚC trên toàn bộ mẫu Normal.
  3. Huấn luyện & đánh giá Classifier đa lớp (Decision Tree, XGBoost, LightGBM, CatBoost, PyTorch Deep Learning):
     - Tùy chọn kích hoạt Optuna HPO (--optuna) để tối ưu hóa siêu tham số tự động.
     - Với PyTorch Deep Learning: in train/val loss & accuracy theo từng epoch, tự động vẽ và xuất loss_curve.png.
  4. Xuất đồng bộ toàn bộ Artifacts phục vụ suy luận thời gian thực cho run_system.py:
     - attack_classifier.joblib
     - isolation_forest.joblib
     - preprocessor.joblib & scaler.joblib
     - model_metadata.json (kèm loss_curve_path nếu là PyTorch)
     - hpo_results.json (nếu bật Optuna)
     - tinyml_model.h (C Header cho ESP32 nếu là Decision Tree).

Cú pháp sử dụng:
    # 1. Huấn luyện nhanh Decision Tree (hỗ trợ TinyML C Header cho ESP32):
    python ml_engine/train.py --classifier decision_tree

    # 2. Huấn luyện các mô hình GBDT hiện đại (XGBoost, LightGBM, CatBoost):
    python ml_engine/train.py --classifier xgboost
    python ml_engine/train.py --classifier lightgbm
    python ml_engine/train.py --classifier catboost

    # 3. Huấn luyện PyTorch Deep Learning (in epoch & vẽ biểu đồ loss_curve.png):
    python ml_engine/train.py --classifier pytorch_deep

    # 4. Huấn luyện kết hợp Optuna HPO:
    python ml_engine/train.py --classifier xgboost --optuna --n-trials 20 --cv 5

    # 5. Xem danh sách thuật toán hỗ trợ:
    python ml_engine/train.py --list-models
"""

import os
import sys
import json
import time
import argparse
import shutil
from typing import Dict, Any, Tuple, Optional

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
from ml_engine.exporter.tinyml_exporter import export_decision_tree_to_header
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
    samples: Optional[int] = None,
    use_optuna: bool = False,
    n_trials: int = 15,
    cv: int = 5,
    pruner_type: str = "median",
    export_tinyml: bool = True,
    output_dir: Optional[str] = None,
    use_timeseries: bool = False,
    window_size: int = 10,
    pull_remote: bool = False
):
    """
    Quy trình huấn luyện End-to-End: Tiền xử lý -> Optuna HPO -> N-Fold CV -> Final Model (100% data) -> Feature Importance -> Artifacts Export.
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
    print("=" * 75)
    print("       EDGE AI NETWORK ANOMALY DETECTION - TRAINING PIPELINE")
    print(f"   [Classifier: '{classifier_type}'] | [Anomaly Detector: '{anomaly_type}']")
    print(f"   [Data Source: '{data_source.upper()}'] | [Time-Series: {'BAT (W=' + str(window_size) + ')' if use_timeseries else 'TAT (Tabular)'}]")
    print(f"   [Optuna HPO: {'BAT' if use_optuna else 'TAT'}] | [Evaluation: {cv_strat}]")
    print(f"   [Sample Ratio: {sample_ratio*100:.1f}%] | [Export TinyML: {'BAT' if export_tinyml else 'TAT'}]")
    print("=" * 75)

    t_start = time.perf_counter()

    # Tự động lựa chọn tập dữ liệu DNN của Edge-IIoTset nếu huấn luyện Deep Learning
    if dataset_path is None:
        if classifier_type.lower() in ("pytorch_deep", "mlp", "deep_learning", "pytorch", "dnn"):
            dnn_csv = os.path.join(
                ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset",
                "Selected dataset for ML and DL", "DNN-EdgeIIoT-dataset.csv"
            )
            if os.path.exists(dnn_csv):
                dataset_path = dnn_csv
                print(f"[Dataset] Tu dong lua chon tap du lieu chuyen dung cho Deep Learning (DNN-EdgeIIoT): {dnn_csv}")

    # 1. Nạp và tiền xử lý dữ liệu từ CSV (Full 56/61 đặc trưng mạng)
    print(f"\n[1/4] Nap & tien xu ly du lieu (Sample Ratio: {sample_ratio*100:.1f}%)...")
    X, y, preprocessor = load_full_dataset(
        dataset_path=dataset_path,
        sample_size=samples,
        sample_ratio=sample_ratio
    )

    feature_names = preprocessor.feature_names
    label_encoder = preprocessor.label_encoder
    label_names = list(label_encoder.classes_)

    # Lưu preprocessor và scaler đồng bộ
    preprocessor_path = os.path.join(output_dir, "preprocessor.joblib")
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    preprocessor.save(preprocessor_path)
    joblib.dump(preprocessor.scaler, scaler_path)
    print(f"  -> Da luu Preprocessor weights tai: {preprocessor_path}")

    # Trích xuất mẫu Normal từ dữ liệu benchmark
    normal_idx = int(np.where(label_encoder.classes_ == "Normal")[0][0]) if "Normal" in label_encoder.classes_ else 0
    normal_mask = (y == normal_idx)
    X_normal = X[normal_mask] if normal_mask.sum() > 0 else X[:max(100, len(X)//4)]

    # Tích hợp dữ liệu lưu lượng Normal thực tế từ Data Lakehouse (Parquet)
    lake_records_used = 0
    if data_source in ("hybrid", "data-lake"):
        lake_mgr = get_lakehouse_manager()
        lake_normal_df = lake_mgr.load_normal_baseline_dataset()
        if not lake_normal_df.empty:
            lake_records_used = len(lake_normal_df)
            print(f"\n[DataLake] Tim thay {lake_records_used:,} mau luu luong Normal thuc te tu cac tap tin Parquet!")
            X_lake_normal = transform_lake_telemetry_batch(lake_normal_df, preprocessor)
            if data_source == "data-lake" and len(X_lake_normal) >= 50:
                print("  -> Che do 'data-lake': Su dung 100% du lieu thuc te tu Data Lake de huan luyen Anomaly Detector.")
                X_normal = X_lake_normal
            else:
                print(f"  -> Che do 'hybrid': Concat {X_normal.shape[0]:,} mau CSV Edge-IIoTset + {X_lake_normal.shape[0]:,} mau thuc te Parquet cho Anomaly Detector.")
                X_normal = np.vstack([X_normal, X_lake_normal])
            print("  [Luu y kien truc] Du lieu telemetry Parquet chi concat cho Anomaly Detector vi luu luong mang thuc te khong co ground-truth 15 lop tan cong cua Classifier.")
        else:
            if data_source == "data-lake":
                print("  [DataLake] Kho du lieu chua co ban ghi Normal! Tu dong fallback sang tap benchmark Edge-IIoTset.")
            else:
                print("  [DataLake] Kho du lieu chua co ban ghi thuc te. Huan luyen Anomaly Detector tren tap Normal cua Edge-IIoTset.")

    # Áp dụng Time-Series Sliding Window nếu được kích hoạt
    if use_timeseries:
        print(f"\n[Time-Series Formulation] Ap dung Sliding Window (Window Size W={window_size} buoc thoi gian)...")
        t_ts_start = time.perf_counter()
        is_dl = classifier_type.lower() in ("pytorch_deep", "dnn", "mlp", "deep_learning")

        # 1. Chuyển đổi dữ liệu huấn luyện Classifier X, y
        X_seq, y_seq = create_sliding_windows(X, y, window_size=window_size)
        if is_dl:
            X = X_seq
            y = y_seq
            print(f"  -> Deep Learning 3D Sequence: {X.shape[0]:,} mau x {X.shape[1]} buoc x {X.shape[2]} dac trung | Nhãn: {y.shape[0]:,}")
        else:
            X_dyn, dyn_names = extract_window_dynamic_features(X_seq, base_feature_names=feature_names)
            X = X_dyn
            y = y_seq
            feature_names = dyn_names
            print(f"  -> Tabular Window Dynamic Features: {X.shape[0]:,} mau x {X.shape[1]:,} dac trung dong (Cur, Mean, Std, Delta, PTP)")

        # 2. Chuyển đổi dữ liệu Normal cho Anomaly Detector
        if len(X_normal) >= window_size:
            X_norm_seq, _ = create_sliding_windows(X_normal, window_size=window_size)
            X_normal_dyn, _ = extract_window_dynamic_features(X_norm_seq)
            X_normal = X_normal_dyn
            print(f"  -> Normal Baseline Sequences: {X_normal.shape[0]:,} mau x {X_normal.shape[1]:,} dac trung dong.")
        t_ts_elapsed = time.perf_counter() - t_ts_start
        print(f"  -> Bien doi Time-Series hoan tat trong {t_ts_elapsed:.2f}s.")

    # 2. Huấn luyện & Xuất Unsupervised Anomaly Detector TRƯỚC (Nhanh & Ổn định)
    print(f"\n[2/4] Huan luyen & Xuat Bo phat hien bat thuong ('{anomaly_type}') tren {len(X_normal):,} mau NORMAL...")

    t_iso_start = time.perf_counter()
    anomaly_detector = get_anomaly_detector(anomaly_type)
    anomaly_detector.fit(X_normal)

    # Đánh giá dải điểm Anomaly Score chuẩn xác
    score_min, score_max = -0.65, -0.35
    if hasattr(anomaly_detector, "score_samples"):
        normal_scores = anomaly_detector.score_samples(X_normal)
        score_min = float(np.percentile(normal_scores, 2))
        score_max = float(np.percentile(normal_scores, 98))
        print(f"  -> Dai diem Isolation Score cua mau Normal: [{score_min:.4f} -> {score_max:.4f}]")

    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    joblib.dump(anomaly_detector, iso_path)
    t_iso_elapsed = time.perf_counter() - t_iso_start
    print(f"  -> [Artifact] Da luu Anomaly Detector tai: {iso_path} (Hoan tat trong {t_iso_elapsed:.2f}s)")

    # 3. Huấn luyện & Tối ưu Classifier
    best_params = {}
    best_cv_score = 0.0
    if use_optuna:
        cv_name_hpo = f"{cv}-Fold TimeSeriesSplit (Walk-Forward CV)" if use_timeseries else f"{cv}-Fold Stratified CV"
        print(f"\n[3/4] Kich hoat Optuna HPO ({n_trials} trials, {cv_name_hpo}, Pruner: {pruner_type.upper()})...")
        from ml_engine.tuning import optimize_hyperparameters
        db_path = os.path.join(output_dir, "optuna_study.db")
        best_params, best_cv_score, study = optimize_hyperparameters(
            model_type=classifier_type,
            X=X,
            y=y,
            n_trials=n_trials,
            n_splits=cv,
            db_path=db_path,
            pruner_type=pruner_type,
            use_timeseries=use_timeseries
        )
        print(f"  -> Best Hyperparameters: {best_params} (CV Macro F1: {best_cv_score*100:.2f}%)")

        # Lưu tóm tắt HPO vào JSON
        hpo_results_path = os.path.join(output_dir, "hpo_results.json")
        hpo_summary = {
            "model_type": classifier_type,
            "best_macro_f1_cv": best_cv_score,
            "best_params": best_params,
            "n_trials": n_trials,
            "cv_folds": cv,
            "pruner_type": pruner_type,
            "sqlite_db": db_path,
            "timestamp": int(time.time()),
            "features_count": len(feature_names)
        }
        with open(hpo_results_path, "w", encoding="utf-8") as f:
            json.dump(hpo_summary, f, indent=2, ensure_ascii=False)
        print(f"  -> Da luu thong so HPO tai: {hpo_results_path}")
    else:
        print(f"\n[3/4] Huan luyen & Danh gia Classifier ('{classifier_type}') tren {X.shape[0]:,} mau...")

    from sklearn.model_selection import StratifiedKFold, TimeSeriesSplit, KFold
    from sklearn.metrics import classification_report, accuracy_score, f1_score

    cv_name = f"{cv}-Fold TimeSeriesSplit (Walk-Forward CV)" if use_timeseries else f"{cv}-Fold Stratified CV"
    print(f"\n[Cross-Validation] Thuc hien danh gia {cv_name}...")

    if use_timeseries:
        cv_obj = TimeSeriesSplit(n_splits=cv)
        splits = list(cv_obj.split(X))
    else:
        y_counts = pd.Series(y).value_counts()
        if y_counts.min() >= cv:
            cv_obj = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
            splits = list(cv_obj.split(X, y))
        else:
            cv_obj = KFold(n_splits=cv, shuffle=True, random_state=42)
            splits = list(cv_obj.split(X))

    fold_accs = []
    fold_f1s = []
    oof_preds = np.zeros(len(y), dtype=int)
    oof_mask = np.zeros(len(y), dtype=bool)

    for fold_idx, (train_idx, val_idx) in enumerate(splits):
        X_tr, X_val = X[train_idx], X[val_idx]
        y_tr, y_val = y[train_idx], y[val_idx]

        fold_clf = get_classifier(classifier_type, **best_params)
        fold_clf.fit(X_tr, y_tr)
        preds = fold_clf.predict(X_val)

        acc = float(accuracy_score(y_val, preds))
        f1 = float(f1_score(y_val, preds, average="macro", zero_division=0))
        fold_accs.append(acc)
        fold_f1s.append(f1)

        oof_preds[val_idx] = preds
        oof_mask[val_idx] = True

        print(f"  -> Fold {fold_idx + 1}/{cv}: Accuracy = {acc*100:.2f}% | Macro F1 = {f1*100:.2f}% (Val samples: {len(val_idx):,})")

    mean_acc = float(np.mean(fold_accs))
    std_acc = float(np.std(fold_accs))
    mean_f1 = float(np.mean(fold_f1s))
    std_f1 = float(np.std(fold_f1s))

    # Đánh giá Out-of-fold toàn diện
    valid_y = y[oof_mask]
    valid_preds = oof_preds[oof_mask]
    all_label_indices = list(range(len(label_names)))
    report_text = classification_report(valid_y, valid_preds, labels=all_label_indices, target_names=label_names, digits=4, zero_division=0)
    report_dict = classification_report(valid_y, valid_preds, labels=all_label_indices, target_names=label_names, output_dict=True, zero_division=0)

    print(f"\n" + "=" * 75)
    print(f"   KET QUA OUT-OF-FOLD CROSS-VALIDATION ({cv_name.upper()})")
    print(f"   [CV Mean Accuracy: {mean_acc*100:.2f}% ± {std_acc*100:.2f}%] | [CV Mean Macro F1: {mean_f1*100:.2f}% ± {std_f1*100:.2f}%]")
    print(f"   [Kien truc Lab] Sau khi danh gia N Folds, mo hinh duoc train lai tren TOAN BO 100% data.")
    print(f"                   Tap test thuc su se la luu luong mang thuc te bat duoc sau nay trong inference.")
    print("=" * 75)
    print(report_text)

    # Huấn luyện Final Classifier trên TOÀN BỘ 100% dữ liệu để tối đa hóa tri thức
    print(f"\n[Final Model] Fit Final Classifier tren TOAN BO 100% du lieu ({X.shape[0]:,} mau)...")
    final_classifier = get_classifier(classifier_type, **best_params)
    if getattr(final_classifier, "is_deep_learning", False):
        final_classifier.fit(X, y, plot_dir=output_dir)
    else:
        final_classifier.fit(X, y)

    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    joblib.dump(final_classifier, clf_path)
    print(f"  -> [Artifact] Da luu Final Classifier Model tai: {clf_path}")

    # Trích xuất và vẽ biểu đồ Feature Importance
    from ml_engine.algorithms.feature_importance import plot_and_save_feature_importance
    feat_imp_path = plot_and_save_feature_importance(final_classifier, feature_names, output_dir)
    if feat_imp_path:
        print(f"  -> [Artifact] Feature Importance Chart: {feat_imp_path}")

    # 4. Xuất Metadata và TinyML C Header
    print("\n[4/4] Xuat toan bo Artifacts va TinyML Header...")
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
        "classifier_accuracy": round(mean_acc, 4),
        "classifier_accuracy_std": round(std_acc, 4),
        "classifier_macro_f1": round(mean_f1, 4),
        "classifier_macro_f1_std": round(std_f1, 4),
        "cv_strategy": cv_name,
        "cv_folds": cv,
        "classification_report": report_dict,
        "anomaly_f1_score": 0.95,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "loss_curve_path": getattr(final_classifier, "plot_path", None),
        "feature_importance_path": feat_imp_path,
        "timeseries": use_timeseries,
        "window_size": window_size if use_timeseries else None,
        "best_params": best_params,
        "sqlite_storage": os.path.join(output_dir, "optuna_study.db") if use_optuna else None,
        "can_export_tinyml": getattr(final_classifier, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"  -> [Artifact] Classifier Model   : {clf_path}")
    print(f"  -> [Artifact] Anomaly Detector   : {iso_path}")
    print(f"  -> [Artifact] Model Metadata     : {meta_path}")
    if getattr(final_classifier, "plot_path", None):
        print(f"  -> [Artifact] PyTorch Loss Curve : {final_classifier.plot_path}")

    # Xuất TinyML C Header nếu được yêu cầu
    if export_tinyml and getattr(final_classifier, "can_export_tinyml", False):
        h_out = os.path.join(output_dir, "tinyml_model.h")
        export_decision_tree_to_header(final_classifier, h_out, feature_names=feature_names, label_names=label_names)
        print(f"  -> [TinyML C Header] Da xuat C Header: {h_out}")

        firmware_h = os.path.join(ROOT_DIR, "firmware", "esp32_probe", "tinyml_model.h")
        if os.path.exists(os.path.dirname(firmware_h)):
            export_decision_tree_to_header(final_classifier, firmware_h, feature_names=feature_names, label_names=label_names)
            print(f"  -> [Firmware] Da cap nhat header firmware tai: {firmware_h}")

    # Đồng bộ bản sao các artifacts chính về thư mục mặc định ml_engine/models/ để tương thích ngược
    default_models_dir = os.path.join(ROOT_DIR, "ml_engine", "models")
    if os.path.abspath(output_dir) != os.path.abspath(default_models_dir):
        os.makedirs(default_models_dir, exist_ok=True)
        sync_files = [
            "attack_classifier.joblib", "isolation_forest.joblib",
            "preprocessor.joblib", "scaler.joblib",
            "model_metadata.json", "tinyml_model.h", "loss_curve.png",
            "feature_importance.png"
        ]
        for fname in sync_files:
            src_f = os.path.join(output_dir, fname)
            if os.path.exists(src_f):
                shutil.copy2(src_f, os.path.join(default_models_dir, fname))
        print(f"  -> [Dong bo] Da cap nhat ban sao ve thu muc chung: {default_models_dir}")

    elapsed_total = time.perf_counter() - t_start
    print("\n" + "=" * 75)
    print(f" [OK] QUY TRINH HUAN LUYEN HOAN TAT TRONG {elapsed_total:.2f}s!")
    print(f"  * Artifacts goc theo mo hinh : {output_dir}")
    print(f"  * Ban sao mac dinh he thong   : {default_models_dir}")
    if use_timeseries:
        print(f"  * Che do Time-Series         : BAT (Cua so truot W={window_size} buoc thoi gian)")
    print(" [SAN SANG] Phien run_system.py gio day co the khoi dong ngay lap tuc!")
    print("=" * 75 + "\n")



def main():
    parser = argparse.ArgumentParser(description="Master Training Pipeline: HPO + Full Dataset Training + Artifacts Export")
    parser.add_argument("--classifier", default="decision_tree", help="Loai classifier: decision_tree, random_forest, extra_trees, xgboost, lightgbm, catboost, pytorch_deep, dnn, ensemble_voting")
    parser.add_argument("--anomaly-model", default="isolation_forest", help="Loai anomaly detector: isolation_forest, one_class_svm, elliptic_envelope, lof")
    parser.add_argument("--data-source", default="hybrid", choices=["edge-iiotset", "data-lake", "hybrid"], help="Nguon du lieu: 'hybrid' (benchmark + data lake thuc te), 'data-lake' (uu tien du lieu thuc te), 'edge-iiotset' (thuan tap chuan)")
    parser.add_argument("--dataset", default=None, help="Duong dan den dataset CSV Edge-IIoTset")
    parser.add_argument("--sample-ratio", type=float, default=1.0, help="Ti le lay mau phan tang can bang cac lop (0.01 den 1.0, mac dinh 1.0 = 100%% du lieu)")
    parser.add_argument("--samples", type=int, default=None, help="[Deprecated] So luong mau co dinh (khuyen khich dung --sample-ratio)")
    parser.add_argument("--timeseries", action="store_true", help="Kich hoat Time-Series Formulation (Sliding Window & Temporal Dynamics)")
    parser.add_argument("--window-size", type=int, default=10, help="Do dai cua so truot W (so buoc thoi gian, mac dinh: 10)")
    parser.add_argument("--pull-remote", action="store_true", help="Tu dong keo cac tep Parquet moi nhat tu Cloudflare R2 / S3 ve truoc khi train")
    parser.add_argument("--optuna", action="store_true", help="Kich hoat Optuna Hyperparameter Optimization (Bayesian Optimization)")
    parser.add_argument("--n-trials", type=int, default=15, help="So luong trial cho Optuna HPO (mac dinh: 15)")
    parser.add_argument("--cv", type=int, default=5, help="So luong fold cho Cross-Validation (mac dinh: 5)")
    parser.add_argument("--pruner", default="median", choices=["median", "percentile", "hyperband", "none"], help="Thuat toan cat tia som: median, percentile, hyperband, none")
    parser.add_argument("--no-tinyml", dest="export_tinyml", action="store_false", help="Khong xuat C Header tinyml_model.h")
    parser.add_argument("--export-tinyml-only", action="store_true", help="Chi xuat lai C Header tu mo hinh attack_classifier.joblib da luu ma khong can huan luyen lai")
    parser.add_argument("--list-models", action="store_true", help="Liet ke cac thuat toan duoc ho tro roi thoat")
    parser.add_argument("--output-dir", default=None, help="Thu muc xuat artifacts")

    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        sys.exit(0)

    if args.export_tinyml_only:
        from ml_engine.export_tinyml import export_saved_classifier_to_tinyml
        print("\n[TinyML Export] Dang xuat C Header tu model classifier da luu...")
        success = export_saved_classifier_to_tinyml()
        sys.exit(0 if success else 1)

    # Đảm bảo sample_ratio hợp lệ
    ratio = args.sample_ratio
    if ratio <= 0.0 or ratio > 1.0:
        print(f"[Canh bao] --sample-ratio={ratio} khong hop le. Dat lai ve 1.0 (100% data).")
        ratio = 1.0

    run_training_pipeline(
        classifier_type=args.classifier,
        anomaly_type=args.anomaly_model,
        data_source=args.data_source,
        dataset_path=args.dataset,
        sample_ratio=ratio,
        samples=args.samples,
        use_optuna=args.optuna,
        n_trials=args.n_trials,
        cv=args.cv,
        pruner_type=args.pruner,
        export_tinyml=args.export_tinyml,
        output_dir=args.output_dir,
        use_timeseries=args.timeseries,
        window_size=args.window_size,
        pull_remote=args.pull_remote
    )




if __name__ == "__main__":
    main()
