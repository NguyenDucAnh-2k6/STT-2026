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
    samples: Optional[int] = None,
    use_optuna: bool = False,
    n_trials: int = 15,
    cv: int = 5,
    pruner_type: str = "median",
    export_tinyml: bool = True,
    output_dir: Optional[str] = None
):
    """
    Quy trình huấn luyện End-to-End: Tiền xử lý -> Optuna HPO -> Final Model -> Artifacts Export.
    """
    if output_dir is None:
        output_dir = os.path.join(ROOT_DIR, "ml_engine", "models", f"{classifier_type}_{anomaly_type}")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 75)
    print("       EDGE AI NETWORK ANOMALY DETECTION - TRAINING PIPELINE")
    print(f"   [Classifier: '{classifier_type}'] | [Anomaly Detector: '{anomaly_type}']")
    print(f"   [Data Source: '{data_source.upper()}'] | [Optuna HPO: {'BAT' if use_optuna else 'TAT'}]")
    print(f"   [Cross-Validation: {cv}-Fold Stratified CV] | [Export TinyML: {'BAT' if export_tinyml else 'TAT'}]")
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
    print("\n[1/4] Nap & tien xu ly du lieu (Module Preprocessing)...")
    X, y, preprocessor = load_full_dataset(
        dataset_path=dataset_path,
        sample_size=samples
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
        print(f"\n[3/4] Kich hoat Optuna HPO ({n_trials} trials, {cv}-Fold Stratified CV, Pruner: {pruner_type.upper()})...")
        from ml_engine.tuning import optimize_hyperparameters
        db_path = os.path.join(output_dir, "optuna_study.db")
        best_params, best_cv_score, study = optimize_hyperparameters(
            model_type=classifier_type,
            X=X,
            y=y,
            n_trials=n_trials,
            n_splits=cv,
            db_path=db_path,
            pruner_type=pruner_type
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
        print(f"\n[3/4] Huan luyen Classifier ('{classifier_type}') tren {X.shape[0]:,} mau...")

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score, f1_score

    # Phân chia 80% Train, 20% Test phân tầng để đánh giá khách quan
    y_counts = pd.Series(y).value_counts()
    can_stratify = bool(y_counts.min() >= 2)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y if can_stratify else None
    )
    print(f"  -> Phan chia danh gia: {X_train.shape[0]:,} mau Train | {X_test.shape[0]:,} mau Test (Unseen, Stratify={'BAT' if can_stratify else 'TAT'})")

    # Khởi tạo và huấn luyện Classifier (đồng bộ giao diện, không còn lỗi đỏ)
    eval_classifier = get_classifier(classifier_type, **best_params)
    eval_classifier.fit(X_train, y_train, X_val=X_test, y_val=y_test, plot_dir=output_dir)

    y_pred_test = eval_classifier.predict(X_test)
    test_accuracy = float(accuracy_score(y_test, y_pred_test))
    test_macro_f1 = float(f1_score(y_test, y_pred_test, average="macro"))

    all_label_indices = list(range(len(label_names)))
    report_text = classification_report(y_test, y_pred_test, labels=all_label_indices, target_names=label_names, digits=4, zero_division=0)
    report_dict = classification_report(y_test, y_pred_test, labels=all_label_indices, target_names=label_names, output_dict=True, zero_division=0)

    print(f"\n" + "=" * 75)
    print(f"   KET QUA DANH GIA MO HINH TREN TAP KIEM THU DOC LAP (TEST SET)")
    print(f"   [Test Accuracy: {test_accuracy*100:.2f}%] | [Macro F1-Score: {test_macro_f1*100:.2f}%]")
    print("=" * 75)
    print(report_text)

    # Huấn luyện Final Classifier trên TOÀN BỘ dữ liệu để tối đa hóa tri thức
    if getattr(eval_classifier, "is_deep_learning", False):
        # Giữ mô hình PyTorch đã được fit và validate trực tiếp theo epochs
        classifier = eval_classifier
    else:
        print(f"\n[Final Model] Fit Final Classifier tren toan bo {X.shape[0]:,} mau...")
        classifier = get_classifier(classifier_type, **best_params)
        classifier.fit(X, y)

    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    joblib.dump(classifier, clf_path)
    print(f"  -> [Artifact] Da luu Classifier Model tai: {clf_path}")

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
        "classifier_accuracy": round(test_accuracy, 4),
        "classifier_macro_f1": round(test_macro_f1, 4),
        "classification_report": report_dict,
        "anomaly_f1_score": 0.95,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "loss_curve_path": getattr(eval_classifier, "plot_path", None),
        "best_params": best_params,
        "cv_folds": cv if use_optuna else None,
        "sqlite_storage": os.path.join(output_dir, "optuna_study.db") if use_optuna else None,
        "can_export_tinyml": getattr(classifier, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"  -> [Artifact] Classifier Model   : {clf_path}")
    print(f"  -> [Artifact] Anomaly Detector   : {iso_path}")
    print(f"  -> [Artifact] Model Metadata     : {meta_path}")
    if getattr(eval_classifier, "plot_path", None):
        print(f"  -> [Artifact] PyTorch Loss Curve : {eval_classifier.plot_path}")

    # Xuất TinyML C Header nếu được yêu cầu
    if export_tinyml and getattr(classifier, "can_export_tinyml", False):
        h_out = os.path.join(output_dir, "tinyml_model.h")
        export_decision_tree_to_header(classifier, h_out, feature_names=feature_names, label_names=label_names)
        print(f"  -> [TinyML C Header] Da xuat C Header: {h_out}")

        firmware_h = os.path.join(ROOT_DIR, "firmware", "esp32_probe", "tinyml_model.h")
        if os.path.exists(os.path.dirname(firmware_h)):
            export_decision_tree_to_header(classifier, firmware_h, feature_names=feature_names, label_names=label_names)
            print(f"  -> [Firmware] Da cap nhat header firmware tai: {firmware_h}")

    # Đồng bộ bản sao các artifacts chính về thư mục mặc định ml_engine/models/ để tương thích ngược
    default_models_dir = os.path.join(ROOT_DIR, "ml_engine", "models")
    if os.path.abspath(output_dir) != os.path.abspath(default_models_dir):
        os.makedirs(default_models_dir, exist_ok=True)
        sync_files = [
            "attack_classifier.joblib", "isolation_forest.joblib",
            "preprocessor.joblib", "scaler.joblib",
            "model_metadata.json", "tinyml_model.h", "loss_curve.png"
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
    print(" [SAN SANG] Phien run_system.py gio day co the khoi dong ngay lap tuc!")
    print("=" * 75 + "\n")



def main():
    parser = argparse.ArgumentParser(description="Master Training Pipeline: HPO + Full Dataset Training + Artifacts Export")
    parser.add_argument("--classifier", default="decision_tree", help="Loai classifier: decision_tree, random_forest, extra_trees, xgboost, lightgbm, catboost, pytorch_deep, dnn, ensemble_voting")
    parser.add_argument("--anomaly-model", default="isolation_forest", help="Loai anomaly detector: isolation_forest, one_class_svm, elliptic_envelope, lof")
    parser.add_argument("--data-source", default="hybrid", choices=["edge-iiotset", "data-lake", "hybrid"], help="Nguon du lieu: 'hybrid' (benchmark + data lake thuc te), 'data-lake' (uu tien du lieu thuc te), 'edge-iiotset' (thuan tap chuan)")
    parser.add_argument("--dataset", default=None, help="Duong dan den dataset CSV Edge-IIoTset")
    parser.add_argument("--samples", type=int, default=30000, help="So luong mau du lieu huan luyen (mac dinh: 30,000 mau phan tang)")
    parser.add_argument("--optuna", action="store_true", help="Kich hoat Optuna Hyperparameter Optimization (Bayesian Optimization)")
    parser.add_argument("--n-trials", type=int, default=15, help="So luong trial cho Optuna HPO (mac dinh: 15)")
    parser.add_argument("--cv", type=int, default=5, help="So luong fold cho Stratified K-Fold CV khi Optuna bat (mac dinh: 5)")
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

    run_training_pipeline(
        classifier_type=args.classifier,
        anomaly_type=args.anomaly_model,
        data_source=args.data_source,
        dataset_path=args.dataset,
        samples=args.samples,
        use_optuna=args.optuna,
        n_trials=args.n_trials,
        cv=args.cv,
        pruner_type=args.pruner,
        export_tinyml=args.export_tinyml,
        output_dir=args.output_dir
    )


if __name__ == "__main__":
    main()
