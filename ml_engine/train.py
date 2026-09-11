#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Model Training & Artifact Export Pipeline
=============================================================================
Chỉ dẫn module:
- Module này thực thi quy trình huấn luyện offline hoàn chỉnh độc lập:
  1. Nạp và tiền xử lý toàn diện tập dữ liệu Edge-IIoTset (full 61 đặc trưng đầu vào, 15 nhãn tấn công).
  2. Tùy chọn tối ưu hóa siêu tham số (HPO) tự động qua Optuna 5-Fold Stratified CV (--optuna).
  3. Huấn luyện Final Classifier trên tập huấn luyện (X_train, y_train).
  4. Huấn luyện Anomaly Detector Unsupervised (Isolation Forest) trên các mẫu lưu lượng Normal.
  5. Đánh giá toàn diện trên tập kiểm thử (Accuracy, Macro F1, Chi tiết từng loại tấn công).
  6. Xuất đầy đủ toàn bộ Artifacts phục vụ suy luận thời gian thực:
     - attack_classifier.joblib
     - isolation_forest.joblib
     - preprocessor.joblib & scaler.joblib
     - model_metadata.json
     - tinyml_model.h (C Header cho ESP32 nếu là Decision Tree).

Cú pháp sử dụng:
    python ml_engine/train.py --classifier decision_tree
    python ml_engine/train.py --classifier random_forest --samples 25000
    python ml_engine/train.py --classifier decision_tree --optuna --n-trials 15
    python ml_engine/train.py --list-models
"""

import os
import sys
import json
import time
import argparse
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
from sklearn.metrics import classification_report, accuracy_score, f1_score
import joblib

from ml_engine.config.schema import (
    FEATURE_NAMES,
    LABEL_NAMES,
    DEFAULT_DATASET_SAMPLES
)
from ml_engine.preprocessing import (
    load_and_preprocess_dataset,
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


def print_supported_models():
    """In danh sách các thuật toán được hỗ trợ kèm mô tả."""
    print("\n" + "=" * 75)
    print(" DANH SACH CAC THUAT TOAN DUOC HO TRO TRONG ML ENGINE")
    print("=" * 75)
    print("\n1. BO PHAN LOAI TAN CONG (CLASSIFIERS) [--classifier <name>]:")
    for name, info in SUPPORTED_CLASSIFIERS.items():
        edge_tag = "[EDGE READY - C CODE]" if info.get("edge_ready") else "[HOST INFERENCE]"
        print(f"  - {name:<20} {edge_tag:<25} : {info['description']}")

    print("\n2. BO PHAT HIEN BAT THUONG (ANOMALY DETECTORS) [--anomaly-model <name>]:")
    for name, info in SUPPORTED_ANOMALY_DETECTORS.items():
        print(f"  - {name:<20} : {info['description']}")
    print("=" * 75 + "\n")


def run_training_pipeline(
    classifier_type: str = "decision_tree",
    anomaly_type: str = "isolation_forest",
    dataset_path: Optional[str] = None,
    samples: Optional[int] = None,
    use_optuna: bool = False,
    n_trials: int = 15,
    cv: int = 5,
    export_tinyml: bool = True,
    output_dir: Optional[str] = None
):
    """
    Quy trình huấn luyện offline hoàn chỉnh và xuất toàn bộ artifacts & header.
    """
    if output_dir is None:
        output_dir = os.path.join(ROOT_DIR, "ml_engine", "models")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 75)
    print("       EDGE AI NETWORK ANOMALY DETECTION - TRAINING PIPELINE")
    print(f"   [Classifier: '{classifier_type}'] | [Anomaly Detector: '{anomaly_type}']")
    print(f"   [Optuna HPO: {'BAT' if use_optuna else 'TAT'}] | [Export TinyML: {'BAT' if export_tinyml else 'TAT'}]")
    print("=" * 75)

    # 1. Nạp và tiền xử lý dữ liệu từ module preprocessing (Full 61 đặc trưng)
    print("\n[1/5] Nap & tien xu ly du lieu (Module Preprocessing - Full 61 Features)...")
    t_start = time.perf_counter()
    X_train, X_test, y_train, y_test, preprocessor = load_and_preprocess_dataset(
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

    # 2. Tối ưu hóa siêu tham số (HPO) nếu có yêu cầu
    best_params = {}
    if use_optuna:
        print(f"\n[2/5] Kich hoat Optuna HPO ({n_trials} trials, {cv}-Fold Stratified CV)...")
        from ml_engine.tuning.optuna_tuner import optimize_hyperparameters
        db_path = os.path.join(output_dir, "optuna_study.db")
        best_params, best_cv_score, _ = optimize_hyperparameters(
            model_type=classifier_type,
            X=X_train,
            y=y_train,
            n_trials=n_trials,
            n_splits=cv,
            db_path=db_path
        )
        print(f"  -> Best Hyperparameters: {best_params} (CV F1: {best_cv_score*100:.2f}%)")
    else:
        print("\n[2/5] Bo qua HPO. Su dung bo sieu tham so mac dinh toi uu cho canh bien.")

    # 3. Huấn luyện Final Classifier trên toàn bộ tập train
    print(f"\n[3/5] Huan luyen Final Classifier ('{classifier_type}') tren {X_train.shape[0]:,} mau...")
    classifier = get_classifier(classifier_type, **best_params)
    classifier.fit(X_train, y_train)

    y_pred = classifier.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    print(f"  -> {classifier_type} Test Accuracy: {acc * 100:.2f}% | Test Macro F1: {macro_f1 * 100:.2f}%")
    print("\nChi tiet Classification Report tren Test Set:")
    eval_labels = sorted(list(set(y_test) | set(y_pred)))
    eval_names = [label_names[i] if i < len(label_names) else f"Class_{i}" for i in eval_labels]
    print(classification_report(y_test, y_pred, labels=eval_labels, target_names=eval_names, zero_division=0))

    # 4. Huấn luyện Unsupervised Anomaly Detector trên mẫu Normal (y == 0)
    print(f"\n[4/5] Huan luyen Bo phat hien bat thuong ('{anomaly_type}')...")
    anomaly_detector = get_anomaly_detector(anomaly_type)
    normal_train = X_train[y_train == 0]
    if len(normal_train) == 0:
        normal_train = X_train[:max(100, len(X_train)//4)]
    anomaly_detector.fit(normal_train)

    # Đánh giá Anomaly Score
    if hasattr(anomaly_detector, "score_samples"):
        test_scores = anomaly_detector.score_samples(X_test)
        score_min = float(test_scores.min())
        score_max = float(test_scores.max())
    else:
        score_min, score_max = -1.0, 0.0

    preds_binary = (anomaly_detector.predict(X_test) == -1).astype(int)
    actual_binary = (y_test != 0).astype(int)
    anomaly_f1 = float(f1_score(actual_binary, preds_binary, zero_division=0))
    print(f"  -> {anomaly_type} Binary F1: {anomaly_f1:.4f} (Score range: [{score_min:.3f}, {score_max:.3f}])")

    # 5. Lưu Artifacts và xuất C Header
    print("\n[5/5] Xuat toan bo Artifacts va TinyML Header...")
    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(classifier, clf_path)
    joblib.dump(anomaly_detector, iso_path)

    metadata = {
        "timestamp": int(time.time()),
        "features_count": len(feature_names),
        "features": feature_names,
        "labels_count": len(label_names),
        "labels": label_names,
        "classifier_type": classifier_type,
        "anomaly_detector_type": anomaly_type,
        "classifier_accuracy": acc,
        "classifier_macro_f1": macro_f1,
        "anomaly_f1_score": anomaly_f1,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "best_params": best_params,
        "can_export_tinyml": getattr(classifier, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"  -> [Artifact] Classifier Model   : {clf_path}")
    print(f"  -> [Artifact] Anomaly Detector   : {iso_path}")
    print(f"  -> [Artifact] Model Metadata     : {meta_path}")

    # Xuất TinyML C Header nếu được yêu cầu
    if export_tinyml and getattr(classifier, "can_export_tinyml", False):
        h_out = os.path.join(output_dir, "tinyml_model.h")
        export_decision_tree_to_header(classifier, h_out, feature_names=feature_names, label_names=label_names)
        print(f"  -> [TinyML C Header] Da xuat C Header: {h_out}")

        firmware_h = os.path.join(ROOT_DIR, "firmware", "esp32_probe", "tinyml_model.h")
        if os.path.exists(os.path.dirname(firmware_h)):
            export_decision_tree_to_header(classifier, firmware_h, feature_names=feature_names, label_names=label_names)
            print(f"  -> [Firmware] Da cap nhat header firmware tai: {firmware_h}")

    elapsed_total = time.perf_counter() - t_start
    print("\n" + "=" * 75)
    print(f" [OK] QUY TRINH HUAN LUYEN HOAN TAT TRONG {elapsed_total:.2f}s!")
    print(f"  * Tat ca Artifacts da san sang tai: {output_dir}")
    print("=" * 75 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Train Offline Network Anomaly Detection Models & Export Artifacts")
    parser.add_argument("--classifier", default="decision_tree", help="Loai classifier: decision_tree, random_forest, extra_trees, gradient_boosting, mlp, ensemble_voting")
    parser.add_argument("--anomaly-model", default="isolation_forest", help="Loai anomaly detector: isolation_forest, one_class_svm, elliptic_envelope, lof")
    parser.add_argument("--dataset", default=None, help="Duong dan den dataset CSV Edge-IIoTset")
    parser.add_argument("--samples", type=int, default=None, help="So luong mau du lieu huan luyen (mac dinh: None - huan luyen toan bo 157,800 mau)")
    parser.add_argument("--optuna", action="store_true", help="Kich hoat Optuna Hyperparameter Optimization")
    parser.add_argument("--n-trials", type=int, default=15, help="So luong trial cho Optuna HPO")
    parser.add_argument("--cv", type=int, default=5, help="So luong fold cho Stratified K-Fold CV khi Optuna bat (mac dinh: 5)")
    parser.add_argument("--no-tinyml", dest="export_tinyml", action="store_false", help="Khong xuat C Header tinyml_model.h")
    parser.add_argument("--list-models", action="store_true", help="Liet ke cac thuat toan duoc ho tro roi thoat")
    parser.add_argument("--output-dir", default=None, help="Thu muc xuat artifacts")

    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        sys.exit(0)

    run_training_pipeline(
        classifier_type=args.classifier,
        anomaly_type=args.anomaly_model,
        dataset_path=args.dataset,
        samples=args.samples,
        use_optuna=args.optuna,
        n_trials=args.n_trials,
        cv=args.cv,
        export_tinyml=args.export_tinyml,
        output_dir=args.output_dir
    )


if __name__ == "__main__":
    main()
