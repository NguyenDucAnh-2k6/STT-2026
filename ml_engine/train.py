#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Model Training Pipeline
============================================================
Chỉ dẫn module:
- Module này thực thi quy trình huấn luyện toàn diện cho hệ thống phát hiện bất thường:
  1. Sinh tập dữ liệu lưu lượng mạng mô phỏng (CIC-IDS2017/NSL-KDD benchmark).
  2. Chuẩn hóa đặc trưng qua TrafficFeaturePreprocessor.
  3. Huấn luyện mô hình phát hiện bất thường Unsupervised (chọn qua flag --anomaly-model).
  4. Huấn luyện bộ phân loại dạng tấn công Supervised (chọn qua flag --classifier).
  5. Đánh giá độ chính xác (Accuracy, F1-Score, Classification Report).
  6. Lưu trữ model weights (.joblib), metadata (.json), và xuất C header (TinyML).

Cú pháp sử dụng dòng lệnh:
    python ml_engine/train.py --list-models
    python ml_engine/train.py --classifier decision_tree --export-tinyml
    python ml_engine/train.py --classifier random_forest --anomaly-model isolation_forest
    python ml_engine/train.py --classifier all_compare
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, Tuple

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path khi gọi trực tiếp
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Đảm bảo UTF-8 hoặc an toàn mã hóa trên Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
import joblib

# Import các module đã tách biệt
from ml_engine.config.schema import (
    FEATURE_NAMES,
    LABEL_NAMES,
    DEFAULT_DATASET_SAMPLES,
    DEFAULT_CONTAMINATION_RATE
)
from ml_engine.preprocessing.dataset_generator import generate_synthetic_dataset
from ml_engine.preprocessing.feature_preprocessor import TrafficFeaturePreprocessor
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
    """In danh sach cac thuat toan duoc ho tro kem mo ta."""
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


def train_single_classifier(
    model_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> Tuple[Any, float, float]:
    """Huan luyen va danh gia mot bo phan loai cu the."""
    clf = get_classifier(model_name)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    return clf, acc, macro_f1


def benchmark_all_classifiers(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray
):
    """Huan luyen va so sanh toan bo cac bo phan loai duoc ho tro."""
    print("\n" + "=" * 70)
    print("  SO SANH DOI CHUNG TOAN BO CAC BO PHAN LOAI (BENCHMARK MODE)")
    print("=" * 70)
    print(f"{'Thuat toan':<22} | {'Accuracy':<12} | {'Macro F1':<12} | {'Thoi gian train':<15}")
    print("-" * 70)

    best_name = None
    best_f1 = -1.0
    results = {}

    for name in list_supported_classifiers():
        t0 = time.perf_counter()
        clf, acc, f1 = train_single_classifier(name, X_train, y_train, X_test, y_test)
        elapsed = (time.perf_counter() - t0) * 1000.0
        results[name] = {"acc": acc, "f1": f1, "time_ms": elapsed, "model": clf}
        print(f"{name:<22} | {acc * 100:>8.2f}%    | {f1 * 100:>8.2f}%    | {elapsed:>10.2f} ms")
        if f1 > best_f1:
            best_f1 = f1
            best_name = name

    print("-" * 70)
    print(f" [BEST MODEL ACCURACY]: '{best_name}' (F1: {best_f1 * 100:.2f}%)")
    print("=" * 70 + "\n")
    return results[best_name]["model"], best_name


def run_training_pipeline(
    classifier_type: str = "decision_tree",
    anomaly_type: str = "isolation_forest",
    n_samples: int = DEFAULT_DATASET_SAMPLES,
    export_tinyml: bool = True,
    output_dir: str = None
):
    """Quy trình huấn luyện hoàn chỉnh."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if output_dir is None:
        output_dir = os.path.join(root_dir, "ml_engine", "models")
    dataset_dir = os.path.join(root_dir, "ml_engine", "datasets")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(dataset_dir, exist_ok=True)

    print("=" * 70)
    print("       EDGE AI NETWORK ANOMALY DETECTION - TRAINING PIPELINE")
    print(f"   [Classifier: '{classifier_type}'] | [Anomaly Detector: '{anomaly_type}']")
    print("=" * 70)

    # 1. Sinh tập dữ liệu huấn luyện
    print(f"\n[1/5] Sinh tap du lieu luu luong mang mau ({n_samples:,} mau)...")
    df = generate_synthetic_dataset(n_samples=n_samples, random_state=42)
    csv_path = os.path.join(dataset_dir, "synthetic_traffic_dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"  -> Da luu dataset tai: {csv_path}")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # 2. Tiền xử lý và Chuẩn hóa đặc trưng
    print("\n[2/5] Tien xu ly & Chuan hoa dac trung (TrafficFeaturePreprocessor)...")
    preprocessor = TrafficFeaturePreprocessor()
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    preprocessor.save(scaler_path)
    print(f"  -> Da luu weights scaler tai: {scaler_path}")

    # 3. Huấn luyện bộ phát hiện bất thường Unsupervised / Novelty
    print(f"\n[3/5] Huan luyen bo phat hien bat thuong ('{anomaly_type}')...")
    anomaly_detector = get_anomaly_detector(anomaly_type)
    
    # Chỉ học trên dữ liệu bình thường (y == 0)
    X_normal_train = X_train_scaled[y_train == 0]
    anomaly_detector.fit(X_normal_train)

    test_scores = anomaly_detector.score_samples(X_test_scaled)
    score_min = float(test_scores.min())
    score_max = float(test_scores.max())

    preds_binary = (anomaly_detector.predict(X_test_scaled) == -1).astype(int)
    actual_binary = (y_test != 0).astype(int)
    iso_f1 = float(f1_score(actual_binary, preds_binary, zero_division=0))
    print(f"  -> {anomaly_type} Binary F1-Score: {iso_f1:.4f} (Score Range: [{score_min:.3f}, {score_max:.3f}])")

    # 4. Huấn luyện bộ phân loại dạng tấn công
    print(f"\n[4/5] Huan luyen bo phan loai tan cong ('{classifier_type}')...")
    if classifier_type == "all_compare":
        classifier, active_clf_name = benchmark_all_classifiers(X_train, y_train, X_test, y_test)
    else:
        active_clf_name = classifier_type
        classifier = get_classifier(classifier_type)
        classifier.fit(X_train, y_train)

    y_pred = classifier.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    print(f"  -> {active_clf_name} Accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES))

    # 5. Lưu models và metadata
    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(anomaly_detector, iso_path)
    joblib.dump(classifier, clf_path)

    metadata = {
        "timestamp": int(time.time()),
        "features": FEATURE_NAMES,
        "labels": LABEL_NAMES,
        "classifier_type": active_clf_name,
        "anomaly_detector_type": anomaly_type,
        "classifier_accuracy": acc,
        "anomaly_f1_score": iso_f1,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "can_export_tinyml": getattr(classifier, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"  -> Da luu model classifier: {clf_path}")
    print(f"  -> Da luu anomaly detector: {iso_path}")
    print(f"  -> Da luu metadata: {meta_path}")

    # Xuất mã C TinyML nếu được yêu cầu và mô hình hỗ trợ
    if export_tinyml:
        if getattr(classifier, "can_export_tinyml", False):
            print("\n[5/5] Tu dong xuat TinyML C Header (.h) cho firmware ESP32...")
            h_out = os.path.join(output_dir, "tinyml_model.h")
            export_decision_tree_to_header(classifier, h_out)
            
            firmware_h = os.path.join(root_dir, "firmware", "esp32_probe", "tinyml_model.h")
            if os.path.exists(os.path.dirname(firmware_h)):
                export_decision_tree_to_header(classifier, firmware_h)
            print(f"  -> [OK] Da cap nhat TinyML C Header tai: {h_out}")
        else:
            print(f"\n[5/5] Chu y: Model '{active_clf_name}' khong phai Decision Tree.")
            print("  -> Khong xuat ma nguon C truc tiep. Model se chay o tang Host Inference Service.")

    print("\n" + "=" * 70)
    print(f" [OK] HUAN LUYEN HOAN TAT MY MAN! MODELS DA SAN SANG TAI: {output_dir}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Train Network Anomaly Detection and Attack Classification Models"
    )
    parser.add_argument(
        "--classifier",
        default="decision_tree",
        help="Loai model phan loai tan cong (mac dinh: decision_tree). Ho tro: decision_tree, random_forest, extra_trees, gradient_boosting, mlp, logistic_regression, all_compare"
    )
    parser.add_argument(
        "--anomaly-model",
        default="isolation_forest",
        help="Loai model phat hien bat thuong (mac dinh: isolation_forest). Ho tro: isolation_forest, one_class_svm, elliptic_envelope, lof"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_DATASET_SAMPLES,
        help="So luong mau synthetic du lieu sinh ra (mac dinh: 10,000)"
    )
    parser.add_argument(
        "--export-tinyml",
        action="store_true",
        default=True,
        help="Tu dong sinh C Header tinyml_model.h neu classifier ho tro"
    )
    parser.add_argument(
        "--no-tinyml",
        dest="export_tinyml",
        action="store_false",
        help="Bo qua buoc xuat C Header"
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="Liet ke tat ca cac mo hinh duoc ho tro roi thoat"
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Thu muc luu tru weights (.joblib) va metadata (.json)"
    )

    args = parser.parse_args()

    if args.list_models:
        print_supported_models()
        sys.exit(0)

    run_training_pipeline(
        classifier_type=args.classifier,
        anomaly_type=args.anomaly_model,
        n_samples=args.samples,
        export_tinyml=args.export_tinyml,
        output_dir=args.output_dir
    )


if __name__ == "__main__":
    main()
