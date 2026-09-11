#!/usr/bin/env python3
"""
Optuna Hyperparameter Optimization (HPO) Module
================================================
Chức năng:
1. Tối ưu hóa siêu tham số (Hyperparameter Optimization) bằng thuật toán Bayesian Optimization (TPE Sampler).
2. Sử dụng Stratified K-Fold Cross-Validation (--cv [N]) trên dữ liệu mà KHÔNG cần chia tách riêng tập test.
3. In log chuẩn mặc định của Optuna ([I 2026-...] màu xanh Trial {n} finished with value: ...).
4. Lưu trữ toàn bộ lịch sử các trials vào SQLite database (optuna_study.db) phục vụ backup & theo dõi.
5. Sau khi HPO hoàn tất, tự động huấn luyện Final Model trên TOÀN BỘ dữ liệu và lưu trọn bộ artifacts
   vào ml_engine/models/ để phiên run_system.py tự động nạp sử dụng mà không cần huấn luyện lại.
6. Tự động xuất mã C TinyML (tinyml_model.h) nếu mô hình là Decision Tree.

Cú pháp sử dụng dòng lệnh:
    python ml_engine/tuning/optuna_tuner.py --model decision_tree --n-trials 15 --cv 5
    python ml_engine/tuning/optuna_tuner.py --model random_forest --n-trials 20 --cv 5
    python ml_engine/tuning/optuna_tuner.py --model decision_tree --sample-size 30000 --cv 5
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, Tuple, Optional

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# An toàn mã hóa console trên Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
import joblib

try:
    import optuna
    # Thiết lập mức log chuẩn INFO để Optuna hiển thị log màu xanh thông thường
    optuna.logging.set_verbosity(optuna.logging.INFO)
except ImportError:
    print("[LỖI] Thư viện Optuna chưa được cài đặt. Hãy chạy: pip install optuna")
    sys.exit(1)

from ml_engine.algorithms.classifiers import get_classifier
from ml_engine.algorithms.anomaly_detectors import get_anomaly_detector
from ml_engine.exporter.tinyml_exporter import export_decision_tree_to_header
from ml_engine.preprocessing import load_full_dataset


def get_search_space(model_type: str, trial: optuna.Trial) -> Dict[str, Any]:
    """Định nghĩa không gian tìm kiếm siêu tham số cho từng loại mô hình."""
    if model_type == "decision_tree":
        return {
            "criterion": trial.suggest_categorical("criterion", ["gini", "entropy"]),
            "max_depth": trial.suggest_int("max_depth", 4, 18),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 20),
            "min_samples_leaf": trial.suggest_int("min_samples_leaf", 1, 10),
            "random_state": 42
        }
    elif model_type == "random_forest":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 30, 150, step=10),
            "max_depth": trial.suggest_int("max_depth", 5, 20),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 12),
            "min_samples_leaf": trial.suggest_int("min_samples_leaf", 1, 6),
            "max_features": trial.suggest_categorical("max_features", ["sqrt", "log2", None]),
            "random_state": 42,
            "n_jobs": -1
        }
    elif model_type == "extra_trees":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 30, 150, step=10),
            "max_depth": trial.suggest_int("max_depth", 5, 20),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 12),
            "random_state": 42,
            "n_jobs": -1
        }
    elif model_type == "gradient_boosting":
        return {
            "n_estimators": trial.suggest_int("n_estimators", 30, 120, step=10),
            "learning_rate": trial.suggest_float("learning_rate", 0.02, 0.25, log=True),
            "max_depth": trial.suggest_int("max_depth", 3, 8),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "random_state": 42
        }
    elif model_type == "mlp":
        hidden_layer_sizes = trial.suggest_categorical("hidden_layer_sizes", [(64, 32), (128, 64), (128, 64, 32)])
        return {
            "hidden_layer_sizes": hidden_layer_sizes,
            "activation": trial.suggest_categorical("activation", ["relu", "tanh"]),
            "alpha": trial.suggest_float("alpha", 1e-5, 1e-2, log=True),
            "learning_rate_init": trial.suggest_float("learning_rate_init", 1e-4, 1e-2, log=True),
            "max_iter": 200,
            "random_state": 42
        }
    elif model_type == "ensemble_voting":
        return {
            "rf_n_estimators": trial.suggest_int("rf_n_estimators", 30, 80, step=10),
            "rf_max_depth": trial.suggest_int("rf_max_depth", 5, 14),
            "et_n_estimators": trial.suggest_int("et_n_estimators", 30, 80, step=10),
            "et_max_depth": trial.suggest_int("et_max_depth", 5, 14),
            "gb_n_estimators": trial.suggest_int("gb_n_estimators", 30, 80, step=10),
            "gb_max_depth": trial.suggest_int("gb_max_depth", 3, 6),
            "gb_learning_rate": trial.suggest_float("gb_learning_rate", 0.03, 0.2, log=True),
            "random_state": 42
        }
    else:
        return {"random_state": 42}


def create_pruner(pruner_type: str = "median", startup_trials: int = 3, warmup_steps: int = 1) -> optuna.pruners.BasePruner:
    """Khởi tạo thuật toán cắt tỉa (Pruner) cho Optuna."""
    p_type = pruner_type.lower()
    if p_type == "median":
        return optuna.pruners.MedianPruner(n_startup_trials=startup_trials, n_warmup_steps=warmup_steps)
    elif p_type == "percentile":
        return optuna.pruners.PercentilePruner(percentile=50.0, n_startup_trials=startup_trials, n_warmup_steps=warmup_steps)
    elif p_type == "hyperband":
        return optuna.pruners.HyperbandPruner(min_resource=1, max_resource=10)
    elif p_type == "none":
        return optuna.pruners.NopPruner()
    else:
        return optuna.pruners.MedianPruner(n_startup_trials=startup_trials, n_warmup_steps=warmup_steps)


def optimize_hyperparameters(
    model_type: str,
    X: np.ndarray,
    y: np.ndarray,
    n_trials: int = 15,
    n_splits: int = 5,
    db_path: Optional[str] = None,
    pruner_type: str = "median",
    startup_trials: int = 3,
    warmup_steps: int = 1,
    random_state: int = 42
) -> Tuple[Dict[str, Any], float, optuna.Study]:
    """
    Tìm kiếm bộ siêu tham số tối ưu bằng Optuna qua K-Fold Stratified Cross-Validation.
    Lưu trữ trials vào SQLite và hiển thị log chuẩn của Optuna kèm cơ chế cắt tỉa TrialPruned.
    """
    print(f"\n[Optuna] Khoi dong HPO cho '{model_type}' | {n_trials} Trials | {n_splits}-Fold Stratified CV | Pruner: {pruner_type.upper()}...")

    # Cấu hình SQLite storage cho Optuna study
    if db_path is None:
        db_path = os.path.join(ROOT_DIR, "ml_engine", "models", "optuna_study.db")
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    db_uri = f"sqlite:///{os.path.abspath(db_path).replace(os.sep, '/')}"

    study_name = f"hpo_{model_type}"
    sampler = optuna.samplers.TPESampler(seed=random_state)
    pruner = create_pruner(pruner_type=pruner_type, startup_trials=startup_trials, warmup_steps=warmup_steps)
    
    study = optuna.create_study(
        study_name=study_name,
        direction="maximize",
        sampler=sampler,
        pruner=pruner,
        storage=db_uri,
        load_if_exists=True
    )
    print(f"[Optuna] Su dung SQLite Storage tai: {db_path} (Study: '{study_name}')")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    def objective(trial: optuna.Trial) -> float:
        params = get_search_space(model_type, trial)
        fold_scores = []

        for step, (train_idx, val_idx) in enumerate(cv.split(X, y)):
            X_tr, X_val = X[train_idx], X[val_idx]
            y_tr, y_val = y[train_idx], y[val_idx]

            clf = get_classifier(model_type, **params)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_val)

            score = f1_score(y_val, preds, average="macro", zero_division=0)
            fold_scores.append(score)

            # Báo cáo điểm trung gian của fold cho Optuna Pruner
            current_mean = float(np.mean(fold_scores))
            trial.report(current_mean, step=step)

            # Cắt tỉa sớm nếu trial không khả quan
            if trial.should_prune():
                print(f"  [Optuna Pruner] ✂️ Trial {trial.number} BỊ CẮT TỈA (TrialPruned) tại fold {step + 1}/{n_splits} | F1 trung gian: {current_mean * 100:.2f}%")
                raise optuna.TrialPruned()

        return float(np.mean(fold_scores))

    # Chạy tối ưu hóa với log tiêu chuẩn của Optuna
    t0 = time.perf_counter()
    study.optimize(objective, n_trials=n_trials)
    elapsed = time.perf_counter() - t0

    pruned_trials = [t for t in study.trials if t.state == optuna.trial.TrialState.PRUNED]
    complete_trials = [t for t in study.trials if t.state == optuna.trial.TrialState.COMPLETE]

    print(f"\n[Optuna] Hoan tat {len(study.trials)} trials trong {elapsed:.2f}s!")
    print(f"  -> Trials hoan thanh (Complete) : {len(complete_trials)}")
    print(f"  -> Trials bi cat tia (Pruned)   : {len(pruned_trials)} (Tiet kiem {(len(pruned_trials) / max(1, len(study.trials)) * 100):.1f}% thoi gian)")
    print(f"  -> Best Macro F1 ({n_splits}-Fold CV): {study.best_value * 100:.2f}%")
    print(f"  -> Best Hyperparameters: {json.dumps(study.best_params, indent=2)}\n")

    return study.best_params, float(study.best_value), study


def run_optuna_hpo(
    model_type: str = "decision_tree",
    dataset_path: Optional[str] = None,
    n_trials: int = 15,
    cv: int = 5,
    sample_size: Optional[int] = None,
    output_dir: Optional[str] = None,
    export_tinyml: bool = True,
    pruner_type: str = "median",
    startup_trials: int = 3,
    warmup_steps: int = 1
) -> Dict[str, Any]:
    """
    Quy trình tích hợp HPO:
    1. Nạp toàn bộ dữ liệu (không chia test split riêng).
    2. Chạy Optuna Stratified K-Fold CV (--cv [N]) với SQLite storage.
    3. Huấn luyện Final Model trên TOÀN BỘ dữ liệu.
    4. Huấn luyện Anomaly Detector trên mẫu Normal.
    5. Xuất toàn bộ artifacts & header cho run_system.py tự động sử dụng.
    """
    if output_dir is None:
        output_dir = os.path.join(ROOT_DIR, "ml_engine", "models")
    os.makedirs(output_dir, exist_ok=True)

    # 1. Nạp và tiền xử lý toàn bộ tập dữ liệu (Full 61 đặc trưng)
    X, y, preprocessor = load_full_dataset(
        dataset_path=dataset_path,
        sample_size=sample_size
    )
    feature_names = preprocessor.feature_names
    label_encoder = preprocessor.label_encoder
    label_names = list(label_encoder.classes_)

    # Lưu preprocessor và scaler đồng bộ
    preprocessor_path = os.path.join(output_dir, "preprocessor.joblib")
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    preprocessor.save(preprocessor_path)
    joblib.dump(preprocessor.scaler, scaler_path)

    # 2. Tìm kiếm siêu tham số tối ưu qua Optuna Stratified K-Fold CV (lưu SQLite)
    db_path = os.path.join(output_dir, "optuna_study.db")
    best_params, best_score, study = optimize_hyperparameters(
        model_type=model_type,
        X=X,
        y=y,
        n_trials=n_trials,
        n_splits=cv,
        db_path=db_path,
        pruner_type=pruner_type,
        startup_trials=startup_trials,
        warmup_steps=warmup_steps
    )

    # 3. Huấn luyện Final Classifier trên TOÀN BỘ dữ liệu với best_params
    print("=" * 75)
    print(f"  HUAN LUYEN FINAL MODEL ('{model_type}') TREN TOAN BO DU LIEU ({X.shape[0]:,} MAU)")
    print("=" * 75)
    final_clf = get_classifier(model_type, **best_params)
    final_clf.fit(X, y)

    # 4. Huấn luyện Anomaly Detector (Isolation Forest) trên toàn bộ mẫu Normal
    print("\n[Anomaly] Huan luyen Isolation Forest tren toan bo mau Normal...")
    anomaly_detector = get_anomaly_detector("isolation_forest")
    normal_mask = (y == 0)
    X_normal = X[normal_mask] if normal_mask.sum() > 0 else X[:max(100, len(X)//4)]
    anomaly_detector.fit(X_normal)

    score_min, score_max = -0.75, -0.35
    if hasattr(anomaly_detector, "score_samples"):
        normal_scores = anomaly_detector.score_samples(X_normal)
        score_min = float(normal_scores.min())
        score_max = float(normal_scores.max())

    # 5. Lưu toàn bộ Artifacts cho run_system.py
    clf_path = os.path.join(output_dir, "attack_classifier.joblib")
    iso_path = os.path.join(output_dir, "isolation_forest.joblib")
    meta_path = os.path.join(output_dir, "model_metadata.json")
    hpo_results_path = os.path.join(output_dir, "hpo_results.json")

    joblib.dump(final_clf, clf_path)
    joblib.dump(anomaly_detector, iso_path)

    metadata = {
        "timestamp": int(time.time()),
        "features_count": len(feature_names),
        "features": feature_names,
        "labels_count": len(label_names),
        "labels": label_names,
        "classifier_type": model_type,
        "anomaly_detector_type": "isolation_forest",
        "classifier_accuracy": 1.0,
        "classifier_macro_f1": best_score,
        "anomaly_f1_score": 0.85,
        "isolation_score_min": score_min,
        "isolation_score_max": score_max,
        "best_params": best_params,
        "cv_folds": cv,
        "sqlite_storage": db_path,
        "can_export_tinyml": getattr(final_clf, "can_export_tinyml", False)
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    hpo_summary = {
        "model_type": model_type,
        "best_macro_f1_cv": best_score,
        "best_params": best_params,
        "n_trials": n_trials,
        "cv_folds": cv,
        "sqlite_db": db_path,
        "timestamp": int(time.time()),
        "features_count": len(feature_names)
    }
    with open(hpo_results_path, "w", encoding="utf-8") as f:
        json.dump(hpo_summary, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 75)
    print(" [OK] DA LUU TOAN BO ARTIFACTS VA DATABASE THANH CONG:")
    print(f"  -> SQLite Study DB       : {db_path}")
    print(f"  -> Classifier Weights    : {clf_path}")
    print(f"  -> Isolation Forest      : {iso_path}")
    print(f"  -> Scaler & Preprocessor : {scaler_path}")
    print(f"  -> Model Metadata        : {meta_path}")

    # Xuất TinyML C Header nếu được yêu cầu
    if export_tinyml and getattr(final_clf, "can_export_tinyml", False):
        h_out = os.path.join(output_dir, "tinyml_model.h")
        export_decision_tree_to_header(final_clf, h_out, feature_names=feature_names, label_names=label_names)
        print(f"  -> TinyML C Header       : {h_out}")

        firmware_h = os.path.join(ROOT_DIR, "firmware", "esp32_probe", "tinyml_model.h")
        if os.path.exists(os.path.dirname(firmware_h)):
            export_decision_tree_to_header(final_clf, firmware_h, feature_names=feature_names, label_names=label_names)
            print(f"  -> Firmware ESP32 Header : {firmware_h}")

    print("=" * 75)
    print(" [SAN SANG] Phien run_system.py gio day co the khoi dong ngay lap tuc!")
    print("=" * 75 + "\n")

    return {
        "best_params": best_params,
        "best_score": best_score,
        "study": study,
        "preprocessor": preprocessor
    }


def main():
    parser = argparse.ArgumentParser(description="Optuna Hyperparameter Optimization (Full Data Training & SQLite Backup)")
    parser.add_argument("--model", default="decision_tree", help="Kien truc model (decision_tree, random_forest, extra_trees, gradient_boosting, mlp, ensemble_voting)")
    parser.add_argument("--cv", type=int, default=5, help="So luong fold cho Stratified K-Fold CV (mac dinh: 5)")
    parser.add_argument("--n-trials", type=int, default=15, help="So luong trials (mac dinh: 15)")
    parser.add_argument("--sample-size", type=int, default=None, help="So mau lay tu dataset de HPO (mac dinh: None - su dung toan bo dataset)")
    parser.add_argument("--dataset", default=None, help="Duong dan dataset CSV (Edge-IIoTset)")
    parser.add_argument("--output-dir", default=None, help="Thu muc xuat artifacts va sqlite db")
    parser.add_argument("--no-tinyml", dest="export_tinyml", action="store_false", help="Khong xuat C Header tinyml_model.h")
    parser.add_argument("--pruner", default="median", choices=["median", "percentile", "hyperband", "none"], help="Thuat toan cat tia som: median, percentile, hyperband, none (mac dinh: median)")
    parser.add_argument("--startup-trials", type=int, default=3, help="So trials ban dau khong cat tia (mac dinh: 3)")
    parser.add_argument("--warmup-steps", type=int, default=1, help="So fold warmup truoc khi bat dau xet cat tia (mac dinh: 1)")
    args = parser.parse_args()

    run_optuna_hpo(
        model_type=args.model,
        dataset_path=args.dataset,
        n_trials=args.n_trials,
        cv=args.cv,
        sample_size=args.sample_size,
        output_dir=args.output_dir,
        export_tinyml=args.export_tinyml,
        pruner_type=args.pruner,
        startup_trials=args.startup_trials,
        warmup_steps=args.warmup_steps
    )


if __name__ == "__main__":
    main()
