"""
Optuna Hyperparameter Optimization (HPO) Library Module
========================================================
Chỉ dẫn module:
- Module này thuần túy đóng vai trò là thư viện tiện ích (utility / library module) cho HPO:
  1. Định nghĩa không gian tìm kiếm siêu tham số (Search Space) cho từng kiến trúc học máy.
  2. Khởi tạo thuật toán cắt tỉa sớm (Pruners: Median, Percentile, Hyperband).
  3. Cung cấp hàm tối ưu hóa Bayesian Optimization (TPE Sampler) qua Stratified K-Fold Cross-Validation.
  4. Lưu trữ persistent study vào SQLite database (optuna_study.db) phục vụ backup & theo dõi.
  5. Hiển thị log chuẩn mặc định của Optuna ([I 2026-...] Trial {n} finished with value...).
- Entry Point chính duy nhất để chạy thử nghiệm và huấn luyện là `ml_engine/train.py`.
"""

import os
import sys
import json
import time
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

try:
    import optuna
    # Thiết lập mức log chuẩn INFO để Optuna hiển thị log màu xanh thông thường
    optuna.logging.set_verbosity(optuna.logging.INFO)
except ImportError:
    print("[LỖI] Thư viện Optuna chưa được cài đặt. Hãy chạy: pip install optuna")
    sys.exit(1)

from ml_engine.algorithms.classifiers import get_classifier


def get_search_space(model_type: str, trial: optuna.Trial) -> Dict[str, Any]:
    """
    Định nghĩa không gian tìm kiếm siêu tham số (Search Space) cho từng loại mô hình.
    """
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
    """
    Khởi tạo thuật toán cắt tỉa (Pruner) cho Optuna nhằm tiết kiệm tài nguyên tính toán.
    """
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
    Lưu trữ trials vào SQLite database và hiển thị log chuẩn màu xanh của Optuna.

    Parameters:
    -----------
    model_type : str
        Tên kiến trúc mô hình (decision_tree, random_forest, v.v.).
    X : np.ndarray
        Ma trận đặc trưng số (full 61 đặc trưng).
    y : np.ndarray
        Vector nhãn số nguyên.
    n_trials : int
        Số lượng trial thử nghiệm của Optuna.
    n_splits : int
        Số fold cho Stratified K-Fold CV (--cv [N]).
    db_path : str, optional
        Đường dẫn đến file SQLite database lưu study.
    pruner_type : str
        Thuật toán cắt tỉa: median, percentile, hyperband, none.
    startup_trials : int
        Số trial khởi động không bị cắt tỉa.
    warmup_steps : int
        Số fold tối thiểu trước khi xét cắt tỉa.
    random_state : int
        Hạt giống ngẫu nhiên.

    Returns:
    --------
    Tuple: (best_params, best_macro_f1, study)
    """
    print(f"\n[Optuna HPO] Khoi dong HPO cho '{model_type}' | {n_trials} Trials | {n_splits}-Fold Stratified CV | Pruner: {pruner_type.upper()}")

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
    print(f"[Optuna HPO] Su dung SQLite Storage tai: {db_path} (Study: '{study_name}')")

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
                print(f"  [Optuna Pruner] ✂️ Trial {trial.number} BI CAT TIA (TrialPruned) tai fold {step + 1}/{n_splits} | F1 trung gian: {current_mean * 100:.2f}%")
                raise optuna.TrialPruned()

        return float(np.mean(fold_scores))

    # Chạy tối ưu hóa với log tiêu chuẩn của Optuna
    t0 = time.perf_counter()
    study.optimize(objective, n_trials=n_trials)
    elapsed = time.perf_counter() - t0

    pruned_trials = [t for t in study.trials if t.state == optuna.trial.TrialState.PRUNED]
    complete_trials = [t for t in study.trials if t.state == optuna.trial.TrialState.COMPLETE]

    print(f"\n[Optuna HPO] Hoan tat {len(study.trials)} trials trong {elapsed:.2f}s!")
    print(f"  -> Trials hoan thanh (Complete) : {len(complete_trials)}")
    print(f"  -> Trials bi cat tia (Pruned)   : {len(pruned_trials)} (Tiet kiem {(len(pruned_trials) / max(1, len(study.trials)) * 100):.1f}% thoi gian)")
    print(f"  -> Best Macro F1 ({n_splits}-Fold CV): {study.best_value * 100:.2f}%")
    print(f"  -> Best Hyperparameters: {json.dumps(study.best_params, indent=2)}\n")

    return study.best_params, float(study.best_value), study
