#!/usr/bin/env python3
"""
Fair Model Benchmarking Pipeline on Edge-IIoTset
=================================================
Performs a rigorous, fair 5-fold cross-validation and hardware benchmarking
across supported attack classifiers on the Edge-IIoTset dataset.

Methodological guarantees:
1. Strict No-Leakage 5-Fold Stratified CV: Preprocessor (scaling + encoding)
   is fitted strictly on the training partition of each fold.
2. Identical splits: All models evaluate on the exact same folds.
3. Complete metrics: Accuracy (Mean ± Std), Macro F1 (Mean ± Std), Weighted F1.
4. Hardware Profiling:
   - Inference latency per sample (mean ± std across 1,000 single-sample inferences)
   - Inference throughput (samples/sec)
   - CPU time consumed during inference
   - Memory footprint (in-memory RAM via tracemalloc, on-disk model binary size)
   - Edge / ESP32 chip suitability analysis (Flash constants, SRAM overhead, feasibility)
"""

import os
import sys
import time
import json
import gc
import tracemalloc
import tempfile
import warnings
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
import joblib

# Set UTF-8 encoding for standard output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from ml_engine.preprocessing import load_raw_dataset, EdgeTrafficPreprocessor
from ml_engine.algorithms.classifiers import get_classifier, SUPPORTED_CLASSIFIERS


# List of models to benchmark
BENCHMARK_MODELS = [
    {
        "name": "decision_tree",
        "label": "Decision Tree",
        "family": "Tree",
        "edge_ready": True,
        "kwargs": {"max_depth": 16, "min_samples_split": 6, "min_samples_leaf": 2, "random_state": 42}
    },
    {
        "name": "random_forest",
        "label": "Random Forest",
        "family": "Ensemble Tree",
        "edge_ready": True,
        "kwargs": {"n_estimators": 30, "max_depth": 12, "min_samples_split": 6, "min_samples_leaf": 2, "random_state": 42, "n_jobs": -1}
    },
    {
        "name": "extra_trees",
        "label": "Extra Trees",
        "family": "Ensemble Tree",
        "edge_ready": True,
        "kwargs": {"n_estimators": 30, "max_depth": 12, "min_samples_split": 6, "min_samples_leaf": 2, "random_state": 42, "n_jobs": -1}
    },
    {
        "name": "logistic_regression",
        "label": "Logistic Regression",
        "family": "Linear",
        "edge_ready": True,
        "kwargs": {"max_iter": 150, "random_state": 42, "solver": "lbfgs"}
    },
    {
        "name": "xgboost",
        "label": "XGBoost",
        "family": "GBDT",
        "edge_ready": False,
        "kwargs": {"n_estimators": 50, "max_depth": 6, "learning_rate": 0.1, "random_state": 42, "n_jobs": -1}
    },
    {
        "name": "lightgbm",
        "label": "LightGBM",
        "family": "Histogram GBDT",
        "edge_ready": False,
        "kwargs": {"n_estimators": 50, "max_depth": 6, "learning_rate": 0.1, "random_state": 42, "n_jobs": -1, "verbose": -1}
    },
    {
        "name": "catboost",
        "label": "CatBoost",
        "family": "Symmetric GBDT",
        "edge_ready": False,
        "kwargs": {"iterations": 50, "depth": 6, "learning_rate": 0.1, "random_seed": 42, "thread_count": -1, "verbose": False}
    },
    {
        "name": "pytorch_deep",
        "label": "EdgeDeepNet (PyTorch DNN)",
        "family": "Neural Network",
        "edge_ready": True,  # Via TFLite Micro
        "kwargs": {"epochs": 10, "batch_size": 256, "lr": 1e-3, "hidden_dims": (128, 64, 32), "verbose": False, "random_state": 42}
    }
]


def estimate_esp32_footprint(model_obj: Any, model_name: str, n_features: int, n_classes: int) -> Dict[str, Any]:
    """
    Estimates flash binary constant size and SRAM requirements for ESP32 chip
    (Xtensa LX6 @ 240MHz, 520 KB SRAM, 4 MB SPI Flash).
    """
    underlying = getattr(model_obj, "underlying_estimator", getattr(model_obj, "model", model_obj))
    
    # Defaults
    flash_bytes = 0
    sram_bytes = 0
    edge_status = "Host-Only (Requires Python/OS Runtime)"
    
    if model_name == "decision_tree":
        # Node count: left, right, feature, threshold
        tree = underlying.tree_
        nodes = tree.node_count
        # left (int16: 2B) + right (int16: 2B) + feature (int8: 1B) + threshold (double: 8B) = 13 bytes/node
        # Leaf values: classes * float (4B) for leaf nodes
        leaf_count = (nodes + 1) // 2
        flash_bytes = nodes * 13 + leaf_count * n_classes * 4
        sram_bytes = 4096  # Scratch vector + stack traversal
        edge_status = "ESP32 Ready (Pure C Flattened Array)"
    elif model_name in ("random_forest", "extra_trees"):
        total_nodes = 0
        total_leaves = 0
        for est in underlying.estimators_:
            nodes = est.tree_.node_count
            total_nodes += nodes
            total_leaves += (nodes + 1) // 2
        flash_bytes = total_nodes * 13 + total_leaves * n_classes * 4
        sram_bytes = 8192 + (n_classes * 4)  # Scratch vector + leaf accumulation buffer
        if flash_bytes < 1.5 * 1024 * 1024:
            edge_status = "ESP32 Ready (Compact C Tree Ensemble)"
        else:
            edge_status = "ESP32 Limited (>1.5MB Partition Warning)"
    elif model_name == "logistic_regression":
        # Weights matrix: n_classes * n_features * 4 bytes (float32) + intercepts (n_classes * 4 bytes)
        flash_bytes = (n_classes * n_features + n_classes) * 4
        sram_bytes = 2048  # Minimal dot-product buffer
        edge_status = "ESP32 Ready (Ultra-light Linear Model)"
    elif model_name == "pytorch_deep":
        # Weights: (56*128 + 128) + (128*64 + 64) + (64*32 + 32) + (32*15 + 15)
        # Parameters count ~ 18,223 floats * 4 = ~73 KB (or quantized int8 ~18 KB)
        param_count = sum(p.numel() for p in underlying.parameters()) if hasattr(underlying, "parameters") else 18223
        flash_bytes = param_count * 4  # Float32 TFLite FlatBuffer
        sram_bytes = 48 * 1024  # TFLite Micro tensor arena (~48 KB)
        edge_status = "ESP32 Ready (TFLite Micro FlatBuffer)"
    else:
        # GBDT: Host only
        flash_bytes = 0
        sram_bytes = 0
        edge_status = "Host-Only (Incompatible with bare-metal ESP32 C)"

    return {
        "flash_bytes": flash_bytes,
        "flash_kb": round(flash_bytes / 1024, 2),
        "sram_bytes": sram_bytes,
        "sram_kb": round(sram_bytes / 1024, 2),
        "edge_status": edge_status,
        "fits_esp32_sram": (sram_bytes <= 300 * 1024) if sram_bytes > 0 else False,
        "fits_esp32_flash": (flash_bytes <= 2 * 1024 * 1024) if flash_bytes > 0 else False
    }


def run_benchmark():
    print("=" * 85)
    print("      AERO FAIR BENCHMARKING SUITE - EDGE-IIOTSET (5-FOLD STRATIFIED CV)")
    print("=" * 85)
    print("Methodology: Independent fold preprocessing, identical splits, zero data leakage.\n")
    
    # 1. Load Data
    t0 = time.time()
    print("[1/4] Loading Edge-IIoTset benchmark dataset (sample_ratio=0.2000)...")
    raw_X, raw_y = load_raw_dataset(sample_ratio=0.2, invalid_rows="drop")
    total_samples = len(raw_X)
    n_features = raw_X.shape[1]
    classes = sorted(raw_y.unique())
    n_classes = len(classes)
    print(f"      -> Loaded {total_samples:,} records | {n_features} features | {n_classes} classes in {time.time()-t0:.2f}s")
    print(f"      -> Class distribution (min={raw_y.value_counts().min()}, max={raw_y.value_counts().max()})")
    
    # 2. Setup 5-Fold Stratified CV
    n_splits = 5
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    folds = list(skf.split(raw_X, raw_y))
    print(f"[2/4] Initialized {n_splits}-Fold Stratified Cross Validation with random_state=42\n")

    results = []

    # 3. Benchmark Each Model
    for m_idx, m_cfg in enumerate(BENCHMARK_MODELS, 1):
        m_name = m_cfg["name"]
        m_label = m_cfg["label"]
        m_kwargs = m_cfg["kwargs"]
        
        print(f"[{m_idx}/{len(BENCHMARK_MODELS)}] Evaluating '{m_label}' ({m_cfg['family']})...")
        
        fold_accs = []
        fold_macro_f1s = []
        fold_weighted_f1s = []
        fold_fit_times = []
        
        for fold_idx, (tr_idx, val_idx) in enumerate(folds, 1):
            t_f0 = time.time()
            
            # Independent fold preprocessing
            prep = EdgeTrafficPreprocessor(feature_names=list(raw_X.columns))
            prep.fit(raw_X.iloc[tr_idx], raw_y.iloc[tr_idx])
            
            X_tr = prep.transform(raw_X.iloc[tr_idx])
            y_tr = prep.label_encoder.transform(raw_y.iloc[tr_idx])
            X_val = prep.transform(raw_X.iloc[val_idx])
            y_val = prep.label_encoder.transform(raw_y.iloc[val_idx])
            
            # Model instantiation & fit
            clf = get_classifier(m_name, **m_kwargs)
            clf.fit(X_tr, y_tr)
            fit_duration = time.time() - t_f0
            fold_fit_times.append(fit_duration)
            
            # Evaluation
            preds = clf.predict(X_val)
            acc = accuracy_score(y_val, preds)
            m_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
            w_f1 = f1_score(y_val, preds, average="weighted", zero_division=0)
            
            fold_accs.append(acc)
            fold_macro_f1s.append(m_f1)
            fold_weighted_f1s.append(w_f1)
            
            print(f"      Fold {fold_idx}: Acc={acc*100:.2f}%, Macro F1={m_f1*100:.2f}%, Fit={fit_duration:.2f}s", flush=True)

        mean_acc = float(np.mean(fold_accs))
        std_acc = float(np.std(fold_accs))
        mean_macro_f1 = float(np.mean(fold_macro_f1s))
        std_macro_f1 = float(np.std(fold_macro_f1s))
        mean_weighted_f1 = float(np.mean(fold_weighted_f1s))
        std_weighted_f1 = float(np.std(fold_weighted_f1s))
        mean_fit_time = float(np.mean(fold_fit_times))
        
        print(f"   -> Result: Acc = {mean_acc*100:.2f}% ± {std_acc*100:.2f}% | Macro F1 = {mean_macro_f1*100:.2f}% ± {std_macro_f1*100:.2f}%")
        
        # 4. Measure Inference Latency, CPU, and Memory on Final Trained Model
        print(f"   -> Profiling hardware inference performance (latency, CPU, memory)...")
        
        # Representative sample for single-sample inference
        test_sample_1 = X_val[0:1]  # shape (1, 56)
        test_batch_100 = X_val[0:100]  # shape (100, 56)
        
        # Warmup
        for _ in range(50):
            _ = clf.predict(test_sample_1)
        
        # Measure single-sample inference latency across 1,000 runs
        n_infer_runs = 1000
        latencies_us = []
        cpu_time_start = time.process_time()
        wall_time_start = time.perf_counter()
        
        for _ in range(n_infer_runs):
            t_s = time.perf_counter_ns()
            _ = clf.predict(test_sample_1)
            latencies_us.append((time.perf_counter_ns() - t_s) / 1000.0)  # microseconds
            
        wall_time_total = time.perf_counter() - wall_time_start
        cpu_time_total = time.process_time() - cpu_time_start
        
        mean_latency_us = float(np.mean(latencies_us))
        std_latency_us = float(np.std(latencies_us))
        mean_latency_ms = mean_latency_us / 1000.0
        throughput_samples_sec = float(n_infer_runs / wall_time_total) if wall_time_total > 0 else 0.0
        cpu_time_per_sample_us = float((cpu_time_total / n_infer_runs) * 1e6)
        
        # Measure RAM allocation during prediction using tracemalloc
        gc.collect()
        tracemalloc.start()
        _ = clf.predict(test_batch_100)
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        infer_ram_kb = round(peak_mem / 1024.0, 2)
        
        # Measure model serialized size on disk
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp_f:
            tmp_path = tmp_f.name
        joblib.dump(clf, tmp_path)
        model_disk_bytes = os.path.getsize(tmp_path)
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        model_disk_kb = round(model_disk_bytes / 1024.0, 2)
        
        # ESP32 footprint estimation
        esp32_info = estimate_esp32_footprint(clf, m_name, n_features, n_classes)
        
        results.append({
            "model_name": m_name,
            "label": m_label,
            "family": m_cfg["family"],
            "edge_ready": m_cfg["edge_ready"],
            "accuracy_mean": mean_acc,
            "accuracy_std": std_acc,
            "macro_f1_mean": mean_macro_f1,
            "macro_f1_std": std_macro_f1,
            "weighted_f1_mean": mean_weighted_f1,
            "weighted_f1_std": std_weighted_f1,
            "fold_accuracies": fold_accs,
            "fold_macro_f1s": fold_macro_f1s,
            "mean_fit_time_sec": round(mean_fit_time, 2),
            "latency_us": round(mean_latency_us, 2),
            "latency_us_std": round(std_latency_us, 2),
            "latency_ms": round(mean_latency_ms, 4),
            "throughput_sps": round(throughput_samples_sec, 1),
            "cpu_time_sample_us": round(cpu_time_per_sample_us, 2),
            "infer_ram_kb": infer_ram_kb,
            "model_disk_kb": model_disk_kb,
            "esp32_flash_kb": esp32_info["flash_kb"],
            "esp32_sram_kb": esp32_info["sram_kb"],
            "esp32_status": esp32_info["edge_status"]
        })
        
        # Incremental save to JSON
        output_path = os.path.join(ROOT_DIR, "scratch", "fair_benchmark_results.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            
        print(f"      Latency: {mean_latency_us:.1f} ± {std_latency_us:.1f} µs | Throughput: {throughput_samples_sec:,.0f} samples/s | Disk: {model_disk_kb} KB\n")

    print(f"\n[Artifact] Saved complete JSON benchmark metrics to: {output_path}")

    # Print Clean Formatted Summary Tables
    print("\n" + "=" * 125)
    print("                    BẢNG BENCHMARKING HIỆU NĂNG PHÂN LOẠI (5-FOLD STRATIFIED CV TRÊN EDGE-IIOTSET)")
    print("=" * 125)
    print(f"{'Mô hình (Model)':<25} | {'Kiến trúc':<16} | {'Accuracy (Mean ± Std)':<23} | {'Macro F1 (Mean ± Std)':<23} | {'Weighted F1':<14} | {'Thời gian fit (TB)':<15}")
    print("-" * 125)
    for r in results:
        acc_str = f"{r['accuracy_mean']*100:.2f}% ± {r['accuracy_std']*100:.2f}%"
        f1_str = f"{r['macro_f1_mean']*100:.2f}% ± {r['macro_f1_std']*100:.2f}%"
        w_str = f"{r['weighted_f1_mean']*100:.2f}%"
        fit_str = f"{r['mean_fit_time_sec']:.2f}s"
        print(f"{r['label']:<25} | {r['family']:<16} | {acc_str:<23} | {f1_str:<23} | {w_str:<14} | {fit_str:<15}")
    print("=" * 125)

    print("\n" + "=" * 135)
    print("                    BẢNG ĐỐI CHIẾU PHẦN CỨNG: THỜI GIAN SUY LUẬN, CPU & BỘ NHỚ TIÊU THỤ (HOST VS ESP32 CHIP)")
    print("=" * 135)
    print(f"{'Mô hình (Model)':<25} | {'Inference Latency':<18} | {'Throughput':<15} | {'CPU Time/sample':<16} | {'Model Disk':<12} | {'ESP32 Flash':<13} | {'Khả năng chạy trên Chip Biên':<30}")
    print("-" * 135)
    for r in results:
        lat_str = f"{r['latency_us']:.1f} µs ({r['latency_ms']:.3f} ms)"
        th_str = f"{r['throughput_sps']:,.0f} smp/s"
        cpu_str = f"{r['cpu_time_sample_us']:.1f} µs"
        disk_str = f"{r['model_disk_kb']:,.1f} KB"
        flash_str = f"{r['esp32_flash_kb']:,.1f} KB" if r['esp32_flash_kb'] > 0 else "N/A (Host)"
        print(f"{r['label']:<25} | {lat_str:<18} | {th_str:<15} | {cpu_str:<16} | {disk_str:<12} | {flash_str:<13} | {r['esp32_status']:<30}")
    print("=" * 135)

    return results


if __name__ == "__main__":
    run_benchmark()
