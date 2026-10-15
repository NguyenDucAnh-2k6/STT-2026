#!/usr/bin/env python3
"""
Train WGAN-GP for Adversarial Attack Traffic Generation
======================================================
Kịch bản huấn luyện mạng đối kháng Wasserstein GAN (WGAN-GP) để sinh lưu lượng tấn công lẩn tránh IDS:
- Nạp dữ liệu (Sliding Window hoặc Edge-IIoTset).
- Tách phân phối lưu lượng sạch (Benign Baseline) và lưu lượng tấn công gốc (Malicious Seeds).
- Tối ưu hóa WGAN-GP với ràng buộc bảo toàn chức năng giao thức mạng.
- Xuất mô hình và đánh giá trực tiếp tỷ lệ lẩn tránh (Evasion Rate).
"""

import os
import sys
import argparse
import json
import time
from typing import Tuple, Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

# Thêm đường dẫn gốc dự án vào sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    import torch
    from torch.utils.data import TensorDataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ml_engine.config.schema import SLIDING_WINDOW_FEATURES, EDGE_IIOTSET_FEATURES
from ml_engine.adversarial.wgan_adversarial import (
    WGANAdversarialTrainer,
    FunctionalFeatureConstraints
)
from ml_engine.adversarial.evaluator import AdversarialEvaluator


def load_sliding_window_data(csv_path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """Nạp tập dữ liệu dạng Sliding Window (8 features)."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Không tìm thấy file dataset: {csv_path}")

    df = pd.read_csv(csv_path)
    feature_cols = [c for c in SLIDING_WINDOW_FEATURES if c in df.columns]

    benign_df = df[df["label"] == 0]
    attack_df = df[df["label"] != 0]

    X_benign = benign_df[feature_cols].values.astype(np.float32)
    X_attack = attack_df[feature_cols].values.astype(np.float32)
    y_attack = attack_df["label"].values.astype(np.int64)

    return X_benign, X_attack, y_attack, feature_cols


def load_target_ids(models_dir: str):
    """Nạp các mô hình IDS hiện có để kiểm thử đối kháng."""
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    clf_path = os.path.join(models_dir, "attack_classifier.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")

    iso_model = joblib.load(iso_path) if os.path.exists(iso_path) else None
    clf_model = joblib.load(clf_path) if os.path.exists(clf_path) else None
    scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None

    return iso_model, clf_model, scaler


def train_wgan(
    X_benign: np.ndarray,
    X_attack: np.ndarray,
    feature_names: List[str],
    epochs: int = 30,
    batch_size: int = 64,
    lr: float = 0.0002,
    latent_dim: int = 16,
    n_critic: int = 4,
    output_dir: str = "ml_engine/models/adversarial_wgan",
    target_models_dir: Optional[str] = None
):
    """Quy trình huấn luyện WGAN-GP đối kháng."""
    if not TORCH_AVAILABLE:
        print("[Lỗi] PyTorch chưa được cài đặt. Không thể huấn luyện WGAN.")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("      HUẤN LUYỆN MÔ HÌNH ĐỐI KHÁNG WGAN-GP SINH LƯU LƯỢNG LẨN TRÁNH      ")
    print("=" * 70)
    print(f"[*] Số lượng mẫu Benign sạch:     {len(X_benign)}")
    print(f"[*] Số lượng mẫu Tấn công gốc:    {len(X_attack)}")
    print(f"[*] Số đặc trưng đầu vào:         {len(feature_names)}")
    print(f"[*] Cấu hình: Epochs={epochs}, BatchSize={batch_size}, LR={lr}, LatentDim={latent_dim}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[*] Thiết bị tính toán:           {device.upper()}")

    # Chuẩn hóa min-max cục bộ cho quá trình train GAN
    feat_min = np.min(X_benign, axis=0)
    feat_max = np.max(X_benign, axis=0)
    feat_range = np.where((feat_max - feat_min) == 0, 1.0, feat_max - feat_min)

    X_benign_norm = (X_benign - feat_min) / feat_range
    X_attack_norm = (X_attack - feat_min) / feat_range

    # Khởi tạo DataLoader
    benign_tensor = torch.tensor(X_benign_norm, dtype=torch.float32)
    attack_tensor = torch.tensor(X_attack_norm, dtype=torch.float32)

    benign_loader = DataLoader(TensorDataset(benign_tensor), batch_size=batch_size, shuffle=True, drop_last=True)
    attack_loader = DataLoader(TensorDataset(attack_tensor), batch_size=batch_size, shuffle=True, drop_last=True)

    # Khởi tạo WGAN Trainer và Functional Constraints
    feature_dim = len(feature_names)
    trainer = WGANAdversarialTrainer(
        feature_dim=feature_dim,
        latent_dim=latent_dim,
        lr=lr,
        device=device
    )
    constraints = FunctionalFeatureConstraints(feature_names)

    # Nạp target models để đánh giá
    iso_model, clf_model, scaler = None, None, None
    if target_models_dir and os.path.exists(target_models_dir):
        iso_model, clf_model, scaler = load_target_ids(target_models_dir)

    print("\n[*] Bắt đầu vòng lặp tối ưu hóa WGAN-GP...")
    start_time = time.time()

    for epoch in range(1, epochs + 1):
        c_losses = []
        g_losses = []

        attack_iter = iter(attack_loader)

        for b_batch in benign_loader:
            x_b = b_batch[0].to(trainer.device)

            try:
                x_a = next(attack_iter)[0].to(trainer.device)
            except StopIteration:
                attack_iter = iter(attack_loader)
                x_a = next(attack_iter)[0].to(trainer.device)

            # 1. Tối ưu hóa Critic (n_critic bước)
            loss_c = trainer.train_step_critic(x_b, x_a)
            c_losses.append(loss_c)

            # 2. Tối ưu hóa Generator (1 bước)
            loss_g, _ = trainer.train_step_generator(x_a)
            g_losses.append(loss_g)

        avg_c = np.mean(c_losses)
        avg_g = np.mean(g_losses)

        if epoch % 5 == 0 or epoch == epochs:
            print(f"  [Epoch {epoch:02d}/{epochs:02d}] Loss Critic: {avg_c:.4f} | Loss Generator: {avg_g:.4f}")

    elapsed = time.time() - start_time
    print(f"\n[+] Huấn luyện WGAN hoàn tất trong {elapsed:.2f}s!")

    # Lưu trọng số mô hình
    os.makedirs(output_dir, exist_ok=True)
    trainer.save_weights(output_dir)

    # Lưu metadata cấu hình
    config_data = {
        "feature_names": feature_names,
        "feature_dim": feature_dim,
        "latent_dim": latent_dim,
        "feat_min": feat_min.tolist(),
        "feat_range": feat_range.tolist(),
        "epochs": epochs,
        "timestamp": int(time.time())
    }
    with open(os.path.join(output_dir, "adversarial_config.json"), "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    print(f"[+] Đã lưu trọng số và cấu hình vào: {output_dir}")

    # Sinh mẫu thử nghiệm đối kháng
    print("\n[*] Đang sinh các mẫu đối kháng để đánh giá tỷ lệ lẩn tránh...")
    test_mal = X_attack[:1000]
    test_mal_norm = (test_mal - feat_min) / feat_range

    trainer.generator.eval()
    with torch.no_grad():
        x_in = torch.tensor(test_mal_norm, dtype=torch.float32, device=trainer.device)
        adv_norm = trainer.generator(x_in).cpu().numpy()

    # Khôi phục về thang đo ban đầu
    adv_unnorm = adv_norm * feat_range + feat_min

    # Áp dụng ràng buộc giao thức mạng (Functional Constraints)
    adv_final = []
    for i in range(len(adv_unnorm)):
        clamped = constraints.apply_constraints(adv_unnorm[i], test_mal[i])
        adv_final.append(clamped)
    adv_final = np.array(adv_final, dtype=np.float32)

    # Lưu file CSV mẫu đối kháng
    adv_df = pd.DataFrame(adv_final, columns=feature_names)
    adv_df["label"] = 1 # Vẫn giữ nhãn tấn công để đối chiếu
    adv_csv_path = os.path.join(output_dir, "adversarial_test_samples.csv")
    adv_df.to_csv(adv_csv_path, index=False)
    print(f"[+] Đã xuất file mẫu đối kháng kiểm thử: {adv_csv_path}")

    # Đánh giá nếu có target model
    if iso_model is not None:
        evaluator = AdversarialEvaluator(
            isolation_forest_model=iso_model,
            classifier_model=clf_model,
            scaler=scaler,
            feature_names=feature_names
        )
        eval_results = evaluator.evaluate(test_mal, adv_final)
        evaluator.print_summary(eval_results)

        # Lưu kết quả đánh giá ra JSON
        eval_json_path = os.path.join(output_dir, "evasion_evaluation_results.json")
        with open(eval_json_path, "w", encoding="utf-8") as f:
            json.dump(eval_results, f, indent=2)
        print(f"[+] Báo cáo đánh giá đã được lưu vào: {eval_json_path}")

    return trainer


def main():
    parser = argparse.ArgumentParser(description="Huấn luyện WGAN-GP đối kháng sinh lưu lượng mạng")
    parser.add_argument("--dataset", type=str, default="synthetic", choices=["synthetic", "edge_iiotset"],
                        help="Tập dữ liệu sử dụng: 'synthetic' (8 features sliding window) hoặc 'edge_iiotset'")
    parser.add_argument("--epochs", type=int, default=25, help="Số epoch huấn luyện WGAN (mặc định 25)")
    parser.add_argument("--batch-size", type=int, default=64, help="Kích thước batch (mặc định 64)")
    parser.add_argument("--lr", type=float, default=0.0002, help="Learning rate (mặc định 0.0002)")
    parser.add_argument("--output-dir", type=str, default="ml_engine/models/adversarial_wgan",
                        help="Thư mục xuất trọng số mô hình")
    parser.add_argument("--target-models", type=str, default="ml_engine/models/decision_tree_isolation_forest",
                        help="Thư mục chứa mô hình IDS mục tiêu để đánh giá Evasion Rate")

    args = parser.parse_args()

    # Xác định đường dẫn file dataset
    if args.dataset == "synthetic":
        csv_path = os.path.join(ROOT_DIR, "ml_engine", "datasets", "synthetic_traffic_dataset.csv")
        X_benign, X_attack, y_attack, feature_names = load_sliding_window_data(csv_path)
    else:
        # Fallback hoặc Edge-IIoTset
        csv_path = os.path.join(ROOT_DIR, "ml_engine", "datasets", "Edge-IIoTset dataset", "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv")
        print(f"[*] Nạp dữ liệu Edge-IIoTset từ {csv_path}...")
        df = pd.read_csv(csv_path, nrows=50000)
        feature_names = [f for f in EDGE_IIOTSET_FEATURES if f in df.columns]
        benign_df = df[df["Attack_label"] == 0]
        attack_df = df[df["Attack_label"] == 1]
        X_benign = benign_df[feature_names].values.astype(np.float32)
        X_attack = attack_df[feature_names].values.astype(np.float32)

    output_dir = os.path.join(ROOT_DIR, args.output_dir)
    target_models_dir = os.path.join(ROOT_DIR, args.target_models)

    train_wgan(
        X_benign=X_benign,
        X_attack=X_attack,
        feature_names=feature_names,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        output_dir=output_dir,
        target_models_dir=target_models_dir
    )


if __name__ == "__main__":
    main()
