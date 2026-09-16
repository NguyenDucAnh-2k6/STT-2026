"""
Deep Learning (PyTorch DNN) Module
==================================
Triển khai mô hình Deep Neural Network (DNN) chuẩn cho tập dữ liệu Edge-IIoTset:
1. EdgeDeepNet: Kiến trúc mạng nơ-ron sâu với BatchNorm, LeakyReLU/ReLU, Dropout.
2. PyTorchDeepWrapper: Wrapper tuân thủ BaseAttackClassifier, in loss/accuracy theo epoch và tự động vẽ loss_curve.png.
"""

import os
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.model_selection import train_test_split

from ..base import BaseAttackClassifier

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import TensorDataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


if TORCH_AVAILABLE:
    class EdgeDeepNet(nn.Module):
        """
        Kiến trúc Deep Neural Network (DNN) chuyên dụng cho tập dữ liệu Edge-IIoTset dạng bảng:
        Input (56 features) -> Dense(128) + BN + LeakyReLU + Dropout -> Dense(64) + BN + LeakyReLU + Dropout -> Dense(32) + BN + LeakyReLU -> Output (num_classes).
        """
        def __init__(
            self,
            in_features: int,
            num_classes: int,
            hidden_dims: Tuple[int, ...] = (128, 64, 32),
            dropout: float = 0.2
        ):
            super().__init__()
            layers = []
            prev_dim = in_features
            for h_dim in hidden_dims:
                layers.append(nn.Linear(prev_dim, h_dim))
                layers.append(nn.BatchNorm1d(h_dim))
                layers.append(nn.LeakyReLU(0.1))
                layers.append(nn.Dropout(dropout))
                prev_dim = h_dim
            layers.append(nn.Linear(prev_dim, num_classes))
            self.net = nn.Sequential(*layers)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.net(x)

    class EdgeLSTMNet(nn.Module):
        """
        Kiến trúc Recurrent Neural Network (Bi-LSTM) chuyên dụng cho chuỗi thời gian Edge-IIoTset:
        Input (Batch, Window_W, Features_D) -> Bi-LSTM(hidden=64, 2 layers) -> Last Step -> Dense(64) -> Output (num_classes).
        """
        def __init__(
            self,
            in_features: int,
            num_classes: int,
            hidden_dim: int = 64,
            num_layers: int = 2,
            dropout: float = 0.2
        ):
            super().__init__()
            self.lstm = nn.LSTM(
                input_size=in_features,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0.0,
                bidirectional=True
            )
            self.fc = nn.Sequential(
                nn.Linear(hidden_dim * 2, 64),
                nn.BatchNorm1d(64),
                nn.LeakyReLU(0.1),
                nn.Dropout(dropout),
                nn.Linear(64, num_classes)
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            out, _ = self.lstm(x)
            last_step = out[:, -1, :]
            return self.fc(last_step)


class PyTorchDeepWrapper(BaseAttackClassifier):
    """
    Mô hình Deep Learning xây dựng bằng PyTorch cho Edge-IIoTset:
    - Huấn luyện theo epochs với in loss & accuracy định dạng bảng trực quan.
    - Tự động vẽ và lưu đồ thị Train | Val Loss & Accuracy theo epochs bằng Matplotlib.
    - Tương thích 100% với inference pipeline và joblib serialization.
    """

    is_deep_learning: bool = True

    def __init__(
        self,
        epochs: int = 25,
        batch_size: int = 256,
        lr: float = 1e-3,
        weight_decay: float = 1e-4,
        dropout: float = 0.2,
        hidden_dims: Tuple[int, ...] = (128, 64, 32),
        plot_dir: Optional[str] = None,
        random_state: int = 42,
        verbose: bool = True,
        **kwargs
    ):
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch chua duoc cai dat. Vui long cai dat: pip install torch")

        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.weight_decay = weight_decay
        self.dropout = dropout
        self.hidden_dims = hidden_dims
        self.plot_dir = plot_dir
        self.random_state = random_state
        self.verbose = verbose

        self.in_features: Optional[int] = None
        self.num_classes: Optional[int] = None
        self.classes_: Optional[np.ndarray] = None
        self.net: Optional[Any] = None
        self.history: Dict[str, List[float]] = {
            "train_loss": [],
            "train_acc": [],
            "val_loss": [],
            "val_acc": []
        }
        self.plot_path: Optional[str] = None

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        plot_dir: Optional[str] = None,
        verbose: Optional[bool] = None,
        **kwargs
    ) -> "PyTorchDeepWrapper":
        """
        Huấn luyện PyTorch Deep Learning Model theo từng epoch.
        In log train/val loss & acc và vẽ biểu đồ loss_curve.png.
        """
        torch.manual_seed(self.random_state)
        np.random.seed(self.random_state)

        target_plot_dir = plot_dir or self.plot_dir
        is_verbose = self.verbose if verbose is None else verbose

        is_3d = bool(len(X.shape) == 3)
        self.is_timeseries = is_3d

        unique_classes = np.unique(y)
        max_label = int(np.max(y)) if len(y) > 0 else 0
        self.num_classes = max(max_label + 1, len(unique_classes), kwargs.get("num_classes", 15))
        self.classes_ = np.arange(self.num_classes)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if is_3d:
            self.window_size = int(X.shape[1])
            self.in_features = int(X.shape[2])
            self.net = EdgeLSTMNet(
                in_features=self.in_features,
                num_classes=self.num_classes,
                hidden_dim=64,
                num_layers=2,
                dropout=self.dropout
            ).to(device)
            arch_desc = f"EdgeLSTMNet (SeqLen={self.window_size}, Dim={self.in_features} -> 128 Bi-LSTM -> {self.num_classes} classes)"
        else:
            self.in_features = int(X.shape[1])
            self.net = EdgeDeepNet(
                in_features=self.in_features,
                num_classes=self.num_classes,
                hidden_dims=self.hidden_dims,
                dropout=self.dropout
            ).to(device)
            arch_desc = f"EdgeDeepNet ({self.in_features} -> {self.hidden_dims} -> {self.num_classes} classes)"

        if X_val is not None and y_val is not None:
            X_tr, y_tr = X, y
            X_va, y_va = X_val, y_val
        else:
            from sklearn.model_selection import train_test_split
            min_count = np.min(np.bincount(y)) if len(y) > 0 and len(np.unique(y)) > 1 else 0
            strat = y if min_count >= 2 else None
            X_tr, X_va, y_tr, y_va = train_test_split(
                X, y, test_size=0.2, random_state=self.random_state, stratify=strat
            )

        # Chuẩn bị Tensor DataLoader
        train_dataset = TensorDataset(
            torch.tensor(X_tr, dtype=torch.float32),
            torch.tensor(y_tr, dtype=torch.long)
        )
        val_dataset = TensorDataset(
            torch.tensor(X_va, dtype=torch.float32),
            torch.tensor(y_va, dtype=torch.long)
        )

        train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True, drop_last=False)
        val_loader = DataLoader(val_dataset, batch_size=self.batch_size, shuffle=False)

        criterion = nn.CrossEntropyLoss()
        optimizer = optim.AdamW(self.net.parameters(), lr=self.lr, weight_decay=self.weight_decay)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=3)

        if is_verbose:
            print(f"\n[PyTorch Network] Khoi tao {arch_desc}")
            print(f"  -> Thiet bi huan luyen: {device} | Batch Size: {self.batch_size} | Epochs: {self.epochs}")
            print("=" * 75)
            print(f" {'EPOCH':^8} | {'TRAIN LOSS':^12} | {'TRAIN ACC':^11} | {'VAL LOSS':^12} | {'VAL ACC':^11} | {'LR':^8}")
            print("=" * 75)

        self.history = {"train_loss": [], "train_acc": [], "val_loss": [], "val_acc": []}

        for epoch in range(1, self.epochs + 1):
            # 1. Training Phase
            self.net.train()
            total_train_loss = 0.0
            correct_train = 0
            total_train_samples = 0

            for batch_x, batch_y in train_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                optimizer.zero_grad()
                outputs = self.net(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                total_train_loss += loss.item() * batch_x.size(0)
                preds = outputs.argmax(dim=1)
                correct_train += (preds == batch_y).sum().item()
                total_train_samples += batch_x.size(0)

            epoch_train_loss = total_train_loss / max(1, total_train_samples)
            epoch_train_acc = correct_train / max(1, total_train_samples)

            # 2. Validation Phase
            self.net.eval()
            total_val_loss = 0.0
            correct_val = 0
            total_val_samples = 0

            with torch.no_grad():
                for batch_x, batch_y in val_loader:
                    batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                    outputs = self.net(batch_x)
                    loss = criterion(outputs, batch_y)

                    total_val_loss += loss.item() * batch_x.size(0)
                    preds = outputs.argmax(dim=1)
                    correct_val += (preds == batch_y).sum().item()
                    total_val_samples += batch_x.size(0)

            epoch_val_loss = total_val_loss / max(1, total_val_samples)
            epoch_val_acc = correct_val / max(1, total_val_samples)

            scheduler.step(epoch_val_loss)
            current_lr = optimizer.param_groups[0]["lr"]

            self.history["train_loss"].append(epoch_train_loss)
            self.history["train_acc"].append(epoch_train_acc)
            self.history["val_loss"].append(epoch_val_loss)
            self.history["val_acc"].append(epoch_val_acc)

            if is_verbose:
                print(f" {epoch:^8d} | {epoch_train_loss:^12.4f} | {epoch_train_acc*100:^10.2f}% | {epoch_val_loss:^12.4f} | {epoch_val_acc*100:^10.2f}% | {current_lr:^8.1e}")

        if is_verbose:
            print("=" * 75)

        # Đưa mạng về CPU để bảo đảm joblib serialize an toàn trên mọi môi trường
        self.net.cpu()
        self.net.eval()

        # 3. Vẽ và lưu đồ thị Loss / Accuracy Curves khi verbose=True
        if is_verbose:
            self._plot_loss_curves(target_plot_dir)

        return self

    def _plot_loss_curves(self, target_plot_dir: Optional[str]):
        """Vẽ biểu đồ huấn luyện Train | Val Loss và Train | Val Accuracy."""
        try:
            import matplotlib.pyplot as plt
            if target_plot_dir is None:
                root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
                target_plot_dir = os.path.join(root_dir, "ml_engine", "models")
            os.makedirs(target_plot_dir, exist_ok=True)
            self.plot_path = os.path.join(target_plot_dir, "loss_curve.png")

            epochs_range = range(1, len(self.history["train_loss"]) + 1)

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
            fig.suptitle("Edge AI Network Anomaly Detection - PyTorch DNN Training History", fontsize=13, fontweight="bold")

            # Biểu đồ Loss
            ax1.plot(epochs_range, self.history["train_loss"], label="Train Loss", color="#1f77b4", linewidth=2.2, marker="o", markersize=3)
            ax1.plot(epochs_range, self.history["val_loss"], label="Val Loss", color="#ff7f0e", linewidth=2.2, linestyle="--", marker="s", markersize=3)
            ax1.set_title("Cross-Entropy Loss theo Epochs", fontsize=11)
            ax1.set_xlabel("Epoch", fontsize=10)
            ax1.set_ylabel("Loss", fontsize=10)
            ax1.grid(True, linestyle=":", alpha=0.6)
            ax1.legend(loc="upper right")

            # Biểu đồ Accuracy
            train_acc_pct = [acc * 100.0 for acc in self.history["train_acc"]]
            val_acc_pct = [acc * 100.0 for acc in self.history["val_acc"]]
            ax2.plot(epochs_range, train_acc_pct, label="Train Accuracy", color="#2ca02c", linewidth=2.2, marker="o", markersize=3)
            ax2.plot(epochs_range, val_acc_pct, label="Val Accuracy", color="#d62728", linewidth=2.2, linestyle="--", marker="s", markersize=3)
            ax2.set_title("Accuracy (%) theo Epochs", fontsize=11)
            ax2.set_xlabel("Epoch", fontsize=10)
            ax2.set_ylabel("Accuracy (%)", fontsize=10)
            ax2.grid(True, linestyle=":", alpha=0.6)
            ax2.legend(loc="lower right")

            plt.tight_layout()
            plt.savefig(self.plot_path, dpi=200)
            plt.close(fig)
            print(f"  -> [PyTorch DNN] Da ve va xuat do thi Loss & Accuracy tai: {self.plot_path}")
        except Exception as e:
            print(f"  -> [PyTorch Canh bao] Khong the ve do thi loss: {e}")

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán ma trận xác suất phân loại đa lớp."""
        if self.net is None:
            raise RuntimeError("Mo hinh PyTorch chua duoc fit!")
        self.net.eval()
        self.net.cpu()

        with torch.no_grad():
            tensor_x = torch.tensor(X, dtype=torch.float32)
            if getattr(self, "is_timeseries", False) and len(tensor_x.shape) == 2:
                w = getattr(self, "window_size", 10)
                tensor_x = tensor_x.unsqueeze(1).repeat(1, w, 1)
            logits = self.net(tensor_x)
            probabilities = torch.softmax(logits, dim=1).numpy()
        return probabilities


    def predict(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán nhãn phân loại đa lớp."""
        probs = self.predict_proba(X)
        pred_indices = np.argmax(probs, axis=1)
        if self.classes_ is not None:
            return self.classes_[pred_indices]
        return pred_indices

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self) -> Any:
        return self.net
