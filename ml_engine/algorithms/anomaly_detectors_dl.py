"""
Deep Learning Anomaly Detector (Autoencoder) Module
===================================================
Mô hình Deep Autoencoder phát hiện bất thường không giám sát (Unsupervised) cho Edge-IIoTset:
1. Kiến trúc Autoencoder đối xứng:
   Input (56) -> Dense(32, ReLU) -> Dense(16, ReLU) -> Bottleneck(8, ReLU) -> Dense(16, ReLU) -> Dense(32, ReLU) -> Output (56)
2. Cơ chế:
   - Huấn luyện trên 100% dữ liệu lưu lượng Bình thường (Normal Traffic).
   - Mạng học cách nén và tái tạo hoàn hảo các đặc trưng bình thường.
   - Khi gặp lưu lượng tấn công, mạng không thể tái tạo chính xác -> Sai số tái tạo MSE (Mean Squared Error) tăng vọt.
3. Hỗ trợ chuyển đổi sang TensorFlow Lite (.tflite) và C Header cho ESP-32.
"""

import os
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

from .base import BaseAnomalyDetector
from ..config.schema import DEFAULT_CONTAMINATION_RATE

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import TensorDataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


if TORCH_AVAILABLE:
    class AutoencoderNet(nn.Module):
        """Mạng nơ-ron Autoencoder PyTorch phục vụ phát hiện bất thường."""
        def __init__(self, in_features: int = 56, latent_dim: int = 8):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(in_features, 32),
                nn.ReLU(),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, latent_dim),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 16),
                nn.ReLU(),
                nn.Linear(16, 32),
                nn.ReLU(),
                nn.Linear(32, in_features)
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed


class DeepAutoencoderAnomalyDetector(BaseAnomalyDetector):
    """
    Wrapper phát hiện bất thường bằng Deep Autoencoder tuân thủ BaseAnomalyDetector.
    Tương thích hoàn toàn với scikit-learn, joblib serialization và TFLite Exporter.
    """

    def __init__(
        self,
        in_features: int = 56,
        latent_dim: int = 8,
        epochs: int = 15,
        batch_size: int = 64,
        lr: float = 0.001,
        contamination: float = DEFAULT_CONTAMINATION_RATE,
        random_state: int = 42,
        **kwargs
    ):
        self.in_features = in_features
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.contamination = contamination
        self.random_state = random_state

        self.threshold_: float = 0.1
        self.min_loss_: float = 0.0
        self.max_loss_: float = 1.0
        self.net: Optional[Any] = None
        self.weights_: Optional[Dict[str, np.ndarray]] = None

        if TORCH_AVAILABLE:
            torch.manual_seed(self.random_state)
            self.net = AutoencoderNet(in_features=in_features, latent_dim=latent_dim)

    def fit(self, X_normal: np.ndarray) -> "DeepAutoencoderAnomalyDetector":
        """Huấn luyện Autoencoder trên các mẫu lưu lượng bình thường (Normal)."""
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch chua duoc cai dat de huan luyen Deep Autoencoder.")

        X_tensor = torch.tensor(X_normal, dtype=torch.float32)
        dataset = TensorDataset(X_tensor, X_tensor)
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.net.parameters(), lr=self.lr)

        self.net.train()
        for epoch in range(1, self.epochs + 1):
            total_loss = 0.0
            for batch_x, _ in loader:
                optimizer.zero_grad()
                recon = self.net(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(batch_x)

            epoch_loss = total_loss / len(X_tensor)
            if epoch % 5 == 0 or epoch == 1:
                print(f"  [Autoencoder] Epoch {epoch:2d}/{self.epochs} - MSE Reconstruction Loss: {epoch_loss:.6f}")

        # Tính toán ngưỡng phát hiện (Threshold) dựa trên phân vị contamination của tập Normal
        self.net.eval()
        with torch.no_grad():
            recon_all = self.net(X_tensor).numpy()
            errors = np.mean(np.square(X_normal - recon_all), axis=1)

        perc = 100.0 * (1.0 - self.contamination)
        self.threshold_ = float(np.percentile(errors, perc))
        self.min_loss_ = float(np.min(errors))
        self.max_loss_ = float(np.percentile(errors, 99.5))
        if self.max_loss_ <= self.min_loss_:
            self.max_loss_ = self.min_loss_ + 1e-4

        # Trích xuất trọng số (Weights & Biases) dạng Numpy để phục vụ export TFLite / C Header
        self._extract_weights()
        print(f"  -> Ngưỡng phát hiện bất thường Autoencoder (Threshold MSE): {self.threshold_:.6f}")
        return self

    def _extract_weights(self):
        """Trích xuất ma trận trọng số và bias của các tầng sang numpy array."""
        self.weights_ = {}
        if self.net is not None:
            state = self.net.state_dict()
            for k, v in state.items():
                self.weights_[k] = v.cpu().numpy()

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Tính điểm bất thường cho từng mẫu.
        Trả về giá trị âm của MSE sao cho điểm càng thấp (âm nhiều) thì càng bất thường (chuẩn scikit-learn).
        """
        if self.net is None:
            return np.zeros(len(X))

        self.net.eval()
        with torch.no_grad():
            X_tensor = torch.tensor(X, dtype=torch.float32)
            recon = self.net(X_tensor).numpy()
            mse = np.mean(np.square(X - recon), axis=1)

        # Trả về -mse để nhất quán với convention IsolationForest (càng âm -> càng ngoại lai)
        return -mse

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Dự đoán nhãn: 1 là Bình thường (Inlier), -1 là Bất thường (Outlier)."""
        mse = -self.score_samples(X)
        preds = np.where(mse > self.threshold_, -1, 1)
        return preds

    def get_normalized_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Tính điểm bất thường chuẩn hóa trong khoảng [0.0, 1.0] cho Dashboard & ESP32."""
        mse = -self.score_samples(X)
        norm_scores = (mse - self.min_loss_) / (self.max_loss_ - self.min_loss_)
        return np.clip(norm_scores, 0.0, 1.0)

    @property
    def underlying_estimator(self):
        return self.net
