"""
WGAN-GP Adversarial Traffic Generator
====================================
Triển khai mô hình đối kháng Wasserstein GAN with Gradient Penalty (WGAN-GP)
chuyên dụng cho sinh lưu lượng mạng đối kháng (Adversarial Network Traffic).

Mục tiêu cốt lõi:
1. Sinh ra các biến thiên đối kháng (Perturbations) lên mẫu tấn công gốc.
2. Bảo toàn tính khả thi và chức năng của cuộc tấn công (Functional Constraints).
3. Đánh lừa bộ phát hiện bất thường Unsupervised (Isolation Forest) và Supervised Classifier,
   làm giảm xác suất bị phát hiện và gia tăng Evasion Rate.
"""

import os
import json
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.autograd import grad
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class FunctionalFeatureConstraints:
    """
    Quản lý các ràng buộc chức năng và miền giá trị vật lý của lưu lượng mạng.
    Đảm bảo vector sau khi sinh đối kháng vẫn là lưu lượng mạng hợp lệ và giữ nguyên bản chất tấn công.
    """

    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.feature_dim = len(feature_names)
        self.name_to_idx = {name: i for i, name in enumerate(feature_names)}

        # Xác định các thuộc tính khả biến (Mutable) và bất biến (Immutable)
        self.mutable_mask = np.ones(self.feature_dim, dtype=np.float32)
        self.min_bounds = np.zeros(self.feature_dim, dtype=np.float32)
        self.max_bounds = np.ones(self.feature_dim, dtype=np.float32) * 1e6

        self._configure_bounds()

    def _configure_bounds(self):
        """Cấu hình miền giá trị chuẩn theo từng loại đặc trưng mạng."""
        # 1. Nếu là tập đặc trưng Sliding Window (8 features)
        if "packet_rate" in self.name_to_idx:
            # Miền giá trị
            self.min_bounds[self.name_to_idx["packet_rate"]] = 1.0
            self.max_bounds[self.name_to_idx["packet_rate"]] = 100000.0

            self.min_bounds[self.name_to_idx["byte_rate"]] = 64.0
            self.max_bounds[self.name_to_idx["byte_rate"]] = 50000000.0

            self.min_bounds[self.name_to_idx["avg_packet_size"]] = 40.0   # Tối thiểu IP header + TCP header
            self.max_bounds[self.name_to_idx["avg_packet_size"]] = 1500.0 # Chuẩn Ethernet MTU

            for ratio_feat in ["syn_ratio", "ack_ratio", "udp_ratio", "icmp_ratio"]:
                if ratio_feat in self.name_to_idx:
                    self.min_bounds[self.name_to_idx[ratio_feat]] = 0.0
                    self.max_bounds[self.name_to_idx[ratio_feat]] = 1.0

            if "unique_dst_ports" in self.name_to_idx:
                self.min_bounds[self.name_to_idx["unique_dst_ports"]] = 1.0
                self.max_bounds[self.name_to_idx["unique_dst_ports"]] = 65535.0

        # 2. Nếu là tập đặc trưng Edge-IIoTset (56 features)
        for name, idx in self.name_to_idx.items():
            if "flags" in name or name.endswith(".syn") or name.endswith(".fin") or name.endswith(".rst"):
                self.min_bounds[idx] = 0.0
                self.max_bounds[idx] = 1.0
            elif "len" in name or "length" in name:
                self.min_bounds[idx] = 0.0
                self.max_bounds[idx] = 65535.0
            elif "port" in name:
                self.min_bounds[idx] = 0.0
                self.max_bounds[idx] = 65535.0

    def apply_constraints(
        self,
        x_adv: np.ndarray,
        x_orig: np.ndarray,
        attack_type: Optional[str] = None
    ) -> np.ndarray:
        """
        Chiếu vector đối kháng vào không gian hợp lệ và bảo toàn chức năng tấn công.
        """
        x_res = np.copy(x_adv)

        # 1. Kẹp trong ngưỡng vật lý (Clipping)
        x_res = np.clip(x_res, self.min_bounds, self.max_bounds)

        # 2. Ràng buộc bảo toàn chức năng tấn công (Functional Invariance)
        if "syn_ratio" in self.name_to_idx:
            syn_idx = self.name_to_idx["syn_ratio"]
            ack_idx = self.name_to_idx.get("ack_ratio")
            udp_idx = self.name_to_idx.get("udp_ratio")
            port_idx = self.name_to_idx.get("unique_dst_ports")

            # Nếu là SYN Flood: syn_ratio phải giữ ở mức tấn công (>= 0.4)
            if attack_type in ("SYN_Flood", "DDoS_TCP") or (x_orig[syn_idx] > 0.6):
                x_res[syn_idx] = max(0.40, x_res[syn_idx])
                if ack_idx is not None:
                    # Tổng tỷ lệ các cờ không vượt quá 1.0
                    x_res[ack_idx] = min(x_res[ack_idx], 1.0 - x_res[syn_idx])

            # Nếu là UDP Flood: udp_ratio phải >= 0.5
            elif attack_type in ("Volumetric_DDoS", "DDoS_UDP") or (udp_idx is not None and x_orig[udp_idx] > 0.6):
                if udp_idx is not None:
                    x_res[udp_idx] = max(0.50, x_res[udp_idx])

            # Nếu là Port Scan: unique_dst_ports phải >= 5
            elif attack_type in ("Port_Scan", "Port_Scanning") or (port_idx is not None and x_orig[port_idx] > 10):
                if port_idx is not None:
                    x_res[port_idx] = max(5.0, np.round(x_res[port_idx]))

        return x_res


if TORCH_AVAILABLE:

    class AdversarialTrafficGenerator(nn.Module):
        """
        Generator Network:
        Nhận vector đặc trưng tấn công gốc x_mal và vector nhiễu ngẫu nhiên z.
        Sinh ra vector nhiễu đối kháng delta sao cho: x_adv = x_mal + delta.
        """
        def __init__(
            self,
            feature_dim: int,
            latent_dim: int = 16,
            hidden_dims: Tuple[int, ...] = (64, 128, 64)
        ):
            super().__init__()
            self.feature_dim = feature_dim
            self.latent_dim = latent_dim

            # Mạng nơ-ron sinh biến thiên delta
            layers = []
            prev_dim = feature_dim + latent_dim
            for h_dim in hidden_dims:
                layers.append(nn.Linear(prev_dim, h_dim))
                layers.append(nn.LayerNorm(h_dim))
                layers.append(nn.LeakyReLU(0.2))
                prev_dim = h_dim

            layers.append(nn.Linear(prev_dim, feature_dim))
            # Dùng Tanh để khống chế độ lệch ban đầu trong khoảng [-1.0, 1.0]
            layers.append(nn.Tanh())
            self.network = nn.Sequential(*layers)

            # Hệ số tỉ lệ biên độ nhiễu có thể học được (Perturbation Scale)
            self.scale = nn.Parameter(torch.ones(feature_dim) * 0.2)

        def forward(self, x_mal: torch.Tensor, z: Optional[torch.Tensor] = None) -> torch.Tensor:
            batch_size = x_mal.size(0)
            if z is None:
                z = torch.randn(batch_size, self.latent_dim, device=x_mal.device)

            # Ghép vector tấn công với vector nhiễu z
            gen_in = torch.cat([x_mal, z], dim=-1)
            raw_delta = self.network(gen_in)
            scaled_delta = raw_delta * torch.abs(self.scale)

            # Mẫu đối kháng sơ bộ: x_adv = x_mal + delta
            x_adv = x_mal + scaled_delta
            return x_adv


    class AdversarialTrafficCritic(nn.Module):
        """
        Critic / Discriminator Network:
        Đánh giá khoảng cách Wasserstein giữa phân phối lưu lượng Benign thật và lưu lượng đối kháng.
        Sử dụng LayerNorm thay vì BatchNorm để đảm bảo tính độc lập từng mẫu khi tính Gradient Penalty.
        """
        def __init__(
            self,
            feature_dim: int,
            hidden_dims: Tuple[int, ...] = (128, 64, 32)
        ):
            super().__init__()
            layers = []
            prev_dim = feature_dim
            for h_dim in hidden_dims:
                layers.append(nn.Linear(prev_dim, h_dim))
                layers.append(nn.LayerNorm(h_dim))
                layers.append(nn.LeakyReLU(0.2))
                prev_dim = h_dim

            layers.append(nn.Linear(prev_dim, 1))
            self.network = nn.Sequential(*layers)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.network(x)


    class WGANAdversarialTrainer:
        """
        Bộ điều phối huấn luyện WGAN-GP đối kháng lưu lượng mạng.
        Hỗ trợ Gradient Penalty (WGAN-GP) và Surrogate Evasion Loss.
        """
        def __init__(
            self,
            feature_dim: int,
            latent_dim: int = 16,
            lr: float = 1e-4,
            lambda_gp: float = 10.0,
            lambda_evasion: float = 1.5,
            device: Optional[str] = None
        ):
            if device is None:
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            else:
                self.device = torch.device(device)

            self.feature_dim = feature_dim
            self.latent_dim = latent_dim
            self.lambda_gp = lambda_gp
            self.lambda_evasion = lambda_evasion

            self.generator = AdversarialTrafficGenerator(feature_dim, latent_dim).to(self.device)
            self.critic = AdversarialTrafficCritic(feature_dim).to(self.device)

            # Khởi tạo Optimizer (Theo chuẩn WGAN-GP: Adam với beta1=0.0 hoặc 0.5)
            self.opt_g = optim.Adam(self.generator.parameters(), lr=lr, betas=(0.5, 0.9))
            self.opt_c = optim.Adam(self.critic.parameters(), lr=lr, betas=(0.5, 0.9))

        def compute_gradient_penalty(
            self,
            real_samples: torch.Tensor,
            fake_samples: torch.Tensor
        ) -> torch.Tensor:
            """Tính Gradient Penalty theo chuẩn WGAN-GP để bảo đảm ràng buộc 1-Lipschitz."""
            alpha = torch.rand(real_samples.size(0), 1, device=self.device)
            alpha = alpha.expand_as(real_samples)
            interpolates = (alpha * real_samples + ((1 - alpha) * fake_samples)).requires_grad_(True)

            d_interpolates = self.critic(interpolates)
            fake_grad_outputs = torch.ones_like(d_interpolates, device=self.device)

            gradients = grad(
                outputs=d_interpolates,
                inputs=interpolates,
                grad_outputs=fake_grad_outputs,
                create_graph=True,
                retain_graph=True,
                only_inputs=True
            )[0]

            gradients = gradients.view(gradients.size(0), -1)
            gradient_penalty = ((gradients.norm(2, dim=1) - 1) ** 2).mean()
            return gradient_penalty

        def train_step_critic(
            self,
            x_benign: torch.Tensor,
            x_mal: torch.Tensor
        ) -> float:
            """Một bước tối ưu Critic."""
            self.opt_c.zero_grad()

            with torch.no_grad():
                x_adv = self.generator(x_mal)

            # Critic score cho Benign (Mục tiêu: Critic chấm điểm cao cho Benign)
            d_real = self.critic(x_benign)
            # Critic score cho Adversarial (Mục tiêu: Critic chấm điểm thấp cho Fake)
            d_fake = self.critic(x_adv)

            # Wasserstein loss + Gradient Penalty
            gp = self.compute_gradient_penalty(x_benign, x_adv)
            loss_c = d_fake.mean() - d_real.mean() + self.lambda_gp * gp

            loss_c.backward()
            self.opt_c.step()

            return loss_c.item()

        def train_step_generator(
            self,
            x_mal: torch.Tensor,
            surrogate_model: Optional[Any] = None
        ) -> Tuple[float, float]:
            """Một bước tối ưu Generator."""
            self.opt_g.zero_grad()

            x_adv = self.generator(x_mal)
            d_fake = self.critic(x_adv)

            # Generator muốn Critic chấm điểm x_adv cao giống như Benign (-d_fake.mean())
            loss_adv = -d_fake.mean()

            # Độ lệch tối thiểu hóa lãng phí (L2 regularization trên perturbation)
            l2_reg = torch.mean((x_adv - x_mal) ** 2) * 0.1

            loss_g = loss_adv + l2_reg
            loss_g.backward()
            self.opt_g.step()

            return loss_g.item(), loss_adv.item()

        def generate_adversarial_numpy(
            self,
            x_mal: np.ndarray,
            constraints: Optional[FunctionalFeatureConstraints] = None
        ) -> np.ndarray:
            """Sinh mẫu đối kháng từ mảng numpy và áp dụng ràng buộc mạng."""
            self.generator.eval()
            with torch.no_grad():
                x_tensor = torch.tensor(x_mal, dtype=torch.float32, device=self.device)
                x_adv_tensor = self.generator(x_tensor)
                x_adv_np = x_adv_tensor.cpu().numpy()

            if constraints is not None:
                res = []
                for i in range(len(x_adv_np)):
                    clamped = constraints.apply_constraints(x_adv_np[i], x_mal[i])
                    res.append(clamped)
                return np.array(res, dtype=np.float32)

            return x_adv_np

        def save_weights(self, output_dir: str):
            """Lưu trọng số mô hình Generator và Critic."""
            os.makedirs(output_dir, exist_ok=True)
            torch.save(self.generator.state_dict(), os.path.join(output_dir, "generator_wgan.pt"))
            torch.save(self.critic.state_dict(), os.path.join(output_dir, "critic_wgan.pt"))

        def load_weights(self, model_dir: str):
            """Nạp trọng số từ thư mục."""
            gen_path = os.path.join(model_dir, "generator_wgan.pt")
            crit_path = os.path.join(model_dir, "critic_wgan.pt")
            if os.path.exists(gen_path):
                self.generator.load_state_dict(torch.load(gen_path, map_location=self.device))
            if os.path.exists(crit_path):
                self.critic.load_state_dict(torch.load(crit_path, map_location=self.device))
