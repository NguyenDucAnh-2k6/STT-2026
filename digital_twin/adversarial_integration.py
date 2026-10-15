"""
Digital Twin & WGAN Adversarial Integration
===========================================
Module tích hợp trực tiếp giữa mô hình đối kháng WGAN-GP và Bản sao số (Digital Twin):
1. Nạp mô hình sinh WGAN Generator đã huấn luyện.
2. Sinh các mẫu tấn công đối kháng (Adversarial Evasion Vectors) dựa trên hạt giống tấn công (Malicious Seed).
3. Đẩy luồng đối kháng vào nút tấn công trong Digital Twin.
4. Đo lường hiệu năng suy giảm của mạng và thử nghiệm chính sách dập tắt trong Sandbox.
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

# Thêm đường dẫn gốc dự án vào sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ml_engine.adversarial.wgan_adversarial import (
    AdversarialTrafficGenerator,
    FunctionalFeatureConstraints
)
from digital_twin.engine import NetworkDigitalTwin
from digital_twin.models import MitigationPolicy, MitigationAction, DryRunReport


class TwinAdversarialBridge:
    """
    Cầu nối tích hợp giữa mô hình WGAN Adversarial và Network Digital Twin.
    """

    def __init__(
        self,
        twin: NetworkDigitalTwin,
        model_dir: str = "ml_engine/models/adversarial_wgan"
    ):
        self.twin = twin
        self.model_dir = os.path.join(ROOT_DIR, model_dir)
        self.device = "cuda" if (TORCH_AVAILABLE and torch.cuda.is_available()) else "cpu"

        self.generator: Optional[AdversarialTrafficGenerator] = None
        self.config: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.constraints: Optional[FunctionalFeatureConstraints] = None

        self._load_generator()

    def _load_generator(self):
        """Nạp trọng số WGAN Generator và cấu hình chuẩn."""
        config_path = os.path.join(self.model_dir, "adversarial_config.json")
        weights_path = os.path.join(self.model_dir, "generator_wgan.pt")

        if not (os.path.exists(config_path) and os.path.exists(weights_path)):
            print(f"[Bridge] Chưa tìm thấy mô hình WGAN tại {self.model_dir}. Vui lòng chạy train_gan.py trước.")
            return

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        self.feature_names = self.config.get("feature_names", [])
        feature_dim = self.config.get("feature_dim", len(self.feature_names))
        latent_dim = self.config.get("latent_dim", 16)

        self.generator = AdversarialTrafficGenerator(
            feature_dim=feature_dim,
            latent_dim=latent_dim
        ).to(self.device)

        self.generator.load_state_dict(torch.load(weights_path, map_location=self.device))
        self.generator.eval()

        self.constraints = FunctionalFeatureConstraints(self.feature_names)
        print(f"[Bridge] Đã nạp thành công WGAN Generator ({feature_dim} features) vào Digital Twin.")

    def generate_adversarial_traffic(
        self,
        base_attack_type: str = "SYN_Flood",
        n_samples: int = 1
    ) -> np.ndarray:
        """
        Sinh ra vector đặc trưng đối kháng từ một mẫu tấn công cơ sở.
        """
        if self.generator is None:
            raise RuntimeError("Generator chưa được khởi tạo thành công.")

        # Tạo vector tấn công cơ sở (Seed Vector)
        seed = np.zeros(len(self.feature_names), dtype=np.float32)
        name_to_idx = {name: i for i, name in enumerate(self.feature_names)}

        if base_attack_type in ("SYN_Flood", "DDoS_TCP"):
            seed[name_to_idx["packet_rate"]] = 3500.0
            seed[name_to_idx["byte_rate"]] = 245000.0
            seed[name_to_idx["avg_packet_size"]] = 70.0
            seed[name_to_idx["syn_ratio"]] = 0.95
            seed[name_to_idx["ack_ratio"]] = 0.02
            seed[name_to_idx["udp_ratio"]] = 0.01
            seed[name_to_idx["icmp_ratio"]] = 0.0
            seed[name_to_idx["unique_dst_ports"]] = 5.0
        elif base_attack_type in ("Volumetric_DDoS", "DDoS_UDP"):
            seed[name_to_idx["packet_rate"]] = 4000.0
            seed[name_to_idx["byte_rate"]] = 4800000.0
            seed[name_to_idx["avg_packet_size"]] = 1200.0
            seed[name_to_idx["syn_ratio"]] = 0.01
            seed[name_to_idx["ack_ratio"]] = 0.02
            seed[name_to_idx["udp_ratio"]] = 0.96
            seed[name_to_idx["icmp_ratio"]] = 0.0
            seed[name_to_idx["unique_dst_ports"]] = 2.0
        else: # Port Scan
            seed[name_to_idx["packet_rate"]] = 1200.0
            seed[name_to_idx["byte_rate"]] = 72000.0
            seed[name_to_idx["avg_packet_size"]] = 60.0
            seed[name_to_idx["syn_ratio"]] = 0.85
            seed[name_to_idx["ack_ratio"]] = 0.05
            seed[name_to_idx["udp_ratio"]] = 0.05
            seed[name_to_idx["icmp_ratio"]] = 0.0
            seed[name_to_idx["unique_dst_ports"]] = 250.0

        seeds_batch = np.tile(seed, (n_samples, 1))

        # Chuẩn hóa theo min-max đã lưu lúc huấn luyện
        feat_min = np.array(self.config["feat_min"], dtype=np.float32)
        feat_range = np.array(self.config["feat_range"], dtype=np.float32)
        seeds_norm = (seeds_batch - feat_min) / feat_range

        with torch.no_grad():
            x_in = torch.tensor(seeds_norm, dtype=torch.float32, device=self.device)
            adv_norm = self.generator(x_in).cpu().numpy()

        adv_unnorm = adv_norm * feat_range + feat_min

        # Áp dụng ràng buộc bảo toàn chức năng
        adv_clamped = []
        for i in range(len(adv_unnorm)):
            vec = self.constraints.apply_constraints(adv_unnorm[i], seeds_batch[i], base_attack_type)
            adv_clamped.append(vec)

        return np.array(adv_clamped, dtype=np.float32)

    def inject_gan_adversary_into_twin(
        self,
        base_attack_type: str = "SYN_Flood",
        target_node_id: str = "node_threat_01"
    ) -> Dict[str, Any]:
        """
        Sinh mẫu tấn công đối kháng từ GAN và nạp trực tiếp vào nút tấn công của Digital Twin.
        """
        adv_vecs = self.generate_adversarial_traffic(base_attack_type, n_samples=1)
        adv_vector = adv_vecs[0]

        # Nạp vào Digital Twin
        self.twin.inject_adversarial_attack(
            adversarial_vector=adv_vector,
            feature_names=self.feature_names,
            target_node_id=target_node_id
        )

        attacker_node = self.twin.get_node(target_node_id)

        return {
            "target_node": target_node_id,
            "base_attack_type": base_attack_type,
            "adversarial_features": {
                name: round(float(adv_vector[i]), 4)
                for i, name in enumerate(self.feature_names)
            },
            "status": attacker_node.status.value if attacker_node else "UNKNOWN"
        }
