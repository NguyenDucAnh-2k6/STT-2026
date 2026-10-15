"""
Adversarial Machine Learning Module for Network Traffic
======================================================
Cung cấp các công cụ và mô hình đối kháng (Adversarial ML):
1. WGAN-GP (Wasserstein GAN với Gradient Penalty) sinh lưu lượng đối kháng (Evasion Traffic).
2. Functional Constraints Engine: Đảm bảo mẫu đối kháng bảo toàn chức năng giao thức mạng.
3. Evasion Evaluator: Đánh giá tỷ lệ lẩn tránh (Evasion Rate) trước IDS (Isolation Forest & Classifier).
"""

from .wgan_adversarial import (
    AdversarialTrafficGenerator,
    AdversarialTrafficCritic,
    FunctionalFeatureConstraints,
    WGANAdversarialTrainer
)
from .evaluator import AdversarialEvaluator

__all__ = [
    "AdversarialTrafficGenerator",
    "AdversarialTrafficCritic",
    "FunctionalFeatureConstraints",
    "WGANAdversarialTrainer",
    "AdversarialEvaluator"
]
