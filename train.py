#!/usr/bin/env python3
"""
Master Training Entrypoint Wrapper
==================================
Chuyển tiếp trực tiếp sang ml_engine/train.py.
Cho phép người dùng gõ lệnh ngắn gọn:
    python train.py --traffic-mode decrypted --classifier decision_tree
    python train.py --traffic-mode encrypted --classifier decision_tree
    python train.py --traffic-mode wireless --classifier random_forest
    python train.py --classifier xgboost --optuna --sample-ratio 0.2
    python train.py --list-models
"""

import os
import sys

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml_engine.train import main

if __name__ == "__main__":
    main()
