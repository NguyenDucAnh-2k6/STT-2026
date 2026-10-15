#!/usr/bin/env python3
"""
Master Training Entrypoint Wrapper
==================================
Chuyển tiếp trực tiếp sang ml_engine/train.py.
Cho phép người dùng gõ lệnh ngắn gọn:
    python train.py --classifier decision_tree
    python train.py --train-gan
    python train.py --train-rl --rl-episodes 300
    python train.py --train-all
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
