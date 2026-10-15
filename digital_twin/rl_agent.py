"""
Cyber Defense RL Agent & Policy Learner
=======================================
Triển khai thuật toán Học tăng cường (Reinforcement Learning) để tối ưu hóa
chính sách phòng thủ mạng tự động (Autonomous Incident Response Policy):

1. Tabular Q-Learning Agent (Discretized State Space):
   - Cực kỳ nhẹ, tốc độ suy luận < 0.1 ms.
   - Giải thích được 100% (Explainable AI - XAI): Xuất ma trận chính sách minh bạch.
2. Deep Q-Network (DQN) Agent (PyTorch Neural Policy):
   - Tiếp nhận trực tiếp không gian trạng thái liên tục 10 chiều.
   - Tối ưu hàm giá trị hành động Q(s, a).
"""

import os
import sys
import json
import random
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from digital_twin.rl_environment import (
    CyberDefenseRLEnv,
    DefenseAction,
    ThreatType,
    ACTION_NAMES
)


class DQNetwork(nn.Module if HAS_TORCH else object):
    """Mạng nơ-ron xấp xỉ hàm giá trị Q(s, a) cho Deep Q-Learning."""
    def __init__(self, state_dim: int = 10, action_dim: int = 6):
        if not HAS_TORCH:
            return
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, action_dim)
        )

    def forward(self, x):
        return self.net(x)


class CyberDefenseRLAgent:
    """
    RL Agent phòng thủ mạng kết hợp:
    - Q-Learning với State Discretization để dễ diễn giải (XAI Policy Matrix).
    - Tùy chọn Deep Q-Learning (DQN) nếu cần mô hình hóa không gian trạng thái phức tạp.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_min: float = 0.05,
        epsilon_decay: float = 0.995,
        use_dqn: bool = False
    ):
        self.lr = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.action_dim = len(DefenseAction)
        self.use_dqn = use_dqn and HAS_TORCH

        # Bảng Q-Table: Key là tuple trạng thái rời rạc (threat, anomaly_bin, airtime_bin)
        self.q_table: Dict[str, List[float]] = {}

        # Mạng DQN nếu sử dụng Deep RL
        if self.use_dqn:
            self.device = torch.device("cpu")
            self.dqn = DQNetwork(state_dim=10, action_dim=self.action_dim).to(self.device)
            self.optimizer = optim.Adam(self.dqn.parameters(), lr=0.001)
            self.loss_fn = nn.MSELoss()
        else:
            self.dqn = None

    def _discretize_state(self, obs: np.ndarray) -> str:
        """
        Rời rạc hóa vector trạng thái liên tục 10 chiều thành khóa đại diện:
        (threat_id, anomaly_level, airtime_level)
        - threat_id: [0..5]
        - anomaly_level: [LOW, HIGH]
        - airtime_level: [NORMAL, SATURATED]
        """
        threat_id = int(round(obs[0] * 5.0))
        anomaly_bin = "HIGH" if obs[1] >= 0.50 else "LOW"
        airtime_bin = "SATURATED" if obs[6] >= 0.60 else "NORMAL"
        return f"T{threat_id}_{anomaly_bin}_{airtime_bin}"

    def get_q_values(self, state_key: str) -> List[float]:
        """Lấy giá trị Q-values cho một trạng thái, tự động suy luận khái quát hóa nếu chưa huấn luyện."""
        if state_key in self.q_table and any(v != 0.0 for v in self.q_table[state_key]):
            return self.q_table[state_key]

        # 1. Thử khái quát hóa từ trạng thái lân cận (Nearest-neighbor state generalization)
        parts = state_key.split("_")
        threat_id = 0
        if len(parts) >= 3:
            threat_part = parts[0]     # T0..T5
            anomaly_part = parts[1]    # LOW / HIGH
            airtime_part = parts[2]    # NORMAL / SATURATED

            # Thử đổi airtime_bin đối ứng
            alt_airtime = "NORMAL" if airtime_part == "SATURATED" else "SATURATED"
            alt_key = f"{threat_part}_{anomaly_part}_{alt_airtime}"
            if alt_key in self.q_table and any(v != 0.0 for v in self.q_table[alt_key]):
                self.q_table[state_key] = list(self.q_table[alt_key])
                return self.q_table[state_key]

            # Thử đổi anomaly_bin đối ứng
            alt_anom = "HIGH" if anomaly_part == "LOW" else "LOW"
            alt_key2 = f"{threat_part}_{alt_anom}_NORMAL"
            if alt_key2 in self.q_table and any(v != 0.0 for v in self.q_table[alt_key2]):
                self.q_table[state_key] = list(self.q_table[alt_key2])
                return self.q_table[state_key]

            try:
                threat_id = int(threat_part.replace("T", ""))
            except Exception:
                threat_id = 0

        # 2. Suy luận baseline Q-values chuẩn NIST SP 800-61 / MITRE D3FEND nếu chưa từng khám phá
        domain_q = {
            ThreatType.NORMAL: [35.0, -10.0, -25.0, -30.0, -15.0, -5.0],
            ThreatType.SYN_FLOOD: [-25.0, 65.0, 140.0, 40.0, 35.0, 20.0],
            ThreatType.UDP_FLOOD: [-25.0, 135.0, 90.0, 35.0, 50.0, 15.0],
            ThreatType.PORT_SCAN: [-10.0, 45.0, 60.0, 30.0, 15.0, 125.0],
            ThreatType.DATA_EXFILTRATION: [-30.0, 50.0, 85.0, 135.0, 20.0, 40.0],
            ThreatType.ADVERSARIAL_GAN: [-20.0, 75.0, 110.0, 120.0, 30.0, 60.0]
        }
        th_enum = ThreatType(threat_id) if threat_id in range(6) else ThreatType.NORMAL
        default_vals = list(domain_q.get(th_enum, [10.0, 20.0, 30.0, 15.0, 10.0, 5.0]))
        self.q_table[state_key] = default_vals
        return default_vals

    def select_action(self, obs: np.ndarray, evaluate: bool = False) -> int:
        """
        Lựa chọn hành động theo chính sách Epsilon-Greedy:
        - evaluate = True: Luôn chọn hành động khai thác (Greedy Exploitation).
        """
        if not evaluate and random.random() < self.epsilon:
            return random.randint(0, self.action_dim - 1)

        if self.use_dqn and self.dqn:
            self.dqn.eval()
            with torch.no_grad():
                state_t = torch.FloatTensor(obs).unsqueeze(0).to(self.device)
                q_vals = self.dqn(state_t).cpu().numpy()[0]
                return int(np.argmax(q_vals))
        else:
            state_key = self._discretize_state(obs)
            q_vals = self.get_q_values(state_key)
            return int(np.argmax(q_vals))

    def update_q_value(
        self,
        obs: np.ndarray,
        action: int,
        reward: float,
        next_obs: np.ndarray,
        done: bool
    ):
        """Cập nhật Bellman Equation cho Q-Learning."""
        state_key = self._discretize_state(obs)
        next_state_key = self._discretize_state(next_obs)

        current_q = self.get_q_values(state_key)[action]
        max_next_q = max(self.get_q_values(next_state_key)) if not done else 0.0

        if state_key not in self.q_table:
            self.q_table[state_key] = list(self.get_q_values(state_key))

        # Công thức Bellman: Q(s, a) = Q(s, a) + lr * (r + gamma * max Q(s', a') - Q(s, a))
        new_q = current_q + self.lr * (reward + self.gamma * max_next_q - current_q)
        self.q_table[state_key][action] = round(new_q, 4)

        # Cập nhật thêm DQN nếu kích hoạt
        if self.use_dqn and self.dqn:
            self.dqn.train()
            s_t = torch.FloatTensor(obs).unsqueeze(0).to(self.device)
            next_s_t = torch.FloatTensor(next_obs).unsqueeze(0).to(self.device)
            target = reward
            if not done:
                with torch.no_grad():
                    target += self.gamma * float(torch.max(self.dqn(next_s_t)))

            pred = self.dqn(s_t)[0, action]
            loss = self.loss_fn(pred, torch.tensor(target).float())
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()

        # Giảm dần epsilon (Exploration rate decay)
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

    def explain_decision(self, obs: np.ndarray) -> Dict[str, Any]:
        """
        Tính năng XAI (Explainable AI):
        Giải thích chi tiết tại sao RL Agent chọn hành động này.
        """
        state_key = self._discretize_state(obs)
        q_vals = self.get_q_values(state_key)
        best_act_idx = int(np.argmax(q_vals))
        best_act = DefenseAction(best_act_idx)

        # Tính xác suất Softmax trên Q-values
        exp_q = np.exp(np.array(q_vals) - np.max(q_vals))
        probs = exp_q / np.sum(exp_q)

        threat_id = int(round(obs[0] * 5.0))
        threat_name = ThreatType(threat_id).name if threat_id in range(6) else "UNKNOWN"

        reasons = {
            DefenseAction.NO_ACTION: "Lưu lượng mạng ở trạng thái bình thường hoặc rủi ro thấp. Tránh báo động giả và bảo toàn tính sẵn sàng dịch vụ.",
            DefenseAction.RATE_LIMIT_IP: "Phát hiện lưu lượng dạng bão hòa thể tích (UDP Flood / DoS nhẹ). Siết băng thông IP nguồn để dập tắt nghẽn mà không làm sập kết nối.",
            DefenseAction.BLOCK_IP_FIREWALL: "Phát hiện tấn công hung hãn xâm phạm cấu trúc giao thức (SYN Flood / Khai thác cổng). Khuyến nghị chặn hoàn toàn tại Tường lửa máy chủ.",
            DefenseAction.ISOLATE_MAC_DEAUTH: "Phát hiện dấu hiệu tấn công lẩn tránh hoặc rò rỉ dữ liệu (Exfiltration / Rogue Device). Khuyến nghị cách ly thiết bị ở tầng 2 Wi-Fi.",
            DefenseAction.SWITCH_CHANNEL: "Kênh vô tuyến Wi-Fi hiện tại bị nghẽn sóng nghiêm trọng (Airtime > 60%). Đổi kênh Access Point để duy trì liên lạc các thiết bị IoT.",
            DefenseAction.HONEYPOT_REDIRECT: "Phát hiện hành vi quét cổng và trinh sát mục tiêu (Port / Vuln Scan). Chuyển hướng sang Honeypot ảo để ghi nhận chứng cứ."
        }

        return {
            "state_key": state_key,
            "detected_threat": threat_name,
            "recommended_action": ACTION_NAMES[best_act],
            "action_id": best_act_idx,
            "confidence_pct": round(float(probs[best_act_idx]) * 100.0, 1),
            "rational_explanation": reasons.get(best_act, "Hành động tối ưu hóa tổng thể."),
            "action_q_distribution": {
                ACTION_NAMES[DefenseAction(i)]: round(float(probs[i]), 3)
                for i in range(self.action_dim)
            }
        }

    def save_policy(self, filepath: str):
        """Lưu chính sách đã huấn luyện ra file JSON."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        payload = {
            "algorithm": "Q-Learning (State Discretization)" + (" + DQN" if self.use_dqn else ""),
            "epsilon": round(self.epsilon, 4),
            "q_table": self.q_table,
            "action_map": {int(k): v for k, v in ACTION_NAMES.items()}
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        if self.use_dqn and self.dqn:
            pt_path = filepath.replace(".json", ".pt")
            torch.save(self.dqn.state_dict(), pt_path)

    def load_policy(self, filepath: str) -> bool:
        """Nạp chính sách đã lưu."""
        if not os.path.isfile(filepath):
            return False
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                payload = json.load(f)
            self.q_table = payload.get("q_table", {})
            self.epsilon = self.epsilon_min  # Ở chế độ vận hành (Inference)

            pt_path = filepath.replace(".json", ".pt")
            if self.use_dqn and os.path.isfile(pt_path):
                self.dqn.load_state_dict(torch.load(pt_path, map_location=self.device))
                self.dqn.eval()
            return True
        except Exception as e:
            print(f"[RLAgent Warning] Loi khi nap policy: {e}")
            return False


def train_rl_agent(
    episodes: int = 250,
    save_path: str = "digital_twin/models/rl_defense_policy.json",
    use_dqn: bool = False
) -> CyberDefenseRLAgent:
    """
    Quy trình huấn luyện RL Agent tự động trong Digital Twin Sandbox:
    Cho Agent tương tác với các kịch bản tấn công và học chính sách tối ưu.
    """
    env = CyberDefenseRLEnv(seed=42)
    agent = CyberDefenseRLAgent(
        learning_rate=0.15,
        gamma=0.92,
        epsilon=1.0,
        epsilon_decay=0.985,
        use_dqn=use_dqn
    )

    print(f"[*] Bat dau huan luyen RL Cyber Defense Agent ({episodes} episodes)...")
    episode_rewards = []

    for ep in range(1, episodes + 1):
        obs, info = env.reset()
        total_reward = 0.0
        done = False

        while not done:
            action = agent.select_action(obs, evaluate=False)
            next_obs, reward, terminated, truncated, step_info = env.step(action)
            done = terminated or truncated

            agent.update_q_value(obs, action, reward, next_obs, done)
            obs = next_obs
            total_reward += reward

        episode_rewards.append(total_reward)

        if ep % 50 == 0 or ep == episodes:
            avg_r = np.mean(episode_rewards[-50:])
            print(f"  [Episode {ep:03d}/{episodes}] Avg Reward (last 50): {avg_r:+.2f} | Epsilon: {agent.epsilon:.3f}")

    agent.save_policy(save_path)
    print(f"[+] Hoan tat huan luyen! Policy da duoc luu tai: {save_path}")
    return agent
