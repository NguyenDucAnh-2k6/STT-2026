"""
Digital Twin & Reinforcement Learning Pipeline Runner
=====================================================
Script độc lập chạy mô phỏng và kiểm thử hoàn chỉnh chu trình:
Traffic -> Detection -> Digital Twin -> RL Policy -> Sandbox -> Safety Validation -> Network Control -> Feedback
"""

import sys
import os
import argparse
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from digital_twin.rl_environment import CyberDefenseRLEnv, ThreatType, DefenseAction, ACTION_NAMES
from digital_twin.rl_agent import CyberDefenseRLAgent, train_rl_agent
from digital_twin.safety_controller import SafetyController
from digital_twin.network_controller import NetworkController
from digital_twin.engine import NetworkDigitalTwin


def run_demo(policy_file: str, train: bool = False, episodes: int = 150):
    print("=" * 75)
    print("   AERO DIGITAL TWIN & REINFORCEMENT LEARNING CYBER DEFENSE PIPELINE")
    print("=" * 75)

    if train or not os.path.isfile(policy_file):
        print(f"\n[Giai đoạn 1] Huấn luyện RL Defense Agent trong Sandbox ({episodes} episodes)...")
        agent = train_rl_agent(episodes=episodes, save_path=policy_file, use_dqn=False)
    else:
        print(f"\n[Giai đoạn 1] Nạp chính sách RL Agent đã huấn luyện: {policy_file}")
        agent = CyberDefenseRLAgent()
        agent.load_policy(policy_file)

    print("\n[Giai đoạn 2] Khởi tạo hệ thống Closed-Loop Sandbox & Safety Controller...")
    twin = NetworkDigitalTwin(name="Demo-Validation-Twin")
    safety = SafetyController()
    net_ctrl = NetworkController(dry_run=True)

    # Các kịch bản thử nghiệm
    scenarios = [
        (ThreatType.NORMAL, "Lưu lượng thông thường (Benign Traffic)", "192.168.1.50"),
        (ThreatType.SYN_FLOOD, "Tấn công SYN Flood 3.500 pkts/s", "192.168.1.199"),
        (ThreatType.UDP_FLOOD, "Tấn công UDP Volumetric Storm", "192.168.1.205"),
        (ThreatType.PORT_SCAN, "Quét cổng Nmap Reconnaissance", "192.168.1.210"),
        (ThreatType.DATA_EXFILTRATION, "Rò rỉ dữ liệu C2 Exfiltration", "192.168.1.215"),
        (ThreatType.ADVERSARIAL_GAN, "Tấn công đối kháng WGAN-GP Evasion", "192.168.1.220"),
    ]

    print("\n[Giai đoạn 3] Thử nghiệm ra quyết định phòng thủ tự động trên 6 kịch bản:")
    print("-" * 75)

    env = CyberDefenseRLEnv()

    for threat, desc, attacker_ip in scenarios:
        obs, info = env.reset(threat_type=threat)
        action_idx = agent.select_action(obs, evaluate=True)
        proposed_action = DefenseAction(action_idx)
        xai = agent.explain_decision(obs)

        # Kiểm định qua Safety Controller trong Sandbox
        decision, final_action, reason = safety.validate_action(
            proposed_action=proposed_action,
            target_ip=attacker_ip,
            twin_engine=twin
        )

        # Thực thi mô phỏng qua Network Controller
        net_ctrl.enforce_action(
            action=final_action,
            target_ip=attacker_ip,
            reason=reason
        )

        print(f"\n[*] KỊCH BẢN: {desc}")
        print(f"    - IP nguồn: {attacker_ip} | Loại đe dọa: {threat.name}")
        print(f"    - RL Đề xuất: {ACTION_NAMES[proposed_action]} (Độ tin cậy: {xai['confidence_pct']}%)")
        print(f"    - Phán quyết Safety Controller: [{decision.value}] -> Quyết định cuối: {ACTION_NAMES[final_action]}")
        print(f"    - XAI Giải thích: {xai['rational_explanation']}")
        time.sleep(0.3)

    print("\n" + "=" * 75)
    print("   HOÀN TẤT KIỂM THỬ PIPELINE DIGITAL TWIN + HỌC TĂNG CƯỜNG THÀNH CÔNG!")
    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(description="AERO Digital Twin & RL Defense Runner")
    parser.add_argument("--train", action="store_true", help="Kích hoạt huấn luyện RL Agent trước khi chạy")
    parser.add_argument("--episodes", type=int, default=150, help="Số episodes huấn luyện (mặc định: 150)")
    parser.add_argument("--policy", default="digital_twin/models/rl_defense_policy.json", help="Đường dẫn lưu/nạp policy")
    args = parser.parse_args()

    run_demo(args.policy, train=args.train, episodes=args.episodes)


if __name__ == "__main__":
    main()
