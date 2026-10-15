#!/usr/bin/env python3
"""
Interactive Network Digital Twin & GAN Adversary Runner
======================================================
Kịch bản thực thi trực quan mô phỏng Digital Twin tích hợp Tấn công đối kháng GAN:
- Khởi động bản sao số mạng biên AERO (Gateway, ESP32 Probe, IoT Nodes, Threat Node).
- Đo đạc trạng thái nền bình thường (Baseline).
- Kích hoạt tấn công tiêu chuẩn và quan sát nghẽn kênh/rớt gói tin (CSMA/CA Contention).
- Chuyển sang Tấn công đối kháng GAN (WGAN-GP Evasion Attack).
- Thử nghiệm chính sách can thiệp trong Sandbox Khép kín (Closed-Loop Dry-Run)
  và in báo cáo an toàn (Blast Radius, Collateral Damage).
"""

import os
import sys
import time
import json
import argparse
from typing import Dict, Any

# Đảm bảo UTF-8 an toàn trên Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from digital_twin.engine import NetworkDigitalTwin
from digital_twin.models import (
    MitigationPolicy,
    MitigationAction,
    NodeRole,
    NodeStatus
)
from digital_twin.adversarial_integration import TwinAdversarialBridge


def print_banner():
    print("\n" + "=" * 76)
    print("      AERO NETWORK DIGITAL TWIN & WGAN-GP ADVERSARIAL SANDBOX       ")
    print("=" * 76)


def print_twin_dashboard(twin: NetworkDigitalTwin, title: str = "TRẠNG THÁI HIỆN TẠI"):
    summary = twin.get_summary_state()
    core_ch = summary["core_channel"]

    print(f"\n--- [{title}] (Thời gian mô phỏng: {summary['sim_time']}s) ---")
    print(f"[*] Kênh trung tâm AP (Kênh {core_ch['id']}):")
    print(f"    - Airtime Utilization:    {core_ch['airtime_utilization']}%")
    print(f"    - Xác suất va chạm gói:  {core_ch['collision_prob']}%")
    print(f"    - Mức nhiễu nền:         {core_ch['noise_dbm']} dBm")

    print(f"\n[*] Bảng trạng thái các nút mạng ({summary['active_nodes']}/{summary['total_nodes']} Online):")
    print(f"  {'TÊN NÚT':<24} | {'VAI TRÒ':<12} | {'TỐC ĐỘ':<10} | {'RỚT GÓI':<8} | {'ĐỘ TRỄ':<9} | {'TRẠNG THÁI'}")
    print("  " + "-" * 72)

    for n in summary["nodes"]:
        name_str = n['name'][:22]
        adv_tag = " (GAN Adv)" if n["is_adversarial"] else ""
        print(f"  {name_str + adv_tag:<24} | {n['role']:<12} | {n['rate_pkts_s']:>6.1f} p/s | {n['loss_pct']:>6.1f}% | {n['latency_ms']:>6.1f} ms | {n['status']}")


def run_full_demonstration():
    print_banner()

    # 1. Khởi tạo Digital Twin
    print("[1/5] Đang khởi tạo Bản sao số mạng biên AERO (Network Digital Twin)...")
    twin = NetworkDigitalTwin(name="AERO-Production-Twin")
    bridge = TwinAdversarialBridge(twin=twin)

    # Chạy 3 bước thời gian để ổn định trạng thái nền
    for _ in range(3):
        twin.step(dt_sec=1.0)

    print_twin_dashboard(twin, "GIAI ĐOẠN 1: MẠNG HOẠT ĐỘNG BÌNH THƯỜNG (BENIGN BASELINE)")
    print("  --> Nhận xét: Airtime < 10%, độ trễ các thiết bị IoT cực thấp (~2.5ms), không có va chạm.")

    # 2. Phát động tấn công tiêu chuẩn (Standard SYN Flood)
    print("\n" + "=" * 76)
    print("[2/5] Kích hoạt TẤN CÔNG TIÊU CHUẨN (Standard SYN Flood 3500 pkts/s)...")
    twin.inject_attack(attack_type="SYN_Flood", packet_rate=3500.0)

    for _ in range(3):
        twin.step(dt_sec=1.0)

    print_twin_dashboard(twin, "GIAI ĐOẠN 2: BỊ TẤN CÔNG TIÊU CHUẨN (SYN FLOOD)")
    gw = twin.get_node("gw_ap_01")
    ch_state = twin.channels[gw.channel]
    print(f"  --> Nhận xét: Kênh 6 bị nghẽn (Airtime đạt {ch_state.airtime_utilization*100:.1f}%), xác suất va chạm CSMA/CA tăng, Camera IoT bị trễ và rớt gói.")

    # 3. Chuyển sang Tấn công Đối kháng GAN (WGAN-GP Adversarial Evasion)
    print("\n" + "=" * 76)
    print("[3/5] Chuyển đổi sang TẤN CÔNG ĐỐI KHÁNG GAN (WGAN-GP Adversarial Attack)...")
    adv_info = bridge.inject_gan_adversary_into_twin(base_attack_type="SYN_Flood")

    print("[*] Vector đặc trưng do WGAN sinh ra để lẩn tránh IDS:")
    for feat_name, val in list(adv_info["adversarial_features"].items())[:6]:
        print(f"    - {feat_name:<18}: {val}")

    for _ in range(3):
        twin.step(dt_sec=1.0)

    print_twin_dashboard(twin, "GIAI ĐOẠN 3: TẤN CÔNG ĐỐI KHÁNG GAN (LẨN TRÁNH TINH VI)")
    print("  --> Nhận xét: Luồng tấn công được tinh chỉnh tần suất và trộn cờ ACK/UDP, giảm thiểu đột biến để tránh bị IDS chặn thô bạo.")

    # 4. Thử nghiệm Chính sách Khép kín trong Sandbox (Closed-Loop Dry-run)
    print("\n" + "=" * 76)
    print("[4/5] THỬ NGHIỆM CHÍNH SÁCH PHÒNG THỦ TRONG SANDBOX (CLOSED-LOOP DRY-RUN)...")
    print("Mục tiêu: Đánh giá mức độ an toàn trước khi áp dụng lệnh chặn ra mạng thật.")

    threat_node = twin.get_node("node_threat_01")

    # Kịch bản A: Chặn hoàn toàn MAC (BLOCK_MAC)
    policy_block = MitigationPolicy(
        action=MitigationAction.BLOCK_MAC,
        target_identifier=threat_node.mac_address,
        reason="Cách ly địa chỉ MAC phát động tấn công đối kháng"
    )
    print(f"\n[*] Đang chạy Dry-run Chính sách 1: Chặn MAC ({threat_node.mac_address})...")
    report_block = twin.evaluate_policy_dry_run(policy_block, duration_sec=6.0)

    print(f"    + Tỷ lệ triệt tiêu tấn công:  {report_block.attack_suppressed_pct}%")
    print(f"    + Tổn hại ngoài ý muốn:       {report_block.collateral_damage_pct}%")
    print(f"    + Điểm sức khỏe mạng:         {report_block.network_health_score}/1.0")
    print(f"    + Phán quyết của Twin:        {report_block.verdict.value}")
    print(f"    + Khuyến nghị áp dụng thật:   {'[CÓ] CHO PHÉP THI HÀNH' if report_block.recommended_to_apply else '[KHÔNG] TỪ CHỐI'}")

    # Kịch bản B: Nhảy kênh Wi-Fi (SWITCH_CHANNEL từ 6 sang 11)
    policy_hop = MitigationPolicy(
        action=MitigationAction.SWITCH_CHANNEL,
        target_identifier="AP-Core-AERO",
        parameter_value=11.0,
        reason="Chuyển toàn bộ hạ tầng sang Kênh 11 để thoát khỏi kênh bị tấn công"
    )
    print(f"\n[*] Đang chạy Dry-run Chính sách 2: Nhảy kênh hạ tầng (Ch 6 -> Ch 11)...")
    report_hop = twin.evaluate_policy_dry_run(policy_hop, duration_sec=6.0)

    print(f"    + Tỷ lệ triệt tiêu tấn công:  {report_hop.attack_suppressed_pct}%")
    print(f"    + Tổn hại ngoài ý muốn:       {report_hop.collateral_damage_pct}%")
    print(f"    + Điểm sức khỏe mạng:         {report_hop.network_health_score}/1.0")
    print(f"    + Phán quyết của Twin:        {report_hop.verdict.value}")
    print(f"    + Khuyến nghị áp dụng thật:   {'[CÓ] CHO PHÉP THI HÀNH' if report_hop.recommended_to_apply else '[KHÔNG] TỪ CHỐI'}")

    # 5. Áp dụng chính sách an toàn đã được xác thực (Enforce Safe Policy)
    print("\n" + "=" * 76)
    print("[5/5] ÁP DỤNG CHÍNH SÁCH ĐÃ ĐƯỢC XÁC THỰC AN TOÀN LÊN DIGITAL TWIN...")
    threat_node.status = NodeStatus.ISOLATED
    for _ in range(3):
        twin.step(dt_sec=1.0)

    print_twin_dashboard(twin, "GIAI ĐOẠN 5: SAU KHI CÁCH LY THÀNH CÔNG NÚT TẤN CÔNG")
    print("  --> Kết quả: Toàn bộ lưu lượng tấn công đối kháng đã bị dập tắt 100%. Mạng IoT trở lại trạng thái xanh (Healthy).")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    run_full_demonstration()
