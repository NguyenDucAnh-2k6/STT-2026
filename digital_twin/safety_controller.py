"""
Safety Controller & Sandbox Validator
======================================
Module kiểm định an toàn (Safety Controller) theo kiến trúc:
    RL Policy -> Simulation (Digital Twin Sandbox) -> Safety Validation -> Network Control

Nhiệm vụ:
1. Đảm bảo RL Agent KHÔNG BAO GIỜ can thiệp vào các địa chỉ quan trọng (Whitelist Protection).
2. Thẩm định kết quả thử nghiệm trong Sandbox (Dry-run Sandbox Verification).
3. Đưa ra phán quyết: APPROVED (Duyệt), DOWNGRADED (Hạ cấp an toàn), hoặc REJECTED (Bác bỏ).
"""

import time
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple

from digital_twin.rl_environment import DefenseAction, ACTION_NAMES
from digital_twin.models import (
    MitigationPolicy,
    MitigationAction,
    DryRunReport,
    TwinSafetyVerdict
)
from digital_twin.engine import NetworkDigitalTwin


class SafetyDecision(str, Enum):
    APPROVED = "APPROVED"               # Đạt mọi tiêu chuẩn an toàn, cho phép thực thi lên mạng thật
    DOWNGRADED = "DOWNGRADED"           # Hạ cấp hành động (ví dụ: đổi từ BLOCK sang RATE_LIMIT để tránh rủi ro)
    REJECTED = "REJECTED"               # Từ chối thực thi do vi phạm an toàn / nguy cơ tổn hại cao


class SafetyController:
    """
    Bộ kiểm soát an toàn độc lập trước khi lệnh được chuyển tới Tường lửa máy chủ.
    """

    def __init__(
        self,
        whitelist_ips: Optional[Set[str]] = None,
        max_allowable_collateral_damage: float = 15.0,
        min_required_health_score: float = 0.65
    ):
        # Danh sách trắng bảo vệ tuyệt đối (Không bao giờ cho phép chặn)
        self.whitelist_ips: Set[str] = whitelist_ips or {
            "127.0.0.1",
            "localhost",
            "::1",
            "192.168.1.1",       # Router Gateway
            "192.168.1.100",     # Host PC Server
            "192.168.1.101",     # ESP32 Sniffer Probe
            "8.8.8.8",           # DNS Server
            "1.1.1.1"
        }
        self.max_collateral = max_allowable_collateral_damage
        self.min_health = min_required_health_score
        self.validation_history: List[Dict[str, Any]] = []

    def validate_action(
        self,
        proposed_action: DefenseAction,
        target_ip: str,
        twin_engine: NetworkDigitalTwin,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[SafetyDecision, DefenseAction, str]:
        """
        Kiểm định toàn diện hành động phòng thủ:
        1. Kiểm tra Whitelist
        2. Chạy thử nghiệm Sandbox (Twin Dry-run)
        3. Phán quyết an toàn
        """
        target_clean = str(target_ip).strip()

        # 1. KIỂM TRA BẢO VỆ WHITELIST
        if target_clean in self.whitelist_ips:
            if proposed_action in (DefenseAction.BLOCK_IP_FIREWALL, DefenseAction.ISOLATE_MAC_DEAUTH):
                reason = f"BÁC BỎ: Mục tiêu {target_clean} nằm trong Whitelist mạng bảo vệ! Tuyệt đối không chặn."
                self._record_decision(proposed_action, DefenseAction.NO_ACTION, SafetyDecision.REJECTED, reason)
                return SafetyDecision.REJECTED, DefenseAction.NO_ACTION, reason

        # Nếu là NO_ACTION thì luôn an toàn
        if proposed_action == DefenseAction.NO_ACTION:
            return SafetyDecision.APPROVED, DefenseAction.NO_ACTION, "Hành động duy trì an toàn."

        # 2. KIỂM ĐỊNH DRY-RUN TRONG SANDBOX CỦA DIGITAL TWIN
        # Chuyển đổi thành policy kiểm thử
        test_policy = MitigationPolicy(
            action=MitigationAction.BLOCK_MAC if proposed_action == DefenseAction.BLOCK_IP_FIREWALL else MitigationAction.RATE_LIMIT_IP,
            target_identifier=target_clean,
            parameter_value=25000.0 if proposed_action == DefenseAction.RATE_LIMIT_IP else None
        )

        dry_run_report: DryRunReport = twin_engine.evaluate_mitigation_policy_dry_run(test_policy, duration_sec=2.0)

        # 3. ĐÁNH GIÁ TIÊU CHUẨN AN TOÀN
        # Nếu tổn hại phụ (Collateral Damage) vượt ngưỡng cho phép:
        if dry_run_report.collateral_damage_pct > self.max_collateral:
            # Nếu hành động ban đầu là Chặn IP, thử hạ cấp xuống Siết băng thông (Rate-Limit)
            if proposed_action == DefenseAction.BLOCK_IP_FIREWALL:
                downgraded_action = DefenseAction.RATE_LIMIT_IP
                reason = (
                    f"HẠ CẤP: Chặn IP gây tổn hại thiết bị phụ ({dry_run_report.collateral_damage_pct:.1f}% > {self.max_collateral}%). "
                    f"Tự động chuyển sang Siết băng thông (RATE_LIMIT_IP)."
                )
                self._record_decision(proposed_action, downgraded_action, SafetyDecision.DOWNGRADED, reason, dry_run_report)
                return SafetyDecision.DOWNGRADED, downgraded_action, reason
            else:
                reason = f"BÁC BỎ: Rủi ro tổn hại ngoài ý muốn quá lớn ({dry_run_report.collateral_damage_pct:.1f}%)."
                self._record_decision(proposed_action, DefenseAction.NO_ACTION, SafetyDecision.REJECTED, reason, dry_run_report)
                return SafetyDecision.REJECTED, DefenseAction.NO_ACTION, reason

        # Nếu sức khỏe mạng quá thấp hoặc không hiệu quả
        if dry_run_report.network_health_score < self.min_health:
            reason = f"BÁC BỎ: Điểm sức khỏe mạng sau can thiệp không đạt chuẩn ({dry_run_report.network_health_score:.2f} < {self.min_health})."
            self._record_decision(proposed_action, DefenseAction.NO_ACTION, SafetyDecision.REJECTED, reason, dry_run_report)
            return SafetyDecision.REJECTED, DefenseAction.NO_ACTION, reason

        # Phê duyệt thành công
        reason = (
            f"PHÊ DUYỆT: An toàn tuyệt đối qua kiểm định Sandbox "
            f"(Dập tắt: {dry_run_report.attack_suppressed_pct:.1f}%, Tổn hại phụ: {dry_run_report.collateral_damage_pct:.1f}%)."
        )
        self._record_decision(proposed_action, proposed_action, SafetyDecision.APPROVED, reason, dry_run_report)
        return SafetyDecision.APPROVED, proposed_action, reason

    def _record_decision(
        self,
        original_action: DefenseAction,
        final_action: DefenseAction,
        decision: SafetyDecision,
        reason: str,
        report: Optional[DryRunReport] = None
    ):
        """Ghi nhật ký thẩm duyệt an toàn."""
        self.validation_history.append({
            "timestamp": time.time(),
            "original_action": ACTION_NAMES[original_action],
            "final_action": ACTION_NAMES[final_action],
            "decision": decision.value,
            "reason": reason,
            "attack_suppressed": report.attack_suppressed_pct if report else None,
            "collateral_damage": report.collateral_damage_pct if report else None
        })
        if len(self.validation_history) > 500:
            self.validation_history.pop(0)
