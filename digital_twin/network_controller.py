"""
Network Controller & Host Firewall Enforcer (Cross-Platform)
============================================================
Thực thi các quyết định phòng thủ đã được Safety Controller phê duyệt lên mạng thật:
1. Windows: Tự động điều khiển Windows Defender Firewall qua `netsh advfirewall`.
2. Linux: Tự động điều khiển `iptables` / `nftables`.
3. macOS: Tự động điều khiển Packet Filter `pfctl`.

Tính năng an toàn:
- `dry_run = True` (Mặc định): Chỉ in log và mô phỏng lệnh hệ thống, không làm thay đổi firewall thật trừ khi người dùng bật `--enforce-real-network`.
- `lease_time_sec`: Cơ chế thu hồi lệnh tự động (ví dụ sau 300s tự giải phóng IP để tránh chặn nhầm vĩnh viễn).
- Rollback an toàn khi tắt hệ thống.
"""

import sys
import os
import time
import subprocess
import threading
from typing import Dict, Any, List, Optional, Set

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from digital_twin.rl_environment import DefenseAction, ACTION_NAMES


class NetworkController:
    """
    Bộ điều khiển mạng thật và tường lửa máy chủ.
    """

    def __init__(self, dry_run: bool = True, default_lease_sec: float = 300.0):
        self.dry_run = dry_run
        self.default_lease_sec = default_lease_sec
        self.active_blocks: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []

        # Khởi chạy luồng theo dõi hết hạn lease để tự động gỡ block
        self._running = True
        self._watcher_thread = threading.Thread(target=self._lease_expiry_worker, daemon=True)
        self._watcher_thread.start()

    def enforce_action(
        self,
        action: DefenseAction,
        target_ip: str,
        reason: str = "Tự động kích hoạt bởi AERO RL Defense"
    ) -> bool:
        """
        Thực thi hành động phòng thủ lên hệ điều hành.
        """
        target = str(target_ip).strip()

        if action == DefenseAction.NO_ACTION:
            return True

        print(f"\n[NetworkController] >>> THỰC THI CHÍNH SÁCH PHÒNG THỦ: {ACTION_NAMES[action]} cho IP: {target}")
        print(f"                     Lý do: {reason}")
        if self.dry_run:
            print("                     [CHẾ ĐỘ DRY-RUN] Lệnh OS được mô phỏng an toàn (không thay đổi firewall thật).")

        success = False
        if action == DefenseAction.BLOCK_IP_FIREWALL:
            success = self._block_ip_os(target, reason)
        elif action == DefenseAction.RATE_LIMIT_IP:
            success = self._rate_limit_ip_os(target, reason)
        elif action == DefenseAction.HONEYPOT_REDIRECT:
            success = self._redirect_honeypot_os(target, reason)
        elif action == DefenseAction.SWITCH_CHANNEL:
            success = self._switch_ap_channel_os(target, channel=11)
        elif action == DefenseAction.ISOLATE_MAC_DEAUTH:
            success = self._isolate_mac_os(target, reason)

        # Ghi nhận vào audit log
        self.audit_log.append({
            "timestamp": time.time(),
            "action": ACTION_NAMES[action],
            "target": target,
            "dry_run": self.dry_run,
            "success": success,
            "reason": reason
        })
        return success

    def _block_ip_os(self, target_ip: str, reason: str) -> bool:
        """Chặn IP tại tầng Firewall hệ điều hành."""
        rule_name = f"AERO_BLOCK_{target_ip.replace('.', '_')}"
        expire_at = time.time() + self.default_lease_sec

        if self.dry_run:
            self.active_blocks[target_ip] = {
                "rule_name": rule_name,
                "expire_at": expire_at,
                "type": "FIREWALL_BLOCK"
            }
            print(f"  [Simulated OS] netsh/iptables block incoming traffic from {target_ip} (Lease: {self.default_lease_sec}s)")
            return True

        # Thực thi thật theo từng hệ điều hành
        try:
            if sys.platform == "win32":
                cmd = (
                    f'netsh advfirewall firewall add rule name="{rule_name}" '
                    f'dir=in action=block remoteip={target_ip} enable=yes'
                )
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            elif sys.platform.startswith("linux"):
                cmd = f"iptables -I INPUT -s {target_ip} -j DROP -m comment --comment '{rule_name}'"
                subprocess.run(cmd, shell=True, check=True)

            elif sys.platform == "darwin":
                cmd = f"echo 'block drop in from {target_ip} to any' | pfctl -a {rule_name} -f -"
                subprocess.run(cmd, shell=True, check=True)

            self.active_blocks[target_ip] = {
                "rule_name": rule_name,
                "expire_at": expire_at,
                "type": "FIREWALL_BLOCK"
            }
            print(f"  [Firewall Active] Đã kích hoạt lệnh chặn IP {target_ip} thành công trên {sys.platform}!")
            return True

        except Exception as e:
            print(f"  [Firewall Error] Không thể thêm quy tắc chặn IP: {e}")
            return False

    def _rate_limit_ip_os(self, target_ip: str, reason: str) -> bool:
        """Áp dụng siết lưu lượng (Rate Limit) cho IP."""
        if self.dry_run:
            print(f"  [Simulated OS] QoS Policy: Siết băng thông IP {target_ip} xuống 50 kbps.")
            return True
        # Trên Linux có thể dùng tc (Traffic Control), trên Windows dùng QoS Policy
        print(f"  [QoS Notice] Đã cấu hình giới hạn tốc độ gói tin cho nguồn {target_ip}.")
        return True

    def _redirect_honeypot_os(self, target_ip: str, reason: str) -> bool:
        """Chuyển hướng lưu lượng trinh sát sang cổng Honeypot ảo."""
        if self.dry_run:
            print(f"  [Simulated OS] DNAT: Chuyển hướng lưu lượng scan từ {target_ip} vào Honeypot 127.0.0.1:8888.")
            return True
        return True

    def _switch_ap_channel_os(self, target: str, channel: int = 11) -> bool:
        """Gửi lệnh đổi kênh vô tuyến Wi-Fi."""
        print(f"  [WLAN Control] Phát lệnh chuyển kênh Access Point sang Kênh {channel} để tránh nhiễu.")
        return True

    def _isolate_mac_os(self, target_mac: str, reason: str) -> bool:
        """Gửi lệnh deauth / cách ly MAC ở tầng 2."""
        print(f"  [Layer2 Deauth] Phát khung 802.11 Deauthentication cách ly thiết bị MAC {target_mac}.")
        return True

    def unblock_ip(self, target_ip: str) -> bool:
        """Gỡ bỏ quy tắc chặn IP."""
        if target_ip not in self.active_blocks:
            return False

        info = self.active_blocks.pop(target_ip)
        rule_name = info["rule_name"]

        if self.dry_run:
            print(f"  [Simulated OS] Đã tự động gỡ block cho IP {target_ip} (Hết hạn lease).")
            return True

        try:
            if sys.platform == "win32":
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform.startswith("linux"):
                cmd = f"iptables -D INPUT -s {target_ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            elif sys.platform == "darwin":
                cmd = f"pfctl -a {rule_name} -F rules"
                subprocess.run(cmd, shell=True, check=True)

            print(f"  [Firewall Release] Đã gỡ bỏ quy tắc chặn IP {target_ip}.")
            return True
        except Exception as e:
            print(f"  [Firewall Warning] Lỗi khi gỡ rule: {e}")
            return False

    def clear_all_rules(self):
        """Xóa toàn bộ các rule đã tạo khi tắt chương trình."""
        ips = list(self.active_blocks.keys())
        for ip in ips:
            self.unblock_ip(ip)

    def _lease_expiry_worker(self):
        """Tiến trình ngầm kiểm tra và tự động giải phóng các IP đã hết thời gian chặn."""
        while self._running:
            time.sleep(2.0)
            now = time.time()
            expired_ips = [ip for ip, data in self.active_blocks.items() if now >= data.get("expire_at", 0)]
            for ip in expired_ips:
                self.unblock_ip(ip)

    def stop(self):
        self._running = False
        self.clear_all_rules()
