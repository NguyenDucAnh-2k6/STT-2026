"""
Launcher Network Utilities
==========================
Cung cấp các hàm phát hiện IP LAN, tự động nhận diện thông tin WiFi (Zero-Config)
trên Windows/Linux/macOS, đồng bộ thông tin mạng vào .env và firmware/credentials.h,
và kiểm tra cổng mạng khả dụng.
"""

import os
import sys
import re
import socket
import subprocess
from typing import Optional, Tuple


def detect_host_lan_ip(preferred_iface: Optional[str] = None) -> str:
    """Tự động phát hiện chính xác địa chỉ IPv4 LAN nội bộ của card Wi-Fi/Ethernet máy tính."""
    # 1. Windows: Thử truy vấn IP trực tiếp từ card Wi-Fi đang hoạt động
    if sys.platform == "win32":
        try:
            target_iface = preferred_iface
            if not target_iface:
                out_if = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, errors="ignore")
                m = re.search(r"^\s*Name\s*:\s*(.+)$", out_if, re.M)
                if m:
                    target_iface = m.group(1).strip()
            if target_iface:
                out_addr = subprocess.check_output(f'netsh interface ipv4 show addresses "{target_iface}"', shell=True, text=True, errors="ignore")
                m_ip = re.search(r"IP Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out_addr)
                if m_ip:
                    return m_ip.group(1).strip()
        except Exception:
            pass

    # 2. Linux: Lấy IP qua nmcli thiết bị mạng wifi
    elif sys.platform.startswith("linux"):
        import shutil
        if shutil.which("nmcli"):
            try:
                out = subprocess.check_output(["nmcli", "-g", "IP4.ADDRESS", "device", "show"], text=True, errors="ignore")
                for line in out.splitlines():
                    val = line.split("/")[0].strip()
                    if val and not val.startswith("127."):
                        return val
            except Exception:
                pass

    # 3. macOS: Lấy IP qua ipconfig trên các interface en0/en1
    elif sys.platform == "darwin":
        for iface in ["en0", "en1"]:
            try:
                out = subprocess.check_output(["ipconfig", "getifaddr", iface], text=True, errors="ignore").strip()
                if out and not out.startswith("127."):
                    return out
            except Exception:
                pass

    # 4. Fallback qua UDP socket routing table
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def auto_detect_wifi_credentials() -> Tuple[Optional[str], Optional[str], str]:
    """
    Tự động trích xuất SSID, Mật khẩu WiFi và IPv4 máy tính ngầm (Zero-Config)
    trên Windows (netsh), Linux (nmcli), macOS (airport / networksetup).
    Không yêu cầu người dùng phải tự gõ vào .env hay credentials.h.
    """
    ssid = None
    password = None
    host_ip = "127.0.0.1"

    # 1. Windows: sử dụng lệnh netsh wlan
    if sys.platform == "win32":
        try:
            out_if = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, errors="ignore")
            m_iface = re.search(r"^\s*Name\s*:\s*(.+)$", out_if, re.M)
            iface_name = m_iface.group(1).strip() if m_iface else None
            host_ip = detect_host_lan_ip(iface_name)

            for line in out_if.splitlines():
                line = line.strip()
                if line.startswith("SSID") and not line.startswith("SSID name") and not line.startswith("BSSID"):
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        ssid = parts[1].strip()
                        break

            if ssid:
                out_prof = subprocess.check_output(f'netsh wlan show profile name="{ssid}" key=clear', shell=True, text=True, errors="ignore")
                for line in out_prof.splitlines():
                    line = line.strip()
                    if "Key Content" in line or "Nội dung khóa" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2 and parts[1].strip():
                            password = parts[1].strip()
                            break
        except Exception:
            pass

    # 2. Linux: sử dụng nmcli (NetworkManager)
    elif sys.platform.startswith("linux"):
        import shutil
        if shutil.which("nmcli"):
            try:
                out_active = subprocess.check_output(
                    ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                    text=True, errors="ignore"
                )
                for line in out_active.splitlines():
                    line = line.strip()
                    if line.startswith("yes:"):
                        ssid = line.split(":", 1)[1].strip()
                        break
                if ssid:
                    out_sec = subprocess.check_output(
                        ["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", ssid],
                        text=True, errors="ignore"
                    )
                    psk = out_sec.strip()
                    if psk:
                        password = psk
            except Exception:
                pass

    # 3. macOS: sử dụng airport tool hoặc networksetup
    elif sys.platform == "darwin":
        import shutil
        try:
            airport_bin = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_bin):
                out = subprocess.check_output([airport_bin, "-I"], text=True, errors="ignore")
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("SSID:"):
                        ssid = line.split(":", 1)[1].strip()
                        break
            if not ssid and shutil.which("networksetup"):
                out = subprocess.check_output(["networksetup", "-getairportnetwork", "en0"], text=True, errors="ignore")
                if "Current Wi-Fi Network:" in out:
                    ssid = out.split(":", 1)[1].strip()

            if ssid and shutil.which("security"):
                out_sec = subprocess.check_output(
                    ["security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w"],
                    text=True, errors="ignore"
                )
                pwd = out_sec.strip()
                if pwd:
                    password = pwd
        except Exception:
            pass

    return ssid, password, host_ip


def update_env_file(root_dir: str, wifi_ssid: str, wifi_pass: str, mqtt_host: str):
    """Tự động đồng bộ các giá trị mạng phát hiện được vào file .env."""
    env_path = os.path.join(root_dir, ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    keys_set = set()
    new_lines = []
    for line in lines:
        if line.strip().startswith("WIFI_SSID="):
            new_lines.append(f'WIFI_SSID="{wifi_ssid}"\n')
            keys_set.add("WIFI_SSID")
        elif line.strip().startswith("WIFI_PASSWORD="):
            new_lines.append(f'WIFI_PASSWORD="{wifi_pass}"\n')
            keys_set.add("WIFI_PASSWORD")
        elif line.strip().startswith("MQTT_BROKER_HOST=") or line.strip().startswith("MQTT_HOST="):
            new_lines.append(f'MQTT_BROKER_HOST="{mqtt_host}"\n')
            keys_set.add("MQTT_BROKER_HOST")
        else:
            new_lines.append(line)

    if "WIFI_SSID" not in keys_set:
        new_lines.append(f'WIFI_SSID="{wifi_ssid}"\n')
    if "WIFI_PASSWORD" not in keys_set:
        new_lines.append(f'WIFI_PASSWORD="{wifi_pass}"\n')
    if "MQTT_BROKER_HOST" not in keys_set:
        new_lines.append(f'MQTT_BROKER_HOST="{mqtt_host}"\n')

    try:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception:
        pass


def sync_env_to_firmware(root_dir: str):
    """Đồng bộ tự động WiFi SSID/Password và MQTT IP từ thông tin mạng thực tế vào credentials.h và .env."""
    credentials_path = os.path.join(root_dir, "firmware", "esp32_probe", "credentials.h")
    if not os.path.exists(credentials_path):
        return

    # 1. Tự động phát hiện thông tin mạng thực tế hiện tại (Zero-Config)
    detected_ssid, detected_pwd, detected_ip = auto_detect_wifi_credentials()

    # Luôn ưu tiên thông tin mạng thực tế mà card mạng đang kết nối hiện tại
    wifi_ssid = detected_ssid or os.getenv("WIFI_SSID")
    wifi_pass = detected_pwd or os.getenv("WIFI_PASSWORD")

    # Đối với IP máy chủ MQTT phục vụ ESP32, ưu tiên địa chỉ IP LAN thực tế hiện tại
    if detected_ip and detected_ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
        mqtt_host = detected_ip
    else:
        mqtt_host = os.getenv("MQTT_HOST") or os.getenv("MQTT_BROKER_HOST") or "127.0.0.1"

    # Tự động cập nhật lại vào .env để các file khác luôn đồng bộ theo mạng mới nhất
    if wifi_ssid and wifi_pass and mqtt_host:
        update_env_file(root_dir, wifi_ssid, wifi_pass, mqtt_host)

    if not (wifi_ssid and wifi_pass and mqtt_host):
        return

    try:
        with open(credentials_path, "r", encoding="utf-8") as f:
            content = f.read()

        content = re.sub(r'#define WIFI_SSID ".*?"', f'#define WIFI_SSID "{wifi_ssid}"', content)
        content = re.sub(r'#define WIFI_PASSWORD ".*?"', f'#define WIFI_PASSWORD "{wifi_pass}"', content)
        content = re.sub(r'#define MQTT_BROKER_HOST ".*?"', f'#define MQTT_BROKER_HOST "{mqtt_host}"', content)

        with open(credentials_path, "w", encoding="utf-8") as f:
            f.write(content)
        pwd_mask = f"{wifi_pass[:3]}***" if len(wifi_pass) > 3 else "***"
        print(f"  -> Da dong bo cau hinh WiFi/MQTT tu dong vao {os.path.relpath(credentials_path, root_dir)}:")
        print(f"     * WIFI_SSID        : \"{wifi_ssid}\" (Tu dong)")
        print(f"     * WIFI_PASSWORD    : \"{pwd_mask}\" (Tu dong)")
    except Exception as e:
        print(f"  [Canh bao] Khong the dong bo credentials.h: {e}")


def check_port_in_use(port: int) -> bool:
    """Kiểm tra xem một cổng mạng TCP đã có tiến trình nào chiếm dụng hay chưa."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0
