"""
Launcher Network Utilities
==========================
Cung cấp các hàm phát hiện IP LAN, tự động nhận diện thông tin WiFi (Zero-Config)
trên Windows/Linux/macOS, đồng bộ thông tin mạng vào .env và firmware/credentials.h,
và kiểm tra cổng mạng khả dụng.
"""

import os
import json
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
                out_if = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, errors="ignore")
                m = re.search(r"^\s*Name\s*:\s*(.+)$", out_if, re.M)
                if m:
                    target_iface = m.group(1).strip()
            if target_iface:
                out_addr = subprocess.check_output(["netsh", "interface", "ipv4", "show", "addresses", target_iface], text=True, errors="ignore")
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
            out_if = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, errors="ignore")
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
                out_prof = subprocess.check_output(["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"], text=True, errors="ignore")
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


def update_env_file(root_dir: str, wifi_ssid: str, wifi_pass: str, mqtt_host: str, mqtt_port: Optional[int] = None):
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
        elif mqtt_port is not None and (line.strip().startswith("MQTT_BROKER_PORT=") or line.strip().startswith("MQTT_PORT=")):
            new_lines.append(f'MQTT_BROKER_PORT={mqtt_port}\n')
            keys_set.add("MQTT_BROKER_PORT")
        else:
            new_lines.append(line)

    if "WIFI_SSID" not in keys_set:
        new_lines.append(f'WIFI_SSID="{wifi_ssid}"\n')
    if "WIFI_PASSWORD" not in keys_set:
        new_lines.append(f'WIFI_PASSWORD="{wifi_pass}"\n')
    if "MQTT_BROKER_HOST" not in keys_set:
        new_lines.append(f'MQTT_BROKER_HOST="{mqtt_host}"\n')
    if mqtt_port is not None and "MQTT_BROKER_PORT" not in keys_set:
        new_lines.append(f'MQTT_BROKER_PORT={mqtt_port}\n')

    try:
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception:
        pass


def sync_env_to_firmware(root_dir: str) -> None:
    """Generate ignored build credentials; explicit configuration takes priority."""
    credentials_path = os.path.join(root_dir, "firmware", "esp32_probe", "credentials.h")
    wifi_ssid = os.getenv("WIFI_SSID", "")
    wifi_pass = os.getenv("WIFI_PASSWORD", "")
    mqtt_host = os.getenv("MQTT_BROKER_HOST") or os.getenv("MQTT_HOST", "")
    port = int(os.getenv("MQTT_BROKER_PORT", "1883"))
    if not 1 <= port <= 65535:
        raise ValueError("MQTT_BROKER_PORT must be between 1 and 65535")
    if not wifi_ssid or not mqtt_host:
        raise ValueError("ESP32 requires WIFI_SSID and a reachable MQTT_BROKER_HOST in .env")
    values = {"WIFI_SSID": wifi_ssid, "WIFI_PASSWORD": wifi_pass,
              "MQTT_BROKER_HOST": mqtt_host,
              "MQTT_CLIENT_ID": os.getenv("MQTT_CLIENT_ID", "ESP32-EdgeProbe-01")}
    content = "// Generated from local .env. Recompile and flash after changes.\n#pragma once\n"
    content += "".join(f"#define {key} {json.dumps(value, ensure_ascii=True)}\n" for key, value in values.items())
    content += f"#define MQTT_BROKER_PORT {port}\n"
    content += "#define MQTT_AUTO_DISCOVERY " + ("1" if os.getenv("MQTT_AUTO_DISCOVERY", "false").lower() == "true" else "0") + "\n"
    with open(credentials_path, "w", encoding="utf-8") as stream:
        stream.write(content)
    print("  -> Generated local ESP32 credentials from configuration (secrets omitted).")


def resolve_esp32_zero_config(root_dir: str, requested_port: int = 1883,
                             manual_ssid: Optional[str] = None,
                             manual_pwd: Optional[str] = None) -> Tuple[str, str, str, int]:
    """
    Xác định toàn bộ thông số cấu hình mạng ngầm cho ESP32:
    1. Ưu tiên lấy SSID & Password nếu người dùng truyền thủ công.
    2. Nếu không truyền: Tự động lấy SSID & Password của Wi-Fi máy tính đang kết nối.
    3. Tự động lấy IPv4 LAN thực tế của card Wi-Fi máy tính.
    4. Tự động chọn cổng MQTT thông minh (Smart Port Selection).
    5. Tự động đồng bộ vào firmware credentials.h và file .env.
    """
    from broker.manager import check_port_open, check_mqtt_ready

    # 1. Xác định thông tin Wi-Fi
    if manual_ssid:
        wifi_ssid = manual_ssid
        wifi_pass = manual_pwd if manual_pwd is not None else ""
        detected_ip = detect_host_lan_ip()
    else:
        detected_ssid, detected_pwd, detected_ip = auto_detect_wifi_credentials()
        wifi_ssid = detected_ssid or os.getenv("WIFI_SSID", "")
        wifi_pass = detected_pwd or os.getenv("WIFI_PASSWORD", "")
    mqtt_host = detected_ip or detect_host_lan_ip()

    if not mqtt_host or mqtt_host in ("127.0.0.1", "localhost", "0.0.0.0"):
        mqtt_host = detect_host_lan_ip()

    # 2. Lựa chọn cổng MQTT thông minh (Smart Port Selection)
    final_port = requested_port
    if requested_port == 1883 and mqtt_host not in ("127.0.0.1", "localhost", "0.0.0.0"):
        if check_port_open(1883, "127.0.0.1"):
            if not check_mqtt_ready(1883, mqtt_host):
                final_port = 1884
                print("=" * 70)
                print("  [Auto-Config] Cong 1883 dang bi chiem boi dich vu Localhost-Only (127.0.0.1).")
                print(f"  -> Tu dong chuyen sang cong {final_port} de mo toan mang LAN ({mqtt_host}) cho ESP32.")
                print("=" * 70)

    # 3. Cập nhật biến môi trường runtime
    os.environ["WIFI_SSID"] = wifi_ssid
    os.environ["WIFI_PASSWORD"] = wifi_pass
    os.environ["MQTT_BROKER_HOST"] = mqtt_host
    os.environ["MQTT_BROKER_PORT"] = str(final_port)

    # 4. Ghi ngầm vào file .env và firmware/esp32_probe/credentials.h
    update_env_file(root_dir, wifi_ssid, wifi_pass, mqtt_host, final_port)
    sync_env_to_firmware(root_dir)

    print(f"  [Auto-Config] Thong so Wi-Fi/MQTT tu dong nhan dien:")
    print(f"     * Wi-Fi SSID : '{wifi_ssid}'")
    print(f"     * Host LAN IP: {mqtt_host}")
    print(f"     * Broker Port: {final_port}")

    return wifi_ssid, wifi_pass, mqtt_host, final_port


def check_port_in_use(port: int) -> bool:
    """Kiểm tra xem một cổng mạng TCP đã có tiến trình nào chiếm dụng hay chưa."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0
