#!/usr/bin/env python3
"""
Edge AI Network Security System - Runtime System Launcher
==========================================================
Chỉ chịu trách nhiệm KHỞI ĐỘNG VẬN HÀNH hệ thống thời gian thực (Inference Only):
1. Khởi động Embedded Python MQTT Broker (nếu chưa có Mosquitto cài sẵn).
2. Kiểm tra Artifacts mô hình Machine Learning đã huấn luyện (scaler, classifier, detector, metadata).
3. Khởi động ML Real-time Inference Engine (kết nối MQTT, phát hiện bất thường & phân loại cuộc tấn công).
4. Khởi động Web Dashboard Server (FastAPI backend + Static Modern Glassmorphism UI + WebSocket).
5. Khởi động Telemetry Network Probe:
   - 'host': Host PC Live Network Sniffer (mặc định - bắt luồng mạng thật của máy tính).
   - 'esp32': Chế độ chờ dữ liệu từ thiết bị phần cứng ESP32 vật lý qua Wi-Fi/MQTT.
6. (Tùy chọn) Bắn gói tin độc hại mạng thật qua cờ `--attack-sim`:
   - Bắn gói tin thật (Port Scan, UDP Flood, TCP SYN Flood, Vuln Scan, Exfiltration) qua raw socket.
   - Điều khiển trực tiếp các kịch bản on-demand thông qua các nút bấm trên Web Dashboard.
"""

import os
import sys
import time
import re
import socket
import argparse
import subprocess
import webbrowser
import signal
import multiprocessing
import threading
from typing import Optional, Tuple

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from broker.embedded_broker import start_embedded_broker
from firmware.host_probe.host_sniffer import start_host_sniffer
from firmware.simulator.attack_traffic_generator import start_attack_traffic_generator, detect_target_ip

# Tự động nạp biến môi trường từ file .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

processes = []


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

        import re
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


# Biến toàn cục lưu IP LAN máy tính phục vụ UDP Beacon và Roaming
ACTIVE_LAN_IP = "127.0.0.1"


def udp_broker_beacon_worker(broker_port: int = 1883):
    """
    Luồng phát sóng định kỳ UDP Broadcast (Beacon) mỗi 3 giây trong mạng nội bộ.
    Giúp ESP32 tự động nhận biết địa chỉ IP của máy tính mà không cần nạp lại firmware
    kể cả khi máy tính chuyển sang Wi-Fi mới hoặc được cấp IP DHCP mới.
    """
    import socket
    import json
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    while True:
        try:
            global ACTIVE_LAN_IP
            if ACTIVE_LAN_IP and ACTIVE_LAN_IP not in ("127.0.0.1", "0.0.0.0"):
                payload = json.dumps({
                    "service": "AeroEdge",
                    "broker_ip": ACTIVE_LAN_IP,
                    "port": broker_port
                }).encode("utf-8")
                s.sendto(payload, ("255.255.255.255", 18830))
        except Exception:
            pass
        time.sleep(3.0)


def network_roaming_watcher_worker(root_dir: str):
    """
    Luồng nền tự động giám sát card mạng và dải IP thời gian thực (Zero-Config Roaming).
    Khi phát hiện máy tính chuyển sang Wi-Fi mới (ví dụ từ mạng phòng sang Hotspot di động),
    tự động cập nhật IP mới vào .env, credentials.h và luồng UDP Beacon.
    """
    global ACTIVE_LAN_IP
    last_ssid, _, last_ip = auto_detect_wifi_credentials()
    ACTIVE_LAN_IP = last_ip

    while True:
        time.sleep(4.0)
        try:
            curr_ssid, curr_pwd, curr_ip = auto_detect_wifi_credentials()
            if curr_ip and curr_ip != "127.0.0.1" and (curr_ip != last_ip or (curr_ssid and curr_ssid != last_ssid)):
                print(f"\n[NetworkWatcher] >>> PHAT HIEN THAY DOI MANG (ROAMING) <<<")
                print(f"  * Mang cu : SSID='{last_ssid}', IP='{last_ip}'")
                print(f"  * Mang moi: SSID='{curr_ssid}', IP='{curr_ip}'")
                print(f"  -> Dang tu dong cap nhat cau hinh & phat song UDP Beacon toi ESP32...")
                last_ip = curr_ip
                last_ssid = curr_ssid
                ACTIVE_LAN_IP = curr_ip

                if curr_ssid and curr_pwd and curr_ip:
                    update_env_file(root_dir, curr_ssid, curr_pwd, curr_ip)
                    sync_env_to_firmware(root_dir)
        except Exception:
            pass


def serial_telemetry_bridge_worker(com_port: str, broker_port: int = 1883):
    """
    Cầu nối Telemetry dự phòng qua cáp USB Serial (Dual-Transport High Availability).
    Khi ESP32 cắm qua cổng USB, luồng này liên tục lắng nghe các gói tin JSON từ Serial.
    Nếu Wi-Fi bị ngắt do chuyển mạng hoặc router có AP Isolation, dữ liệu từ ESP32
    vẫn được truyền thẳng vào MQTT Broker cục bộ (127.0.0.1:1883) mà không bị gián đoạn 1 giây nào!
    """
    try:
        import serial
        import paho.mqtt.client as mqtt
    except ImportError:
        return

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ESP32-USB-Serial-Bridge")
    try:
        mqtt_client.connect("127.0.0.1", broker_port, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[SerialBridge] Khong the ket noi MQTT 127.0.0.1: {e}")
        return

    print(f"  [SerialBridge] Da kich hoat cau noi USB Serial Telemetry tren {com_port} (115200 baud).")
    print(f"                 (Dam bao luu luong van truyen 100% ve Web Dashboard ke ca khi mat ket noi Wi-Fi!)")

    last_forwarded_ts = 0.0
    while True:
        try:
            with serial.Serial(com_port, 115200, timeout=2.0) as ser:
                while True:
                    line = ser.readline().decode("utf-8", errors="ignore").strip()
                    if line.startswith("ESP32_TELEMETRY:"):
                        json_str = line[len("ESP32_TELEMETRY:"):].strip()
                        now = time.time()
                        if now - last_forwarded_ts >= 0.5:
                            mqtt_client.publish("edge/telemetry/traffic", json_str)
                            last_forwarded_ts = now
        except Exception:
            time.sleep(2.0)


def find_arduino_cli() -> Optional[str]:
    """
    Tìm đường dẫn thực thi của arduino-cli độc lập hoặc tích hợp trong Arduino IDE 2.x
    hỗ trợ đầy đủ trên Windows, Linux và macOS mà không hardcode đường dẫn ổ đĩa cố định.
    """
    import shutil
    # 1. Kiểm tra PATH hệ thống trước
    cli_path = shutil.which("arduino-cli")
    if cli_path and os.path.exists(cli_path):
        return cli_path

    # 2. Tìm kiếm động theo từng hệ điều hành
    common_paths = []
    user_home = os.path.expanduser("~")

    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA", os.path.join(user_home, "AppData", "Local"))
        prog_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
        common_paths.extend([
            os.path.join(local_app_data, "Programs", "Arduino IDE", "resources", "app", "lib", "backend", "resources", "arduino-cli.exe"),
            os.path.join(prog_files, "Arduino IDE", "resources", "app", "lib", "backend", "resources", "arduino-cli.exe"),
            os.path.join(prog_files_x86, "Arduino IDE", "resources", "app", "lib", "backend", "resources", "arduino-cli.exe"),
            os.path.join(user_home, ".arduino15", "bin", "arduino-cli.exe"),
            os.path.join(user_home, "bin", "arduino-cli.exe"),
        ])
    elif sys.platform == "darwin":
        common_paths.extend([
            "/Applications/Arduino IDE.app/Contents/Resources/app/lib/backend/resources/arduino-cli",
            os.path.join(user_home, "Applications", "Arduino IDE.app", "Contents", "Resources", "app", "lib", "backend", "resources", "arduino-cli"),
            "/opt/homebrew/bin/arduino-cli",
            "/usr/local/bin/arduino-cli",
            os.path.join(user_home, ".arduino15", "bin", "arduino-cli"),
            os.path.join(user_home, "bin", "arduino-cli"),
            os.path.join(user_home, ".local", "bin", "arduino-cli"),
        ])
    else:
        # Linux / Unix / WSL
        common_paths.extend([
            "/usr/local/bin/arduino-cli",
            "/usr/bin/arduino-cli",
            os.path.join(user_home, ".local", "bin", "arduino-cli"),
            os.path.join(user_home, "bin", "arduino-cli"),
            os.path.join(user_home, ".arduino15", "bin", "arduino-cli"),
            os.path.join(user_home, ".arduino-ide", "resources", "app", "lib", "backend", "resources", "arduino-cli"),
            "/opt/arduino-ide/resources/app/lib/backend/resources/arduino-cli",
        ])

    for path in common_paths:
        if path and os.path.exists(path):
            return path
    return None


def find_esp32_com_port(arduino_cli_path: Optional[str] = None) -> Optional[str]:
    """
    Tự động phát hiện cổng nối tiếp (COM port trên Windows, /dev/ttyUSB* trên Linux, /dev/cu.* trên macOS)
    kết nối với bo mạch ESP32 (CP210x, CH340, CH9102, FTDI, USB-UART).
    Nếu không tìm thấy thiết bị, trả về None (không hardcode).
    """
    import glob

    # 1. Thử qua thư viện pyserial nếu có (chạy đồng nhất và chuẩn xác nhất trên mọi OS)
    try:
        import serial.tools.list_ports
        ports = list(serial.tools.list_ports.comports())
        for p in ports:
            desc = (p.description or "").upper()
            hwid = (p.hwid or "").upper()
            if any(k in desc or k in hwid for k in ("CP210", "CH340", "CH9102", "SILICON", "USB", "UART", "ESP32", "FTDI")):
                return p.device
        if ports:
            for p in ports:
                if p.device.upper() not in ("COM1", "/DEV/TTYS0", "/DEV/TTY"):
                    return p.device
    except ImportError:
        pass

    # 2. Thử qua PowerShell Win32_SerialPort (trên Windows)
    if sys.platform == "win32":
        try:
            cmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_SerialPort | Select-Object DeviceID, Description | ConvertTo-Json"'
            out = subprocess.check_output(cmd, shell=True, text=True, errors="ignore")
            import json
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                desc = str(item.get("Description", "")).upper()
                dev_id = str(item.get("DeviceID", "")).strip()
                if any(k in desc for k in ("CP210", "CH340", "CH9102", "SILICON", "USB", "UART", "ESP32")):
                    return dev_id
            for item in data:
                dev_id = str(item.get("DeviceID", "")).strip()
                if dev_id and dev_id.upper() not in ("COM1", "COM3"):
                    return dev_id
        except Exception:
            pass

    # 3. Thử quét cổng thiết bị USB Serial trên Linux
    elif sys.platform.startswith("linux"):
        linux_candidates = (
            glob.glob("/dev/serial/by-id/*") +
            glob.glob("/dev/ttyUSB*") +
            glob.glob("/dev/ttyACM*")
        )
        if linux_candidates:
            return os.path.realpath(linux_candidates[0])

    # 4. Thử quét cổng thiết bị USB Serial trên macOS
    elif sys.platform == "darwin":
        mac_candidates = (
            glob.glob("/dev/cu.usbserial*") +
            glob.glob("/dev/cu.SLAB_USBtoUART*") +
            glob.glob("/dev/cu.wchusbserial*") +
            glob.glob("/dev/cu.usbmodem*")
        )
        if mac_candidates:
            return mac_candidates[0]

    # 5. Thử truy vấn qua `arduino-cli board list` (hoạt động đa nền tảng)
    if arduino_cli_path and os.path.exists(arduino_cli_path):
        try:
            out = subprocess.check_output([arduino_cli_path, "board", "list"], text=True, errors="ignore")
            for line in out.splitlines():
                if "(USB)" in line or "serial" in line.lower():
                    parts = line.split()
                    if parts:
                        candidate = parts[0].strip()
                        if candidate.upper() not in ("PORT", "COM1", "/DEV/TTYS0"):
                            return candidate
        except Exception:
            pass

    return None


def flash_esp32_cli(root_dir: str, com_port: Optional[str] = None) -> bool:
    """Biên dịch và nạp firmware ESP32 qua CLI không cần mở Arduino IDE GUI."""
    arduino_cli = find_arduino_cli()
    if not arduino_cli:
        print("  [Lỗi CLI] Không tìm thấy executable của arduino-cli trên máy tính!")
        print("  -> Vui lòng cài đặt Arduino IDE 2.x hoặc cài arduino-cli độc lập vào PATH.")
        print("  -> Tải arduino-cli chính thức tại: https://arduino.github.io/arduino-cli/latest/installation/")
        return False

    ino_path = os.path.join(root_dir, "firmware", "esp32_probe", "esp32_probe.ino")
    if not os.path.exists(ino_path):
        print(f"  [Lỗi CLI] Không tìm thấy file sketch: {ino_path}")
        return False

    port = com_port or find_esp32_com_port(arduino_cli)
    if not port:
        print("\n  [Lỗi CLI] Không tìm thấy bo mạch ESP32 nào đang cắm vào cổng USB/Serial!")
        print("  -> Gợi ý khắc phục:")
        print("     1. Cắm cáp USB nối ESP32 với máy tính (đảm bảo cáp truyền được data, không phải chỉ sạc).")
        print("     2. Hoặc chỉ định cổng trực tiếp bằng cờ --port <CỔNG>:")
        if sys.platform == "win32":
            print("        Ví dụ Windows: python run_system.py --flash --port COM4")
        elif sys.platform.startswith("linux"):
            print("        Ví dụ Linux:   ./run_system.sh --flash --port /dev/ttyUSB0")
            print("        (Nếu bị Permission Denied: chạy 'sudo usermod -a -G dialout $USER' rồi đăng nhập lại)")
        else:
            print("        Ví dụ macOS:   ./run_system.sh --flash --port /dev/cu.usbserial-0001")
        return False

    print("\n" + "=" * 70)
    print(f"   [CLI FLASH] DANG BIEN DICH VA NAP FIRMWARE ESP32 TAI CONG {port}...")
    print("=" * 70)

    # 1. Biên dịch
    print(f"  [1/2] Biên dịch sketch {os.path.relpath(ino_path, root_dir)} (FQBN: esp32:esp32:esp32)...")
    cmd_compile = [arduino_cli, "compile", "--fqbn", "esp32:esp32:esp32", ino_path]
    try:
        ret_compile = subprocess.run(cmd_compile, capture_output=True, text=True)
        if ret_compile.returncode != 0:
            print(f"  [Lỗi Biên Dịch]:\n{ret_compile.stderr or ret_compile.stdout}")
            return False
        print("  -> Biên dịch thành công!")
    except Exception as e:
        print(f"  [Lỗi thực thi compile]: {e}")
        return False

    # 2. Nạp code qua cổng COM
    print(f"  [2/2] Nạp firmware lên board ESP32 qua cổng {port}...")
    cmd_upload = [arduino_cli, "upload", "-p", port, "--fqbn", "esp32:esp32:esp32", ino_path]
    try:
        ret_upload = subprocess.run(cmd_upload, capture_output=True, text=True)
        if ret_upload.returncode != 0:
            err_msg = ret_upload.stderr or ret_upload.stdout
            if "PermissionError" in err_msg or "port is busy" in err_msg or "Access is denied" in err_msg:
                print(f"\n  [CANH BAO QUAN TRONG] Cong {port} dang bi chiem dung boi tien trinh khac!")
                print("  -> Vui long DONG Arduino IDE (hoac tat Serial Monitor) de giai phong cong COM, sau do chay lai!")
            else:
                print(f"  [Lỗi Nạp Code]:\n{err_msg}")
            return False
        print(f"  -> Nạp firmware thành công lên ESP32 qua cổng {port}!")
        print("=" * 70 + "\n")
        return True
    except Exception as e:
        print(f"  [Lỗi thực thi upload]: {e}")
        return False


def check_port_in_use(port: int) -> bool:
    """Kiểm tra xem một cổng mạng TCP đã có tiến trình nào chiếm dụng hay chưa."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def cleanup(sig=None, frame=None):
    """Dọn dẹp an toàn toàn bộ tiến trình con khi nhận tín hiệu kết thúc (Ctrl+C)."""
    print("\n\n" + "=" * 60)
    print("   DANG DUNG TOAN BO HE THONG EDGE AI SECURITY...")
    print("=" * 60)
    for p in processes:
        if isinstance(p, multiprocessing.Process):
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)
        elif isinstance(p, subprocess.Popen):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    p.kill()
    print("   [OK] Tat ca tien trinh da dung an toan. Tam biet!\n")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Edge AI Real-time Anomaly Detection & Attack Classification Runtime",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.55,
        help="Nguong canh bao Anomaly Score (mac dinh: 0.55)"
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=1883,
        help="Port cho MQTT Broker (mac dinh: 1883)"
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8000,
        help="Port cho Web Dashboard FastAPI (mac dinh: 8000)"
    )
    parser.add_argument(
        "--probe",
        default="host",
        choices=["host", "esp32", "sim"],
        help="Chon nguon telemetry: 'host' (mac dinh: bat luu luong mang that qua card mang), 'esp32' (cho ESP32 vat ly qua WiFi)"
    )
    parser.add_argument(
        "--no-sim",
        action="store_true",
        help="Tuong duong --probe esp32 (cho phan cung ESP32 ket noi qua WiFi)"
    )
    parser.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Cua so lay mau telemetry giay (mac dinh: 1.0s)"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Khong tu dong mo trinh duyet"
    )
    parser.add_argument(
        "--attack-sim",
        action="store_true",
        help="Kich hoat bo ban goi tin doc hai mang that (Port Scan, UDP Flood, SYN Flood, Vuln Scan, Exfil) dieu khien truc tiep tu nut bam Web Dashboard"
    )
    parser.add_argument(
        "--attack-target",
        default=None,
        help="IP dich de ban goi tin doc hai khi co --attack-sim (mac dinh: tu dong nhan dien Gateway IP hoac localhost)"
    )
    parser.add_argument(
        "--flash",
        action="store_true",
        help="Tu dong bien dich va nap firmware ESP32 qua CLI (khong can mo Arduino IDE GUI)"
    )
    parser.add_argument(
        "--port",
        "--com-port",
        dest="com_port",
        default=None,
        help="Chi dinh cong Serial / COM cua ESP32 khi dung --flash (mac dinh: tu dong do tim. Vi du: COM4 tren Windows, /dev/ttyUSB0 tren Linux, /dev/cu.usbserial-0001 tren macOS)"
    )

    args = parser.parse_args()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    # Xac dinh che do probe
    if args.no_sim:
        probe_mode = "esp32"
    elif args.probe == "sim":
        print("\n[Luu y] Che do 'sim' (so lieu ao) da duoc thay the bang bo ban goi tin mang that 100%.")
        print("        Tu dong chuyen sang: --probe host --attack-sim\n")
        probe_mode = "host"
        args.attack_sim = True
    else:
        probe_mode = args.probe

    print("=" * 70)
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - RUNTIME LAUNCHER")
    print(f"   [Mode: INFERENCE ONLY (LOAD ARTIFACTS)] | [Probe: {probe_mode.upper()}]")
    if args.attack_sim:
        print("   [Attack Simulator: KICH HOAT (Ban goi tin mang that, dieu khien tu Web UI)]")
    if args.flash:
        print("   [CLI Auto-Flash ESP32: KICH HOAT (Tu dong build & nap qua CLI)]")
    print("=" * 70)

    # Dong bo cau hinh credentials neu co thiet lap (tu dong lay SSID/Pass qua netsh ngam)
    sync_env_to_firmware(root_dir)

    # 0. Neu co yeu cau nap firmware cho ESP32 qua CLI
    if args.flash:
        flash_ok = flash_esp32_cli(root_dir, com_port=args.com_port)
        if not flash_ok:
            print("  [Nhac nho] Ban van co the mo Arduino IDE de nap code bang tay neu muon.")

    # 1. Kiem tra va khoi dong MQTT Broker
    print(f"\n[1/5] Kiem tra MQTT Broker tai port {args.broker_port}...")
    if check_port_in_use(args.broker_port):
        print(f"  -> Da phat hien MQTT Broker dang hoat dong tai port {args.broker_port}.")
    else:
        print(f"  -> Chua co Broker. Dang khoi dong Embedded Python MQTT Broker tren port {args.broker_port}...")
        p_broker = multiprocessing.Process(
            target=start_embedded_broker,
            kwargs={"host": "0.0.0.0", "port": args.broker_port},
            daemon=True
        )
        p_broker.start()
        processes.append(p_broker)
        time.sleep(1.5)
        if check_port_in_use(args.broker_port):
            print(f"  -> Embedded MQTT Broker da san sang tren port {args.broker_port}!")
        else:
            print("  [Canh bao] Chua khoi dong duoc broker, he thong se tiep tuc...")

    # 2. Kiem tra Model Artifacts (Khong con training trong run_system)
    print("\n[2/5] Kiem tra Artifacts mo hinh Machine Learning...")
    model_path = os.path.join(root_dir, "ml_engine", "models", "attack_classifier.joblib")
    meta_path = os.path.join(root_dir, "ml_engine", "models", "model_metadata.json")
    scaler_path = os.path.join(root_dir, "ml_engine", "models", "scaler.joblib")

    if not (os.path.exists(model_path) and os.path.exists(meta_path) and os.path.exists(scaler_path)):
        print("\n" + "=" * 76)
        print("  [NHAC NHO QUAN TRONG] CHUA TIM THAY ARTIFACTS MO HINH MACHINE LEARNING!")
        print("=" * 76)
        print("  He thong van hanh (run_system.py) hoat dong o che do suy luan thuan tuy,")
        print("  khong con tu dong huan luyen de dam bao tinh on dinh va toc do khoi dong.")
        print("\n  Vui long chay quy trinh huan luyen offline truoc de tao artifacts:")
        print("      python ml_engine/train.py --classifier decision_tree")
        print("\n  Hoac toi uu hoa sieu tham so (HPO) voi Optuna:")
        print("      python ml_engine/train.py --classifier random_forest --optuna")
        print("\n  Sau khi huan luyen thanh cong va xuat artifacts, hay chay lai:")
        print("      python run_system.py")
        print("=" * 76 + "\n")
        cleanup()
        sys.exit(1)

    import json
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        clf_name = meta.get("classifier_type", "Unknown")
        det_name = meta.get("anomaly_detector_type", "Unknown")
        feat_cnt = meta.get("features_count", len(meta.get("features", [])))
        lbl_cnt = meta.get("labels_count", len(meta.get("labels", [])))
        acc = meta.get("classifier_accuracy", 0.0)
        macro_f1 = meta.get("classifier_macro_f1", 0.0)
        print(f"  -> Da load thanh cong Artifacts da huan luyen:")
        print(f"     * Classifier Model       : {clf_name} (Accuracy: {acc*100:.2f}%, Macro F1: {macro_f1*100:.2f}%)")
        print(f"     * Anomaly Detector       : {det_name}")
        print(f"     * Schema Features        : {feat_cnt} dac trung (Edge-IIoTset)")
        print(f"     * Nhan phan loai tan cong: {lbl_cnt} lop")
    except Exception as e:
        print(f"  -> Da tim thay artifacts model tai ml_engine/models (Chi tiet meta: {e})")

    # 3. Khoi dong ML Inference Service
    print("\n[3/5] Khoi dong ML Real-time Inference Engine...")
    inference_script = os.path.join(root_dir, "ml_engine", "inference_service.py")
    env_inf = os.environ.copy()
    env_inf["MQTT_HOST"] = "127.0.0.1"
    env_inf["MQTT_BROKER_HOST"] = "127.0.0.1"
    env_inf["MQTT_PORT"] = str(args.broker_port)
    env_inf["ANOMALY_THRESHOLD"] = str(args.threshold)
    p_inference = subprocess.Popen([python_exe, inference_script], env=env_inf)
    processes.append(p_inference)
    time.sleep(1.0)

    # 4. Khoi dong Dashboard Backend (FastAPI)
    print(f"\n[4/5] Khoi dong Web Dashboard Server tren port {args.dashboard_port}...")
    dashboard_script = os.path.join(root_dir, "dashboard", "backend", "app.py")
    env = os.environ.copy()
    env["PORT"] = str(args.dashboard_port)
    env["MQTT_HOST"] = "127.0.0.1"
    env["MQTT_BROKER_HOST"] = "127.0.0.1"
    env["MQTT_PORT"] = str(args.broker_port)
    p_dashboard = subprocess.Popen([python_exe, dashboard_script], env=env)
    processes.append(p_dashboard)
    time.sleep(2.0)

    # 5. Khoi dong Telemetry Probe (Host Sniffer hoac cho ESP32 vat ly)
    if probe_mode == "host":
        print("\n[5/5] Khoi dong Host PC Live Network Sniffer (Bat luu luong mang that cua may tinh)...")
        p_sniffer = multiprocessing.Process(
            target=start_host_sniffer,
            kwargs={
                "broker_host": "127.0.0.1",
                "broker_port": args.broker_port,
                "window_sec": args.window
            },
            daemon=True
        )
        p_sniffer.start()
        processes.append(p_sniffer)
    else:
        print("\n[5/5] Che do ESP32 vat ly: He thong dang cho du lieu tu phan cung ESP32 qua WiFi/MQTT & USB Serial...")
        print("  -> Bo mach ESP32 Promiscuous bat luu luong Wi-Fi over-the-air va day ve qua MQTT & USB Serial.")

        # 1. Kích hoạt luồng UDP Auto-Discovery Beacon giúp ESP32 tự nhận diện IP Broker khi chuyển mạng
        t_beacon = threading.Thread(target=udp_broker_beacon_worker, args=(args.broker_port,), daemon=True)
        t_beacon.start()

        # 2. Kích hoạt luồng Network Roaming Watcher tự động giám sát thay đổi mạng máy tính
        t_roaming = threading.Thread(target=network_roaming_watcher_worker, args=(root_dir,), daemon=True)
        t_roaming.start()

        # 3. Kích hoạt luồng USB Serial Telemetry Bridge dự phòng nếu có cổng COM kết nối
        esp_port = args.com_port or find_esp32_com_port()
        if esp_port:
            t_bridge = threading.Thread(target=serial_telemetry_bridge_worker, args=(esp_port, args.broker_port), daemon=True)
            t_bridge.start()

    # 6. Khoi dong Attack Traffic Generator neu nguoi dung bat co --attack-sim
    if args.attack_sim:
        target_ip = args.attack_target or detect_target_ip()
        print(f"\n[AttackSim] >>> KICH HOAT BO BAN GOI TIN DOC HAI MANG THAT (RAW SOCKET) <<<")
        print(f"  * Target IP: {target_ip}")
        print(f"  * Dieu khien: Nut bam tren Web Dashboard se phat dong tan cong that toi {target_ip}!")
        print(f"  * Sniffer ({probe_mode.upper()}) se thuc su bat duoc cac goi tin nay de ML phan loai!")
        p_attack_gen = multiprocessing.Process(
            target=start_attack_traffic_generator,
            kwargs={
                "target_ip": target_ip,
                "broker_host": "127.0.0.1",
                "broker_port": args.broker_port,
                "cycle_interval": 12.0
            },
            daemon=True
        )
        p_attack_gen.start()
        processes.append(p_attack_gen)

    # Thong bao va mo trinh duyet
    dashboard_url = f"http://localhost:{args.dashboard_port}"
    probe_desc = "Live PC Traffic Sniffer" if probe_mode == "host" else "Physical ESP32 Wi-Fi Hardware"
    print("\n" + "=" * 70)
    print(" [OK] HE THONG DA HOAT DONG TOAN DIEN!")
    print(f"  -> Web Dashboard        : {dashboard_url}")
    print(f"  -> Luong Telemetry      : {probe_desc} -> MQTT:{args.broker_port} -> ML Engine -> WebSocket")
    print(f"  -> Model Classifier     : {clf_name}")
    print(f"  -> Model Anomaly        : {det_name}")
    print(f"  -> Probe Source         : {probe_mode.upper()} ({probe_desc})")
    print(f"  -> Attack Simulation    : {'BAT (Dieu khien on-demand tu Web UI)' if args.attack_sim else 'TAT'}")
    print(f"  -> Nguong canh bao      : {args.threshold}")
    print("  -> Nhan Ctrl + C de dung toan bo he thong.")
    print("=" * 70 + "\n")

    if not args.no_browser:
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    # Giữ tiến trình launcher sống
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
