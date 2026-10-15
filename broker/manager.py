"""
Smart MQTT Broker Manager (Cross-Platform)
==========================================
Tự động phát hiện và khởi chạy Eclipse Mosquitto Native C trên Windows, Linux và macOS.
Nếu hệ thống chưa cài đặt Mosquitto, tự động chuyển đổi sang Embedded Python Broker.

Hỗ trợ quản lý vòng đời (Lifecycle): tự động dọn dẹp tiến trình con khi dừng hệ thống.
"""

import os
import sys
import shutil
import subprocess
import multiprocessing
import time
import socket
import re
from typing import Tuple, Optional, Any

from broker.embedded_broker import start_embedded_broker


def check_port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Kiểm tra xem cổng TCP có đang được lắng nghe hay không."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def check_mqtt_ready(port: int, host: str = "127.0.0.1") -> bool:
    """Check MQTT 3.1.1 CONNACK, rather than accepting any TCP listener."""
    client_id = b"AERO-healthcheck"
    body = b"\x00\x04MQTT\x04\x02\x00\x05" + len(client_id).to_bytes(2, "big") + client_id
    try:
        with socket.create_connection((host, port), timeout=0.5) as conn:
            conn.sendall(b"\x10" + bytes([len(body)]) + body)
            response = b""
            while len(response) < 4:
                chunk = conn.recv(4 - len(response))
                if not chunk:
                    break
                response += chunk
            conn.sendall(b"\xe0\x00")
            return response == b"\x20\x02\x00\x00"
    except OSError:
        return False


def build_runtime_config(root_dir: str, port: int) -> str:
    """Keep template policy, overriding the native TCP port and persistence path."""
    if not 1 <= port <= 65535:
        raise ValueError("Invalid MQTT port")
    data_dir = os.path.join(root_dir, "broker", "data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(root_dir, "broker", "mosquitto.conf"), encoding="utf-8") as source:
        content = source.read()
    content = re.sub(r"(?m)^listener 1883 0\.0\.0\.0$", f"listener {port} 0.0.0.0", content)
    content = re.sub(r"(?m)^persistence_location .*", lambda _: "persistence_location " + data_dir.replace("\\", "/") + "/", content)
    path = os.path.join(data_dir, "mosquitto.runtime.conf")
    with open(path, "w", encoding="utf-8") as output:
        output.write(content)
    return path


def find_mosquitto_executable() -> Optional[str]:
    """
    Tìm kiếm đường dẫn tới file thực thi mosquitto trên hệ thống đa nền tảng.
    Kiểm tra cả biến môi trường PATH lẫn các đường dẫn cài đặt mặc định phổ biến.
    """
    # 1. Kiểm tra qua PATH
    exe_in_path = shutil.which("mosquitto")
    if exe_in_path and os.path.isfile(exe_in_path):
        return exe_in_path

    # 2. Windows: Kiểm tra các thư mục Program Files chuẩn
    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files\mosquitto\mosquitto.exe",
            r"C:\Program Files (x86)\mosquitto\mosquitto.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\mosquitto\mosquitto.exe"),
            os.path.expandvars(r"%PROGRAMFILES%\mosquitto\mosquitto.exe")
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path

    # 3. Linux / Unix
    elif sys.platform.startswith("linux"):
        candidates = [
            "/usr/sbin/mosquitto",
            "/usr/bin/mosquitto",
            "/usr/local/sbin/mosquitto",
            "/usr/local/bin/mosquitto",
            "/snap/bin/mosquitto"
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path

    # 4. macOS (Homebrew / MacPorts)
    elif sys.platform == "darwin":
        candidates = [
            "/opt/homebrew/bin/mosquitto",
            "/opt/homebrew/sbin/mosquitto",
            "/usr/local/bin/mosquitto",
            "/usr/local/sbin/mosquitto"
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path

    return None


def ensure_mqtt_broker(root_dir: str, port: int = 1883) -> Tuple[str, Optional[Any]]:
    """
    Khởi chạy và đảm bảo MQTT Broker sẵn sàng hoạt động:
    1. Nếu cổng port đã mở (Service nền hoặc tiến trình trước đó): Tái sử dụng.
    2. Nếu có Mosquitto Native: Khởi chạy Mosquitto với file mosquitto.conf của dự án.
    3. Nếu không có Mosquitto: Khởi chạy Embedded Python Broker (QoS 0 fallback).

    Trả về:
        (broker_type, process_object)
        - broker_type: "EXISTING_SERVICE" | "NATIVE_MOSQUITTO" | "EMBEDDED_PYTHON"
        - process_object: subprocess.Popen hoặc multiprocessing.Process hoặc None
    """
    # 1. Kiểm tra nếu cổng đã có service lắng nghe
    if check_port_open(port):
        return ("EXISTING_SERVICE", None) if check_mqtt_ready(port) else ("FAILED", None)

    # Đảm bảo thư mục lưu cache database tồn tại để Mosquitto không báo lỗi persistence
    data_dir = os.path.join(root_dir, "broker", "data")
    os.makedirs(data_dir, exist_ok=True)

    conf_path = build_runtime_config(root_dir, port)
    mosquitto_bin = find_mosquitto_executable()

    # 2. Thử khởi chạy Mosquitto Native C
    if mosquitto_bin:
        print(f"  -> Phat hien Mosquitto Native: {mosquitto_bin}")
        print(f"  -> Dang khoi dong Native Mosquitto Broker tren port {port} voi file config...")

        cmd = [mosquitto_bin, "-c", conf_path]
        try:
            # Khởi chạy ngầm không chặn terminal, chuyển stderr để theo dõi nếu có lỗi
            with open(os.path.join(data_dir, "mosquitto.log"), "ab") as log:
                proc = subprocess.Popen(cmd, stdout=log, stderr=log, cwd=root_dir)
            # Chờ một chút để socket mở
            for _ in range(15):
                time.sleep(0.1)
                if check_mqtt_ready(port):
                    return "NATIVE_MOSQUITTO", proc
                if proc.poll() is not None:
                    # Tiến trình thoát sớm (ví dụ lỗi bind socket)
                    print(f"  [Canh bao] Mosquitto Native exited with code {proc.returncode}")
                    break
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        except Exception as e:
            print(f"  [Canh bao] Khong the khoi dong Mosquitto subprocess: {e}")

    # 3. Fallback sang Embedded Python Broker
    print(f"  -> Chuyen sang khoi dong Embedded Python MQTT Broker tai port {port}...")
    p_broker = multiprocessing.Process(
        target=start_embedded_broker,
        kwargs={"host": "0.0.0.0", "port": port},
        daemon=True
    )
    p_broker.start()
    for _ in range(15):
        time.sleep(0.1)
        if check_mqtt_ready(port):
            return "EMBEDDED_PYTHON", p_broker

    p_broker.terminate()
    p_broker.join(timeout=3)
    return "FAILED", None
