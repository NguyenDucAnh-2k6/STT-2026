"""
Launcher ESP32 Flasher & Hardware Detection
===========================================
Cung cấp các hàm tìm kiếm arduino-cli đa nền tảng, phát hiện cổng Serial của ESP32,
và thực hiện biên dịch/nạp firmware tự động qua dòng lệnh (CLI).
"""

import os
import sys
import subprocess
from typing import Optional


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
        # Ưu tiên các chip USB-to-UART phổ biến của ESP32
        for p in ports:
            desc = (p.description or "").upper()
            hwid = (p.hwid or "").upper()
            if any(k in desc or k in hwid for k in ("CP210", "CH340", "CH9102", "SILICON", "USB", "UART", "ESP32", "FTDI", "CDC")):
                if "ROOT\\PORTS" not in hwid and desc != "COMMUNICATIONS PORT":
                    return p.device
        # Dự phòng các cổng serial thực tế (loại bỏ cổng COM ảo/bo mạch chủ COM1, COM3)
        if ports:
            for p in ports:
                desc = (p.description or "").upper()
                hwid = (p.hwid or "").upper()
                if p.device.upper() not in ("COM1", "COM3", "/DEV/TTYS0", "/DEV/TTY"):
                    if "ROOT\\PORTS" not in hwid and "COMMUNICATIONS PORT" not in desc:
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
    elif sys.platform.startswith("darwin"):
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
    """Bien dich va nap firmware ESP32 qua CLI khong can mo Arduino IDE GUI."""
    arduino_cli = find_arduino_cli()
    if not arduino_cli:
        print("  [Loi CLI] Khong tim thay executable cua arduino-cli tren may tinh!")
        print("  -> Vui long cai dat Arduino IDE 2.x hoac cai arduino-cli doc lap vao PATH.")
        print("  -> Tai arduino-cli chinh thuc tai: https://arduino.github.io/arduino-cli/latest/installation/")
        return False

    ino_path = os.path.join(root_dir, "firmware", "esp32_probe", "esp32_probe.ino")
    if not os.path.exists(ino_path):
        print(f"  [Loi CLI] Khong tim thay file sketch: {ino_path}")
        return False

    port = com_port or find_esp32_com_port(arduino_cli)
    if not port:
        print("\n  [Loi CLI] Khong tim thay bo mach ESP32 nao dang cam vao cong USB/Serial!")
        print("  -> Goi y khac phuc:")
        print("     1. Cam cap USB noi ESP32 voi may tinh (dam bao cap truyen duoc data, khong phai chi sac).")
        print("     2. Hoac chi dinh cong truc tiep bang co --port <CONG>:")
        if sys.platform == "win32":
            print("        Vi du Windows: python run_system.py --flash --port COM4")
        elif sys.platform.startswith("linux"):
            print("        Vi du Linux:   ./run_system.sh --flash --port /dev/ttyUSB0")
            print("        (Neu bi Permission Denied: chay 'sudo usermod -a -G dialout $USER' roi dang nhap lai)")
        else:
            print("        Vi du macOS:   ./run_system.sh --flash --port /dev/cu.usbserial-0001")
        return False

    print("\n" + "=" * 70)
    print(f"   [CLI FLASH] DANG BIEN DICH VA NAP FIRMWARE ESP32 TAI CONG {port}...")
    print("=" * 70)

    fqbn = "esp32:esp32:esp32:PartitionScheme=huge_app"
    # 1. Bien dich
    print(f"  [1/2] Bien dich sketch {os.path.relpath(ino_path, root_dir)} (FQBN: {fqbn})...")
    cmd_compile = [arduino_cli, "compile", "--fqbn", fqbn, ino_path]
    try:
        ret_compile = subprocess.run(cmd_compile, capture_output=True, text=True)
        if ret_compile.returncode != 0:
            print(f"  [Loi Bien Dich]:\n{ret_compile.stderr or ret_compile.stdout}")
            return False
        print("  -> Bien dich thanh cong!")
    except Exception as e:
        print(f"  [Loi thuc thi compile]: {e}")
        return False

    # 2. Nap code qua cong COM
    print(f"  [2/2] Nap firmware len board ESP32 qua cong {port}...")
    cmd_upload = [arduino_cli, "upload", "-p", port, "--fqbn", fqbn, ino_path]
    try:
        ret_upload = subprocess.run(cmd_upload, capture_output=True, text=True)
        if ret_upload.returncode != 0:
            err_msg = ret_upload.stderr or ret_upload.stdout
            if "PermissionError" in err_msg or "port is busy" in err_msg or "Access is denied" in err_msg:
                print(f"\n  [CANH BAO QUAN TRONG] Cong {port} dang bi chiem dung boi tien trinh khac!")
                print("  -> Vui long DONG Arduino IDE (hoac tat Serial Monitor) de giai phong cong COM, sau do chay lai!")
            else:
                print(f"  [Loi Nap Code]:\n{err_msg}")
            return False
        print(f"  -> Nap firmware thanh cong len ESP32 qua cong {port}!")
        print("=" * 70 + "\n")
        return True
    except Exception as e:
        print(f"  [Loi thuc thi upload]: {e}")
        return False
