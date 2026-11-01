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
import argparse
import subprocess
import webbrowser
import signal
import multiprocessing
import threading
import shutil
from typing import Optional, Tuple, Any, List, Dict

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


from broker.manager import ensure_mqtt_broker, check_mqtt_ready
from firmware.host_probe.host_sniffer import start_host_sniffer
from firmware.simulator.attack_traffic_generator import start_attack_traffic_generator, detect_target_ip
from data_lake import start_lake_collector, DataLakeCollector

# Tự động nạp biến môi trường từ file .env
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT_DIR, ".env"))
except ImportError:
    pass

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

processes = []
lake_collector: Optional[DataLakeCollector] = None
host_stop_event = None
esp32_stop_event = None
esp32_bridge_thread = None
enable_remote_push: bool = False

from launcher import (
    detect_host_lan_ip,
    auto_detect_wifi_credentials,
    sync_env_to_firmware,
    resolve_esp32_zero_config,
    check_port_in_use,
    sync_esp32_probe_mode,
    udp_broker_beacon_worker,
    network_roaming_watcher_worker,
    serial_telemetry_bridge_worker,
    find_esp32_com_port,
    flash_esp32_cli,
)


def cleanup(sig=None, frame=None):
    """Dọn dẹp an toàn toàn bộ tiến trình con khi nhận tín hiệu kết thúc (Ctrl+C)."""
    print("\n\n" + "=" * 60)
    print("   DANG DUNG TOAN BO HE THONG EDGE AI SECURITY...")
    print("=" * 60)
    global lake_collector
    if esp32_stop_event is not None:
        esp32_stop_event.set()
        if esp32_bridge_thread is not None:
            esp32_bridge_thread.join(timeout=4)
        for process in processes:
            if isinstance(process, multiprocessing.Process) and process.is_alive():
                process.join(timeout=8)
    if host_stop_event is not None:
        host_stop_event.set()
        for process in processes:
            if isinstance(process, multiprocessing.Process) and process.is_alive():
                process.join(timeout=10)
    if lake_collector is not None:
        try:
            print("  [DataLake] Dang chot session va dong bo Parquet file vao kho du lieu...")
            lake_collector.stop()
        except Exception as e:
            print(f"  [DataLake] Canh bao khi dong lake collector: {e}")

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

    global enable_remote_push
    if enable_remote_push:
        try:
            from data_lake.remote_storage import get_remote_storage_manager
            print("  [RemoteStorage] Dang dong bo toan bo phien lam viec len Cloudflare R2 / S3...")
            res = get_remote_storage_manager().sync_lake_to_remote()
            if res.get("success"):
                print(f"  [RemoteStorage] [OK] {res.get('message')}")
            else:
                print(f"  [RemoteStorage] {res.get('message')}")
        except Exception as e:
            print(f"  [RemoteStorage] Canh bao dong bo: {e}")

    print("   [OK] Tat ca tien trinh da dung an toan. Tam biet!\n")
    sys.exit(0)



def str_to_bool(val: Any) -> bool:
    """Chuyển đổi linh hoạt giá trị từ CLI thành boolean."""
    if isinstance(val, bool):
        return val
    s = str(val).lower().strip()
    if s in ("true", "1", "yes", "y", "t", "on"):
        return True
    elif s in ("false", "0", "no", "n", "f", "off"):
        return False
    raise argparse.ArgumentTypeError(f"Gia tri boolean khong hop le: '{val}' (chap nhan: true/false, 1/0)")


class SmartBooleanAction(argparse.Action):
    """
    Action thông minh cho các cờ boolean CLI:
    - Cho phép gõ trực tiếp cờ để BẬT: --attack-sim, --arduino-cli, --push-remote.
    - Cho phép gõ tiền tố --no-... để TẮT: --no-attack-sim, --no-arduino-cli.
    - Cho phép truyền tham số tường minh: --attack-sim true / false / 1 / 0.
    """
    def __init__(self, option_strings, dest, default=False, required=False, help=None, metavar="true/false"):
        opts = []
        for opt in option_strings:
            opts.append(opt)
            if opt.startswith("--") and not opt.startswith("--no-"):
                neg_opt = f"--no-{opt[2:]}"
                if neg_opt not in opts:
                    opts.append(neg_opt)
        super().__init__(
            option_strings=opts,
            dest=dest,
            nargs="?",
            const=True,
            default=default,
            required=required,
            help=help,
            metavar=metavar
        )

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string and option_string.startswith("--no-"):
            if values is None:
                setattr(namespace, self.dest, False)
            else:
                val_bool = str_to_bool(values)
                setattr(namespace, self.dest, not val_bool)
        elif values is None:
            setattr(namespace, self.dest, True)
        else:
            setattr(namespace, self.dest, str_to_bool(values))


def resolve_models_dir(root_dir: str, classifier: str, anomaly_model: str, custom_dir: Optional[str] = None, traffic_mode: str = "decrypted") -> Tuple[str, str]:
    """
    Truy vết và định vị chính xác thư mục chứa model artifacts cho hệ thống qua ml_engine.routing.
    """
    if custom_dir:
        return custom_dir, f"Thu muc chi dinh qua --models-dir ({custom_dir})"

    from ml_engine.routing import resolve_deployed_model, normalize_stream
    base_models = os.path.join(root_dir, "ml_engine", "models")
    canonical_stream = normalize_stream(traffic_mode)
    try:
        resolved_dir, desc = resolve_deployed_model(
            stream=canonical_stream,
            classifier=classifier,
            anomaly_model=anomaly_model,
            base_models_dir=base_models
        )
        return resolved_dir, f"Thu muc model {desc.traffic_mode.upper()} ({desc.profile})"
    except Exception as e:
        clf_clean = classifier.lower().strip()
        ano_clean = anomaly_model.lower().strip()
        fallback_dir = os.path.join(base_models, canonical_stream, f"{clf_clean}_{ano_clean}")
        return fallback_dir, f"Thu muc model {canonical_stream.upper()} ({clf_clean}_{ano_clean}) [Chua huan luyen: {e}]"


def sync_tinyml_header_to_firmware(root_dir: str, models_dir: str, classifier: str, anomaly_model: str, traffic_mode: str = "decrypted") -> bool:
    """
    Tự động sao chép và ghi đè C Header TinyML sang firmware/esp32_probe/ qua ml_engine.routing.
    """
    from ml_engine.routing import sync_firmware_header
    firmware_dir = os.path.join(root_dir, "firmware", "esp32_probe")
    success, message = sync_firmware_header(traffic_mode, models_dir, firmware_dir)
    prefix = "[TinyML Sync]" if success else "[TinyML Sync Warning]"
    print(f"  {prefix} {message}")
    return success


def main():
    parser = argparse.ArgumentParser(
        description="Edge AI Real-time Anomaly Detection & Attack Classification Runtime",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.55,
        help="Nguong canh bao Anomaly Score tren toan he thong (mac dinh: 0.55)"
    )
    parser.add_argument(
        "--broker-host",
        default=os.getenv("MQTT_BROKER_HOST") or os.getenv("MQTT_HOST", "127.0.0.1"),
        help="MQTT broker address; remote brokers must already be running"
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=int(os.getenv("MQTT_BROKER_PORT", "1883")),
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
        help="Nguon du lieu Telemetry: 'host' (bat goi tin mang that tren PC), 'esp32' (cho du lieu tu phan cung ESP32 vat ly), 'sim' (gia lap telemetry)"
    )
    parser.add_argument(
        "--no-sim",
        dest="no_sim",
        action=SmartBooleanAction,
        default=False,
        help="Chay che do phan cung ESP32 vat ly (tuong duong --probe esp32)"
    )
    parser.add_argument(
        "--esp32-gateway", "--gateway",
        dest="esp32_gateway",
        action=SmartBooleanAction,
        default=False,
        help="Kich hoat che do Demo 2: ESP32 Micro-Gateway (Phat SoftAP cho laptop ket noi, NAT ra Internet, giam sat ML Deep Packet Inspection qua CPU; khong drop goi tin)"
    )
    parser.add_argument(
        "--demo-mode", "--demo",
        dest="demo_mode",
        choices=["sniffer", "gateway", "laptop-gateway"],
        default=None,
        help="Lua chon 1 trong 3 loai hinh demo: 'sniffer' (Demo 1: Bat song khong trung WIDS), 'gateway' (Demo 2: ESP32 lam Micro-Gateway DPI), 'laptop-gateway' (Demo 3: Laptop lam Gateway)"
    )
    parser.add_argument(
        "--gateway-ssid",
        dest="gateway_ssid",
        default=os.getenv("GATEWAY_AP_SSID", "AERO-Security-Gateway"),
        help="Ten SSID mang SoftAP do ESP32 phat khi o che do Gateway (mac dinh: AERO-Security-Gateway hoac tu .env)"
    )
    parser.add_argument(
        "--gateway-pass",
        dest="gateway_pass",
        default=os.getenv("GATEWAY_AP_PASSWORD", os.getenv("GATEWAY_AP_PASS", "aero2026sec")),
        help="Mat khau mang SoftAP do ESP32 phat khi o che do Gateway (mac dinh: aero2026sec hoac tu .env, dat '' neu mang mo)"
    )
    parser.add_argument(
        "--window",
        type=float,
        default=1.0,
        help="Cua so lay mau telemetry giay (mac dinh: 1.0s)"
    )
    parser.add_argument(
        "--no-browser",
        dest="no_browser",
        action=SmartBooleanAction,
        default=False,
        help="Khong tu dong mo trinh duyet Web Dashboard khi khoi dong (go --no-browser de tat mo browser)"
    )
    parser.add_argument(
        "--attack-sim",
        dest="attack_sim",
        action=SmartBooleanAction,
        default=False,
        help="Kich hoat bo ban goi tin doc hai mang that (Port Scan, UDP Flood, SYN Flood, Vuln Scan, Exfiltration) qua raw socket, dieu khien tu Dashboard (Go --attack-sim de BAT; hoac --no-attack-sim de TAT)"
    )
    parser.add_argument(
        "--attack-target",
        default=None,
        help="Explicit lab target; defaults to LAB_TARGET_IP and must be in LAB_ALLOWED_TARGETS"
    )
    parser.add_argument(
        "--arduino-cli",
        "--arduino_cli",
        dest="arduino_cli",
        action=SmartBooleanAction,
        default=False,
        help="Tu dong bien dich va nap firmware sang ESP32 qua arduino-cli (Go --arduino-cli de BAT; hoac --no-arduino-cli de TAT)"
    )
    parser.add_argument(
        "--flash",
        dest="arduino_cli",
        action="store_true",
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--port",
        "--com-port",
        dest="com_port",
        default=None,
        help="Chi dinh cong Serial/COM cua ESP32 (mac dinh: tu dong do tim, vd: COM4 tren Windows, /dev/ttyUSB0 tren Linux)"
    )
    parser.add_argument(
        "--wifi-ssid", "--ssid",
        dest="wifi_ssid",
        nargs="?",
        const="",
        default=None,
        help="Chi dinh thu cong SSID cua mang Wi-Fi / Hotspot de ESP32 ket noi va bat goi (mac dinh: tu dong lay theo card WiFi may tinh)"
    )
    parser.add_argument(
        "--wifi-pass", "--wifi-password", "--password",
        dest="wifi_pass",
        nargs="?",
        const="",
        default=None,
        help="Chi dinh mat khau Wi-Fi (neu mang Open / khong co mat khau, go --wifi-pass hoac --wifi-pass '')"
    )
    parser.add_argument(
        "--record-lake",
        dest="record_lake",
        action=SmartBooleanAction,
        default=True,
        help="Tu dong ghi luu toan bo telemetries vao Data Lakehouse Parquet/SQLite (Mac dinh: BAT; go --no-record-lake hoac --no-record de TAT)"
    )
    parser.add_argument(
        "--traffic-mode", "--traffic",
        dest="traffic_mode",
        choices=["auto", "decrypted", "encrypted", "wireless"],
        default="auto",
        help="Che do phan loai luu luong: 'auto' (ESP32 dung encrypted, Host dung decrypted), 'decrypted' (Edge-IIoTset 56 dac trung), 'encrypted' (USTC-TFC2016 10 dac trung), 'wireless' (AWID3 14 dac trung 802.11)"
    )
    parser.add_argument(
        "--classifier",
        default="decision_tree",
        choices=[
            "decision_tree", "random_forest", "extra_trees", "xgboost", "xgb",
            "lightgbm", "lgb", "catboost", "gradient_boosting", "pytorch_deep", "dnn", "mlp", "deep_learning",
            "logistic_regression", "ensemble_voting"
        ],
        help=(
            "Loai Attack Classifier can nap (8 mo hinh phan loai chinh):\n"
            "  [Nhom Edge TinyML C Header / TFLite cho ESP32]:\n"
            "  * decision_tree      : Cây quyết định (C Header TinyML siêu nhẹ)\n"
            "  * random_forest      : Rừng cây ngẫu nhiên (C Header TinyML soft-voting)\n"
            "  * extra_trees        : Extra Trees Ensemble (C Header TinyML)\n"
            "  * pytorch_deep / dnn : Deep Neural Network (TFLite FlatBuffer C array cho ESP32)\n"
            "  * logistic_regression: Hồi quy Logistic tuyến tính (C Header Softmax)\n"
            "  [Nhom High-Performance Server GBDT]:\n"
            "  * xgboost / xgb      : XGBoost Gradient Boosting\n"
            "  * lightgbm / lgb     : LightGBM Histogram GBDT\n"
            "  * catboost           : CatBoost Classifier\n"
            "  * gradient_boosting  : Scikit-learn Gradient Boosting Baseline\n"
            "  * ensemble_voting    : Tổ hợp mềm Soft-Voting Ensemble (RF + ET + XGB)"
        )
    )
    parser.add_argument(
        "--anomaly-model", "--anomaly_model",
        default="isolation_forest",
        choices=[
            "isolation_forest", "deep_autoencoder", "autoencoder",
            "one_class_svm", "elliptic_envelope", "lof"
        ],
        help=(
            "Loai Anomaly Detector can nap (6 mo hinh phat hien bat thuong):\n"
            "  [Nhom Edge TinyML C Header / TFLite cho ESP32]:\n"
            "  * isolation_forest   : Cô lập rừng cây ngẫu nhiên (C Header TinyML)\n"
            "  * deep_autoencoder   : Deep Autoencoder (TFLite FlatBuffer C array cho ESP32)\n"
            "  * one_class_svm      : One-Class SVM RBF Kernel (C Header TinyML)\n"
            "  * elliptic_envelope  : Robust Gaussian Mahalanobis (C Header TinyML)\n"
            "  * lof                : Local Outlier Factor K-Nearest Density (C Header TinyML)"
        )
    )
    parser.add_argument(
        "--models-dir",
        default=None,
        help="Chi dinh truc tiep thu muc chua artifacts mo hinh (mac dinh: tu dong tim kiem hoac tong hop to hop)"
    )
    parser.add_argument(
        "--push-remote",
        dest="push_remote",
        action=SmartBooleanAction,
        default=False,
        help="Tu dong dong bo toan bo phan vung Parquet len Cloudflare R2 / S3 (Go --push-remote de BAT; hoac --no-push-remote de TAT)"
    )
    parser.add_argument(
        "--no-record",
        dest="record_lake",
        action="store_false",
        help="Tat che do ghi vao Data Lakehouse (tuong duong --no-record-lake)"
    )
    parser.add_argument(
        "--rl-defense",
        dest="rl_defense",
        action=SmartBooleanAction,
        default=False,
        help="Kich hoat Digital Twin Sandbox ket hop Hoc Tang Cuong (RL Policy) tu dong phong thu mang"
    )
    parser.add_argument(
        "--enforce-real-network",
        dest="enforce_real_network",
        action=SmartBooleanAction,
        default=False,
        help="Cho phep thuc thi lenh Firewall that tren OS (mac dinh: False - Che do Dry-run an toan)"
    )
    parser.add_argument(
        "--no-tshark",
        dest="use_tshark",
        action="store_false",
        default=True,
        help="Tat che do TShark DPI, uu tien dung Raw Socket hoac psutil"
    )

    parser.add_argument("--lab-capture", action="store_true",
                        help="Use LAB_CAPTURE_INTERFACES for the local host lab; preserve normal capture config")
    parser.add_argument("--twin-lab", action="store_true",
                        help="Twin experiments from UI with stable loopback capture; no legacy attack generator")
    args = parser.parse_args()
    if args.twin_lab:
        if args.probe != "host" or args.no_sim or not args.use_tshark or args.attack_sim or args.lab_capture:
            parser.error("--twin-lab requires --probe host and TShark; omit --attack-sim and --lab-capture")
        from digital_twin.lab.capture_config import loopback_interface
        from firmware.host_probe.tshark_engine import find_tshark_path
        try:
            executable = find_tshark_path()
            if not executable:
                raise ValueError("TShark required for --twin-lab")
            from launcher.docker_setup import ensure_docker_linux
            ensure_docker_linux(report=print)
            os.environ["HOST_CAPTURE_INTERFACES"] = loopback_interface(executable)
            os.environ["HOST_TWIN_SERVICE_PORT"] = str(int(os.getenv("LAB_HTTP_PORT", "8088")))
            from firmware.simulator.lab_config import allow_twin_loopback
            from launcher.capture_setup import persist_env_setting
            persist_env_setting(ROOT_DIR, "LAB_ALLOWED_TARGETS", allow_twin_loopback())
            os.environ["HOST_PCAP_FILE"] = ""
        except (ValueError, RuntimeError, OSError) as error:
            parser.error(str(error))
    if args.lab_capture:
        if args.probe != "host" or args.no_sim or not args.use_tshark:
            parser.error("--lab-capture requires --probe host with TShark")
        from digital_twin.lab.capture_config import loopback_interface
        from firmware.host_probe.tshark_engine import find_tshark_path
        lab_interfaces = os.getenv("LAB_CAPTURE_INTERFACES", "auto-loopback").strip()
        if int(os.getenv("LAB_HTTP_PORT", "8088")) in (args.dashboard_port, args.broker_port):
            parser.error("LAB_HTTP_PORT must differ from dashboard and MQTT ports")
        try:
            executable = find_tshark_path()
            if not executable:
                raise ValueError("TShark required for --lab-capture")
            os.environ["HOST_CAPTURE_INTERFACES"] = loopback_interface(executable, lab_interfaces)
        except ValueError as error:
            parser.error(f"LAB_CAPTURE_INTERFACES: {error}")
        os.environ["HOST_PCAP_FILE"] = ""

    # Xac dinh che do probe va loai hinh demo (Demo 1: Sniffer, Demo 2: ESP32 Gateway, Demo 3: Laptop Gateway)
    is_gateway = getattr(args, "esp32_gateway", False) or (getattr(args, "demo_mode", "") == "gateway")

    if args.no_sim:
        probe_mode = "esp32"
    elif is_gateway:
        # Neu chon gateway, tu dong chuyen sang probe_mode esp32 ma nguoi dung khong can go --probe esp32
        probe_mode = "esp32"
    elif getattr(args, "demo_mode", "") == "sniffer":
        probe_mode = "esp32"
    elif args.probe == "sim":
        print("\n[Luu y] Che do 'sim' (so lieu ao) da duoc thay the bang bo ban goi tin mang that 100%.")
        print("        Tu dong chuyen sang: --probe host --attack-sim\n")
        probe_mode = "host"
        args.attack_sim = True
    else:
        probe_mode = args.probe

    # Thiết lập trạng thái remote push toàn cục
    if not args.twin_lab:
        os.environ.pop("HOST_TWIN_SERVICE_PORT", None)
    if (probe_mode == "host" and not args.no_sim and args.use_tshark
            and not args.twin_lab and not args.lab_capture and not os.getenv("HOST_PCAP_FILE")):
        from launcher.capture_setup import prepare_host_capture
        try:
            selected = prepare_host_capture(ROOT_DIR)
            print(f"[Capture] Auto-discovered {len(selected)} active physical adapter(s); updated HOST_CAPTURE_INTERFACES in .env")
        except (ValueError, OSError, RuntimeError) as error:
            parser.error(f"Host capture discovery: {error}")
    global enable_remote_push
    enable_remote_push = getattr(args, "push_remote", False) or (os.getenv("R2_AUTO_SYNC", "false").lower() in ("true", "1", "yes"))

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    if getattr(args, "demo_mode", None) == "laptop-gateway":
        print("\n" + "=" * 70)
        print("   [DEMO MODE 3] LAPTOP LAM GATEWAY (RESERVED)")
        print("=" * 70)
        print("   * Che do 'Laptop lam Gateway' da duoc quy hoach trong he thong va se trien khai tiep theo.")
        print("=" * 70 + "\n")

    print("=" * 70)
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - RUNTIME LAUNCHER")
    demo_label = "DEMO 2: ESP32 GATEWAY" if is_gateway else (f"DEMO 1: {probe_mode.upper()}" if probe_mode == "esp32" else f"PROBE: {probe_mode.upper()}")
    print(f"   [Mode: INFERENCE ONLY] | [{demo_label}]")
    print(f"   [Target Models: Classifier='{args.classifier}', Anomaly='{args.anomaly_model}']")
    if enable_remote_push:
        print("   [Cloud Sync: KICH HOAT (Tu dong push len Cloudflare R2 / S3)]")
    if args.attack_sim:
        print("   [Attack Simulator: KICH HOAT (Ban goi tin mang that, dieu khien tu Web UI)]")
    if args.arduino_cli:
        print("   [CLI Auto-Flash ESP32 (arduino-cli): KICH HOAT (Tu dong build & nap qua CLI)]")
    print("=" * 70)

    # Dong bo cau hinh credentials neu co thiet lap (tu dong lay SSID/Pass qua netsh ngam)
    if probe_mode == "esp32":
        if getattr(args, "rl_defense", False) or getattr(args, "enforce_real_network", False):
            raise ValueError("--probe esp32 runs independently of Twin/RL; omit defense flags")

        # Dong bo che do hoat dong (Sniffer vs Gateway) vao config.h cua firmware ESP32
        firmware_mode = "gateway" if is_gateway else "sniffer"
        sync_esp32_probe_mode(
            root_dir,
            mode=firmware_mode,
            ap_ssid=getattr(args, "gateway_ssid", None),
            ap_pass=getattr(args, "gateway_pass", None)
        )

        if is_gateway:
            print("\n" + "=" * 70)
            print("   DEMO 2: ESP32 MICRO-GATEWAY (DEEP PACKET INSPECTION & EDGE AI)")
            print("=" * 70)
            print("   * Che do hoat dong : ESP32 phat mang SoftAP + NAT chuyen tiep Internet")
            print(f"   * Wi-Fi SoftAP phat: '{args.gateway_ssid}' | Mat khau: '{args.gateway_pass}'")
            print("   * Cach ly an toan  : Khoa cung toi da 1 client (chiec laptop nay)")
            print("   * Kha nang boc tach: Shannon Payload Entropy + Header L3/L4 (TCP/UDP/ICMP)")
            print("   * Chinh sach bao ve: MONITOR-ONLY (Chua dua ra quyet dinh phong thu,")
            print("                        chuyen tiep nguyen ven 100% goi tin ra Internet)")
            print("   * Huong dan nhanh  : Hay mo Wi-Fi tren laptop va ket noi vao mang")
            print(f"                        '{args.gateway_ssid}' de bat dau luot web & quan sat!")
            print("=" * 70 + "\n")
        else:
            print("\n" + "=" * 70)
            print("   DEMO 1: PROMISCUOUS SNIFFER (L2 WIRELESS OVER-THE-AIR WIDS)")
            print("=" * 70)
            print("   * ESP32 bat song khong trung (802.11 Promiscuous Sniffer).")
            print("   * Khoa bo loc vao Target AP va kenh tuong ung.")
            print("=" * 70 + "\n")

        # Tu dong hoac thu cong xac dinh toan bo thong so mang, IP LAN, va cong MQTT kha dung cho mang LAN
        wifi_ssid, wifi_pass, args.broker_host, args.broker_port = resolve_esp32_zero_config(
            root_dir, requested_port=args.broker_port,
            manual_ssid=args.wifi_ssid, manual_pwd=args.wifi_pass
        )
    else:
        os.environ["MQTT_BROKER_PORT"] = str(args.broker_port)
        os.environ["MQTT_BROKER_HOST"] = args.broker_host

    # Xac dinh traffic mode thuc te (auto: ESP32 Sniffer -> wireless, ESP32 Gateway -> encrypted, Host -> decrypted)
    if args.traffic_mode == "auto":
        if is_gateway:
            effective_traffic_mode = "encrypted"
        elif probe_mode == "esp32":
            effective_traffic_mode = "wireless"
        else:
            effective_traffic_mode = "decrypted"
    else:
        effective_traffic_mode = args.traffic_mode

    # Tu dong xac dinh thu muc model va dong bo C Header TinyML sang firmware ESP32
    models_dir, models_source = resolve_models_dir(
        root_dir, args.classifier, args.anomaly_model, args.models_dir, traffic_mode=effective_traffic_mode
    )
    sync_tinyml_header_to_firmware(root_dir, models_dir, args.classifier, args.anomaly_model, traffic_mode=effective_traffic_mode)

    # 0. Neu co yeu cau nap firmware cho ESP32 qua CLI (arduino-cli)
    if args.arduino_cli:
        com_target = args.com_port or find_esp32_com_port()
        if com_target and not args.com_port:
            print(f"  [Auto-Config] Tu dong phat hien board ESP32 ket noi tai cong: {com_target}")
        flash_ok = flash_esp32_cli(root_dir, com_port=com_target)
        if not flash_ok:
            print("  [Nhac nho] Ban van co the mo Arduino IDE de nap code bang tay neu muon.")

    # 1. Kiem tra va khoi dong MQTT Broker (Tu dong uu tien Mosquitto Native, fallback Python Broker)
    print(f"\n[1/5] Kiem tra va khoi dong MQTT Broker tai port {args.broker_port}...")
    local_addresses = {"127.0.0.1", "localhost", "0.0.0.0", detect_host_lan_ip()}
    if args.broker_host in local_addresses:
        b_type, b_proc = ensure_mqtt_broker(root_dir, port=args.broker_port)
        # Kiem tra neu o che do ESP32 ma broker chi nghe 127.0.0.1, tu choi IP LAN
        if probe_mode == "esp32" and b_type in ("EXISTING_SERVICE", "NATIVE_MOSQUITTO") and args.broker_host not in ("127.0.0.1", "localhost", "0.0.0.0"):
            if not check_mqtt_ready(args.broker_port, args.broker_host):
                print("\n" + "=" * 76)
                print(f"  [CANH BAO MQTT BROKER] CỔNG {args.broker_port} ĐANG BỊ CHIẾM BỞI LOCALHOST-ONLY SERVICE!")
                print("=" * 76)
                print(f"  Hệ thống phát hiện cổng {args.broker_port} chỉ cho phép kết nối nội bộ (127.0.0.1),")
                print(f"  nhưng từ chối kết nối từ mạng LAN ({args.broker_host}).")
                print("  ESP32 ở bên ngoài qua Wi-Fi sẽ KHÔNG THỂ gửi dữ liệu về máy tính được!")
                print("\n  GIẢI PHÁP ĐỀ XUẤT:")
                print(f"  1. Chuyển sang dùng cổng khác (ví dụ 1884) để AERO khởi chạy Mosquitto cho phép LAN:")
                print(f"     python run_system.py --probe esp32 --broker-port 1884 --classifier {args.classifier} --anomaly-model {args.anomaly_model} --arduino-cli")
                print(f"  2. Hoặc cấu hình Mosquitto Windows Service cho phép LAN bằng cách thêm 2 dòng vào")
                print(f"     file C:\\Program Files\\mosquitto\\mosquitto.conf rồi restart service:")
                print(f"         listener {args.broker_port} 0.0.0.0")
                print(f"         allow_anonymous true")
                print("=" * 76 + "\n")
                b_type = "FAILED"
    else:
        b_type, b_proc = ("EXISTING_SERVICE", None) if check_mqtt_ready(args.broker_port, args.broker_host) else ("FAILED", None)
    if b_type == "EXISTING_SERVICE":
        print(f"  -> Da phat hien MQTT Broker (Service/Daemon) dang hoat dong tai port {args.broker_port}.")
    elif b_type == "NATIVE_MOSQUITTO":
        print(f"  -> Eclipse Mosquitto Native da san sang tren port {args.broker_port} (Config: broker/mosquitto.conf)!")
        if b_proc:
            processes.append(b_proc)
    elif b_type == "EMBEDDED_PYTHON":
        print(f"  -> Embedded Python MQTT Broker da san sang tren port {args.broker_port}!")
        if b_proc:
            processes.append(b_proc)
    else:
        raise RuntimeError("Configured MQTT broker is unavailable or does not accept MQTT connections.")

    # 1.1 Khoi dong Data Lakehouse Collector neu co bat
    global lake_collector
    if getattr(args, "record_lake", True):
        try:
            sniffer_mode_tag = "host-interface" if probe_mode == "host" else ("esp32-gateway" if is_gateway else "ap-locked")
            lake_collector = start_lake_collector(
                broker_host=args.broker_host,
                broker_port=args.broker_port,
                probe_type=probe_mode,
                sniffer_mode=sniffer_mode_tag,
                buffer_size=500,
                flush_interval=5.0
            )
            print(f"  -> Data Lakehouse Collector: DA SAN SANG (Ghi Parquet vao data_lake/raw/ | Session: {lake_collector.session_id})")
        except Exception as e:
            print(f"  [DataLake] Canh bao: Khong the khoi dong Data Lake Collector: {e}")
            if probe_mode in ("host", "esp32"):
                cleanup()
                raise RuntimeError("Packet collection requires a working data lake; use --no-record only for capture without persistence") from e

    # 1.2 Khoi dong Periodic Cloud Sync neu bat --push-remote
    if enable_remote_push:
        try:
            from data_lake.remote_storage import get_remote_storage_manager
            r_mgr = get_remote_storage_manager()
            ok_r, msg_r = r_mgr.is_configured_and_available()
            if ok_r:
                print(f"  -> Remote Storage ({r_mgr._provider_name}): DA SAN SANG ({r_mgr.endpoint} | Bucket: {r_mgr.bucket_name})")
                def _periodic_sync_worker():
                    while True:
                        time.sleep(300)
                        try:
                            r_mgr.sync_lake_to_remote()
                        except Exception:
                            pass
                t_r = threading.Thread(target=_periodic_sync_worker, daemon=True)
                t_r.start()
            else:
                print(f"  [RemoteStorage] Canh bao: {msg_r}")
        except Exception as e:
            print(f"  [RemoteStorage] Canh bao khoi tao: {e}")

    # 1.3 Khoi dong Live Network Digital Twin Daemon (Chay song song voi mang that)
    if probe_mode == "host":
        print("\n[Live Digital Twin] Khoi dong Ban sao so mang bien (Network Digital Twin) song song...")
        from digital_twin.live_service import start_live_digital_twin_worker
        p_twin = multiprocessing.Process(
            target=start_live_digital_twin_worker,
            kwargs={
                "broker_host": args.broker_host,
                "broker_port": args.broker_port,
                "enable_rl_defense": getattr(args, "rl_defense", False),
                "enforce_real": getattr(args, "enforce_real_network", False)
            },
            daemon=True
        )
        p_twin.start()
        processes.append(p_twin)
        print("  -> Live Digital Twin: DA SAN SANG!")
        if getattr(args, "rl_defense", False):
            print(f"  -> Autonomous RL Defense: KICH HOAT (Che do: {'Active Firewall' if getattr(args, 'enforce_real_network', False) else 'Dry-run Sandbox'})")

    # 2. Kiem tra Model Artifacts theo co --classifier & --anomaly-model
    print(f"\n[2/5] Kiem tra Artifacts mo hinh Machine Learning (Che do: {effective_traffic_mode.upper()})...")
    print(f"  * Thu muc nguon : {models_dir}")
    print(f"  * Chi tiet nguon: {models_source}")


    model_path = os.path.join(models_dir, "attack_classifier.joblib")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    meta_path = os.path.join(models_dir, "model_metadata.json")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    prep_path = os.path.join(models_dir, "preprocessor.joblib")

    has_scaler = os.path.exists(scaler_path) or os.path.exists(prep_path)
    if not (os.path.exists(model_path) and os.path.exists(iso_path) and has_scaler):
        print("\n" + "=" * 76)
        print("  [NHAC NHO QUAN TRONG] CHUA TIM THAY ARTIFACTS MO HINH MACHINE LEARNING!")
        print("=" * 76)
        print(f"  He thong da tim kiem tai: {models_dir}")
        print("  nhung khong co du cac tep weights can thiet.")
        print("\n  Vui long chay quy trinh huan luyen offline cho cap model nay truoc:")
        print(f"      python ml_engine/train.py --classifier {args.classifier} --anomaly-model {args.anomaly_model}")
        print("\n  Hoac toi uu hoa sieu tham so (HPO) voi Optuna:")
        print(f"      python ml_engine/train.py --classifier {args.classifier} --optuna")
        print("\n  Sau khi huan luyen thanh cong va xuat artifacts, hay chay lai:")
        print(f"      python run_system.py --classifier {args.classifier} --anomaly-model {args.anomaly_model}")
        print("=" * 76 + "\n")
        cleanup()
        sys.exit(1)

    clf_name = args.classifier
    det_name = args.anomaly_model
    import json
    try:
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            clf_name = meta.get("classifier_type", args.classifier)
            det_name = meta.get("anomaly_detector_type", args.anomaly_model)
            feat_cnt = meta.get("features_count", len(meta.get("features", [])))
            lbl_cnt = meta.get("labels_count", len(meta.get("labels", [])))
            acc = meta.get("classifier_accuracy")
            macro_f1 = meta.get("classifier_macro_f1")
            acc_text = f"{acc*100:.2f}%" if isinstance(acc, (int, float)) else "N/A"
            print(f"  -> Da load thanh cong Artifacts da huan luyen:")
            print(f"     * Classifier Model       : {clf_name} (Accuracy: {acc_text}, Macro F1: {macro_f1})")
            print(f"     * Anomaly Detector       : {det_name}")
            schema_info = f"{feat_cnt} dac trung (USTC-TFC2016 L2-4)" if effective_traffic_mode == "encrypted" else f"{feat_cnt} dac trung (Edge-IIoTset DPI)"
            print(f"     * Schema Features        : {schema_info}")
            print(f"     * Nhan phan loai tan cong: {lbl_cnt} lop")
            if probe_mode == "esp32":
                pipeline_f1 = meta.get("pipeline_macro_f1")
                pipeline_text = f"{pipeline_f1*100:.2f}%" if isinstance(pipeline_f1, (int, float)) else "N/A"
                print(f"     * Edge profile: {meta.get('profile')} | Pipeline macro F1: {pipeline_text}")
                print(f"     * Deployment status: {'ready' if meta.get('deployment_ready') else 'experimental, hardware not validated'}")
        else:
            print(f"  -> Da tim thay artifacts model tai {models_dir} (Classifier: {clf_name}, Detector: {det_name})")
    except Exception as e:
        print(f"  -> Da tim thay artifacts model tai {models_dir} (Chi tiet meta: {e})")

    # 3. Khoi dong ML Inference Service voi dung MODELS_DIR
    print("\n[3/5] Khoi dong ML Real-time Inference Engine...")
    inference_script = os.path.join(root_dir, "ml_engine", "inference_service.py")
    env_inf = os.environ.copy()
    env_inf["MQTT_HOST"] = args.broker_host
    env_inf["MQTT_BROKER_HOST"] = args.broker_host
    env_inf["MQTT_PORT"] = str(args.broker_port)
    env_inf["ANOMALY_THRESHOLD"] = str(args.threshold)
    env_inf["MODELS_DIR"] = models_dir
    env_inf["AERO_PROBE_MODE"] = probe_mode
    env_inf["AERO_TRAFFIC_MODE"] = effective_traffic_mode
    env_inf["AERO_ESP32_MODE"] = "gateway" if is_gateway else "sniffer"
    p_inference = subprocess.Popen([python_exe, inference_script], env=env_inf)
    processes.append(p_inference)
    time.sleep(1.0)


    # 4. Khoi dong Dashboard Backend (FastAPI)
    print(f"\n[4/5] Khoi dong Web Dashboard Server tren port {args.dashboard_port}...")
    dashboard_script = os.path.join(root_dir, "dashboard", "backend", "app.py")
    env = os.environ.copy()
    env["PORT"] = str(args.dashboard_port)
    env["MQTT_HOST"] = args.broker_host
    env["MQTT_BROKER_HOST"] = args.broker_host
    env["MQTT_PORT"] = str(args.broker_port)
    env["AERO_PROBE_MODE"] = probe_mode
    env["MODELS_DIR"] = models_dir
    env["AERO_TRAFFIC_MODE"] = effective_traffic_mode
    env["AERO_ESP32_MODE"] = "gateway" if is_gateway else "sniffer"
    if is_gateway:
        env["AERO_GATEWAY_SSID"] = args.gateway_ssid
    p_dashboard = subprocess.Popen([python_exe, dashboard_script], env=env)
    processes.append(p_dashboard)
    time.sleep(2.0)

    # 5. Khoi dong Telemetry Probe (Host Sniffer hoac cho ESP32 vat ly)
    if probe_mode == "host":
        print("\n[5/5] Khoi dong Host PC Live Network Sniffer (Bat luu luong mang that cua may tinh)...")
        global host_stop_event
        host_stop_event = multiprocessing.Event()
        p_sniffer = multiprocessing.Process(
            target=start_host_sniffer,
            kwargs={
                "broker_host": args.broker_host,
                "broker_port": args.broker_port,
                "window_sec": args.window,
                "use_tshark": getattr(args, "use_tshark", True),
                "stop_event": host_stop_event,
                "dashboard_port": args.dashboard_port
            },
            daemon=True
        )
        p_sniffer.start()
        processes.append(p_sniffer)
    else:
        from firmware.esp32_probe.radio_capture import run_radio_capture
        from firmware.host_probe.tshark_engine import find_tshark_path
        if getattr(args, "use_tshark", True) and not is_gateway and not find_tshark_path():
            cleanup()
            raise RuntimeError("ESP32 packet mode requires Wireshark/TShark installed on the host")
        global esp32_stop_event, esp32_bridge_thread
        esp32_stop_event = multiprocessing.Event()
        p_radio = None
        if getattr(args, "use_tshark", True) and not is_gateway:
            p_radio = multiprocessing.Process(target=run_radio_capture,
                args=(args.broker_host, args.broker_port, esp32_stop_event))
            p_radio.start()
            processes.append(p_radio)
        print("\n[5/5] Che do ESP32 vat ly: He thong dang cho du lieu tu phan cung ESP32 qua WiFi/MQTT & USB Serial...")
        print("  -> Bo mach ESP32 Promiscuous bat luu luong Wi-Fi over-the-air va day ve qua MQTT & USB Serial.")

        # 1. Kích hoạt luồng UDP Auto-Discovery Beacon giúp ESP32 tự nhận diện IP Broker khi chuyển mạng
        t_beacon = threading.Thread(target=udp_broker_beacon_worker, args=(args.broker_port,), daemon=True)
        if os.getenv("MQTT_AUTO_DISCOVERY", "false").lower() == "true":
            t_beacon.start()

        # 2. Kích hoạt luồng Network Roaming Watcher tự động giám sát thay đổi mạng máy tính
        t_roaming = threading.Thread(target=network_roaming_watcher_worker, args=(root_dir,), daemon=True)
        if os.getenv("AUTO_DETECT_WIFI", "false").lower() == "true":
            t_roaming.start()

        # 3. Kích hoạt luồng USB Serial Telemetry Bridge dự phòng nếu có cổng COM kết nối
        esp_port = args.com_port or find_esp32_com_port()
        if esp_port:
            esp32_bridge_thread = threading.Thread(target=serial_telemetry_bridge_worker,
                args=(esp_port, args.broker_port, args.broker_host, esp32_stop_event), name="esp32-usb")
            esp32_bridge_thread.start()

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
                "broker_host": args.broker_host,
                "broker_port": args.broker_port,
                "cycle_interval": 12.0
            },
            daemon=True
        )
        p_attack_gen.start()
        processes.append(p_attack_gen)

    # Thong bao va mo trinh duyet
    dashboard_url = f"http://localhost:{args.dashboard_port}"
    tshark_info = " [Wireshark/TShark Headless DPI Engine]" if (probe_mode == "host" and getattr(args, "use_tshark", True)) else ""
    probe_desc = f"Live PC Traffic Sniffer{tshark_info}" if probe_mode == "host" else "Physical ESP32 Wi-Fi Hardware"
    print("\n" + "=" * 70)
    print(" [OK] HE THONG DA HOAT DONG TOAN DIEN!")
    print(f"  -> Web Dashboard        : {dashboard_url}")
    print(f"  -> Luong Telemetry      : {probe_desc} -> MQTT:{args.broker_port} -> ML Engine -> WebSocket")
    print(f"  -> Model Classifier     : {clf_name}")
    print(f"  -> Model Anomaly        : {det_name}")
    print(f"  -> Probe Source         : {probe_mode.upper()} ({probe_desc})")
    demo_arch = "DEMO 2 (ESP32 Micro-Gateway DPI)" if is_gateway else ("DEMO 1 (Promiscuous Sniffer L2)" if probe_mode == "esp32" else "Host PC Sniffer")
    print(f"  -> Demo Architecture   : {demo_arch}")
    if is_gateway:
        print(f"  -> Gateway Wi-Fi SSID  : '{args.gateway_ssid}' (Pass: '{args.gateway_pass}')")
    traffic_domain_desc = "USTC-TFC2016 (10-feature L2-4 encrypted packet header)" if effective_traffic_mode == "encrypted" else "Edge-IIoTset (56-feature L7 DPI cleartext)"
    print(f"  -> Traffic Domain       : {effective_traffic_mode.upper()} ({traffic_domain_desc})")
    print(f"  -> Data Lakehouse       : {'BAT (Luu data_lake/raw/ partitioned theo ngay)' if getattr(args, 'record_lake', True) else 'TAT'}")
    print(f"  -> Digital Twin Live    : {'BAT' if probe_mode == 'host' else 'TAT (ESP32)'}")
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
            if probe_mode == "esp32" and p_radio is not None and not p_radio.is_alive():
                code = p_radio.exitcode
                cleanup()
                raise SystemExit(code or 1)
            if probe_mode == "host" and not p_sniffer.is_alive():
                print(f"[Host] Probe stopped (exitcode={p_sniffer.exitcode}); closing owned services")
                cleanup()
                if p_sniffer.exitcode:
                    raise SystemExit(p_sniffer.exitcode)
                break
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()