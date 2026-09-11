#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Master System Launcher
==========================================================
Chỉ dẫn vận hành hệ thống:
- Script này là ENTRYPOINT DUY NHẤT để khởi động toàn bộ hệ sinh thái runtime:
  1. Tự động kiểm tra các mô hình Artifacts đã được huấn luyện sẵn trong ml_engine/models/.
  2. Khởi động MQTT Broker (Mosquitto hoặc Python Embedded Broker port 1883).
  3. Khởi động ML Real-time Inference Engine (kết nối MQTT, suy luận song song 2 tầng).
  4. Khởi động Web Dashboard Server (FastAPI + WebSockets port 8000).
  5. Khởi động Telemetry Probe (ESP32 Simulator, Host PC Sniffer hoặc đón ESP32 thật).
  6. Tự động mở trình duyệt hiển thị Cyberpunk SOC Web Dashboard.

Cú pháp sử dụng:
    python run_system.py
    python run_system.py --probe host
    python run_system.py --probe esp32
    python run_system.py --threshold 0.60 --no-browser
    python run_system.py --help
"""

import os
import sys
import time
import socket
import argparse
import subprocess
import webbrowser
import signal
import multiprocessing

# Đảm bảo thư mục gốc dự án luôn nằm trong sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from broker.embedded_broker import start_embedded_broker
from firmware.simulator.esp32_simulator import start_simulator
from firmware.host_probe.host_sniffer import start_host_sniffer

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


def sync_env_to_firmware(root_dir: str):
    """Đồng bộ tự động WiFi SSID/Password và MQTT IP từ .env vào firmware/esp32_probe/credentials.h."""
    env_file = os.path.join(root_dir, ".env")
    cred_file = os.path.join(root_dir, "firmware", "esp32_probe", "credentials.h")
    if os.path.exists(env_file):
        wifi_ssid = os.getenv("WIFI_SSID", "your_wifi_ssid").strip('"\'')
        wifi_pass = os.getenv("WIFI_PASSWORD", "your_wifi_password").strip('"\'')
        mqtt_host = os.getenv("MQTT_BROKER_HOST", "127.0.0.1").strip('"\'')
        
        content = f"""#ifndef CREDENTIALS_H
#define CREDENTIALS_H

// ====================================================================
// ESP32 LOCAL CREDENTIALS (TU DONG DONG BO TU .env - DO NOT COMMIT TO GIT)
// ====================================================================

#define WIFI_SSID "{wifi_ssid}"
#define WIFI_PASSWORD "{wifi_pass}"
#define MQTT_BROKER_HOST "{mqtt_host}"

#endif // CREDENTIALS_H
"""
        try:
            with open(cred_file, "w", encoding="utf-8") as f:
                f.write(content)
            print("  [Config] Da tu dong dong bo thong tin WiFi & Broker tu .env vao firmware/esp32_probe/credentials.h")
        except Exception as e:
            pass


def check_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Kiểm tra xem một cổng TCP có đang được tiến trình khác chiếm dụng hay không."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.8)
        return s.connect_ex((host, port)) == 0


def cleanup(signum=None, frame=None):
    """Dọn dẹp và kết thúc toàn bộ các tiến trình con an toàn khi người dùng nhấn Ctrl+C."""
    print("\n[Launcher] Dang dong tat ca cac tien trinh con...")
    for p in processes:
        try:
            p.terminate()
            if hasattr(p, "wait"):
                p.wait(timeout=2)
            elif hasattr(p, "join"):
                p.join(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("[Launcher] He thong da tat hoan toan.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Runtime Launcher for Edge AI Network Anomaly Detection System (Loads Pre-trained Artifacts)"
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
        default="sim",
        choices=["sim", "host", "esp32"],
        help="Chon nguon telemetry: 'sim' (ESP32 Simulator), 'host' (bat mang that tu may tinh), 'esp32' (cho ESP32 vat ly qua WiFi)"
    )
    parser.add_argument(
        "--no-sim",
        action="store_true",
        help="Khong tu dong chay ESP32 simulator (tuong duong --probe esp32)"
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

    args = parser.parse_args()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    # Xac dinh che do probe
    probe_mode = "esp32" if args.no_sim else args.probe

    print("=" * 70)
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - RUNTIME LAUNCHER")
    print(f"   [Mode: INFERENCE ONLY (LOAD ARTIFACTS)] | [Probe: {probe_mode.upper()}]")
    print("=" * 70)

    # Đồng bộ thông tin môi trường vào firmware
    sync_env_to_firmware(root_dir)

    # 1. Kiem tra MQTT Broker
    print(f"\n[1/5] Kiem tra MQTT Broker tai port {args.broker_port}...")
    if check_port_in_use(args.broker_port):
        print(f"  -> Da phat hien MQTT Broker dang hoat dong tai port {args.broker_port}.")
    else:
        print(f"  -> Chua co Broker. Dang khoi dong Embedded Python MQTT Broker tren port {args.broker_port}...")
        p_broker = multiprocessing.Process(
            target=start_embedded_broker,
            kwargs={"host": "127.0.0.1", "port": args.broker_port},
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
    env["MQTT_PORT"] = str(args.broker_port)
    p_dashboard = subprocess.Popen([python_exe, dashboard_script], env=env)
    processes.append(p_dashboard)
    time.sleep(2.0)

    # 5. Khoi dong Telemetry Probe (Simulator, Host Sniffer, hoac cho ESP32 vat ly)
    if probe_mode == "sim":
        print("\n[5/5] Khoi dong ESP32 Network Traffic Simulator (Auto-cycle mode)...")
        p_sim = multiprocessing.Process(
            target=start_simulator,
            kwargs={
                "host": "127.0.0.1",
                "port": args.broker_port,
                "interval": 2.0,
                "auto_cycle": True,
                "device_id": "ESP32-Simulated-Probe-01"
            },
            daemon=True
        )
        p_sim.start()
        processes.append(p_sim)
    elif probe_mode == "host":
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
        print("\n[5/5] Che do ESP32 vat ly: He thong dang cho du lieu tu phan cung ESP32 qua WiFi/MQTT...")
        print("  -> Khong bat Simulator va khong bat Host Sniffer.")

    # Thong bao va mo trinh duyet
    dashboard_url = f"http://localhost:{args.dashboard_port}"
    probe_desc = "Live PC Traffic" if probe_mode == "host" else ("Automated Simulator" if probe_mode == "sim" else "Physical ESP32 Hardware")
    print("\n" + "=" * 70)
    print(" [OK] HE THONG DA HOAT DONG TOAN DIEN!")
    print(f"  -> Truy cap Web Dashboard: {dashboard_url}")
    print(f"  -> Luong Telemetry: {probe_desc} -> MQTT:{args.broker_port} -> ML Engine -> WebSocket")
    print(f"  -> Model Classifier: {clf_name}")
    print(f"  -> Model Anomaly:    {det_name}")
    print(f"  -> Probe Source:     {probe_mode.upper()} ({probe_desc})")
    print(f"  -> Nguong canh bao:  {args.threshold}")
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
    main()
