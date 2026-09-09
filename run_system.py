#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Master System Launcher
==========================================================
Chỉ dẫn vận hành hệ thống:
- Script này là Entry Point chính để khởi động toàn bộ hệ sinh thái chỉ bằng 1 lệnh:
  1. Kiểm tra & tự động khởi động MQTT Broker (Mosquitto hoặc Python Embedded Broker port 1883).
  2. Kiểm tra trọng số mô hình hoặc huấn luyện mới theo flag (--classifier & --anomaly-model).
  3. Khởi động Real-time Inference Engine kết nối MQTT.
  4. Khởi động Web Dashboard Server (FastAPI + WebSockets port 8000).
  5. Khởi động ESP32 Network Traffic Simulator phát luồng dữ liệu thời gian thực.
  6. Tự động mở trình duyệt hiển thị Dashboard giám sát an ninh mạng.

Cú pháp sử dụng:
    python run_system.py
    python run_system.py --classifier random_forest
    python run_system.py --classifier decision_tree --anomaly-model isolation_forest --retrain
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

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

processes = []


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
            p.wait(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("[Launcher] He thong da tat hoan toan.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Master Launcher for Edge AI Network Anomaly Detection System"
    )
    parser.add_argument(
        "--classifier",
        default="decision_tree",
        choices=["decision_tree", "random_forest", "extra_trees", "gradient_boosting", "mlp", "logistic_regression", "ensemble_voting"],
        help="Chon mo hinh phan loai tan cong (mac dinh: decision_tree)"
    )
    parser.add_argument(
        "--anomaly-model",
        default="isolation_forest",
        choices=["isolation_forest", "one_class_svm", "elliptic_envelope", "lof"],
        help="Chon mo hinh phat hien bat thuong (mac dinh: isolation_forest)"
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Bat buoc huan luyen lai mo hinh theo flag truoc khi khoi dong"
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
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - ONE-CLICK LAUNCHER")
    print(f"   [Classifier: {args.classifier}] | [Anomaly: {args.anomaly_model}] | [Probe: {probe_mode.upper()}]")
    print("=" * 70)

    # 1. Kiem tra MQTT Broker
    print(f"\n[1/5] Kiem tra MQTT Broker tai port {args.broker_port}...")
    if check_port_in_use(args.broker_port):
        print(f"  -> Da phat hien MQTT Broker dang hoat dong tai port {args.broker_port}.")
    else:
        print(f"  -> Chua co Broker. Dang khoi dong Embedded Python MQTT Broker tren port {args.broker_port}...")
        broker_script = os.path.join(root_dir, "broker", "embedded_broker.py")
        p_broker = subprocess.Popen([python_exe, broker_script])
        processes.append(p_broker)
        time.sleep(1.5)
        if check_port_in_use(args.broker_port):
            print(f"  -> Embedded MQTT Broker da san sang tren port {args.broker_port}!")
        else:
            print("  [Canh bao] Chua khoi dong duoc broker, he thong se tiep tuc...")

    # 2. Kiem tra Model Weights & Huan luyen neu can
    print("\n[2/5] Kiem tra mo hinh Machine Learning...")
    model_path = os.path.join(root_dir, "ml_engine", "models", "attack_classifier.joblib")
    meta_path = os.path.join(root_dir, "ml_engine", "models", "model_metadata.json")

    need_train = args.retrain or not os.path.exists(model_path)
    if not need_train and os.path.exists(meta_path):
        import json
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                if meta.get("classifier_type") != args.classifier or meta.get("anomaly_detector_type") != args.anomaly_model:
                    print(f"  -> Phat hien yeu cau doi model tu '{meta.get('classifier_type')}' sang '{args.classifier}'.")
                    need_train = True
        except Exception:
            pass

    if need_train:
        print(f"  -> Bat dau huan luyen mo hinh: [{args.classifier}] + [{args.anomaly_model}]...")
        train_cmd = [
            python_exe,
            os.path.join(root_dir, "ml_engine", "train.py"),
            "--classifier", args.classifier,
            "--anomaly-model", args.anomaly_model
        ]
        subprocess.run(train_cmd, check=True)
    else:
        print(f"  -> Models [{args.classifier}] da ton tai va san sang suy luan!")

    # 3. Khoi dong ML Inference Service
    print("\n[3/5] Khoi dong ML Real-time Inference Engine...")
    inference_script = os.path.join(root_dir, "ml_engine", "inference_service.py")
    inference_cmd = [
        python_exe,
        inference_script,
        "--port", str(args.broker_port),
        "--threshold", str(args.threshold)
    ]
    p_inference = subprocess.Popen(inference_cmd)
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
        sim_script = os.path.join(root_dir, "firmware", "simulator", "esp32_simulator.py")
        p_sim = subprocess.Popen([python_exe, sim_script, "--auto-cycle", "--port", str(args.broker_port)])
        processes.append(p_sim)
    elif probe_mode == "host":
        print("\n[5/5] Khoi dong Host PC Live Network Sniffer (Bat luu luong mang that cua may tinh)...")
        sniffer_script = os.path.join(root_dir, "firmware", "host_probe", "host_sniffer.py")
        p_sniffer = subprocess.Popen([python_exe, sniffer_script, "--port", str(args.broker_port)])
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
    print(f"  -> Model Classifier: {args.classifier}")
    print(f"  -> Model Anomaly:    {args.anomaly_model}")
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
