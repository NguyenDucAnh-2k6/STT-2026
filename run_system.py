#!/usr/bin/env python3
"""
Edge AI Network Anomaly Detection - Master System Launcher
==========================================================
Chạy toàn bộ hệ thống bằng 1 lệnh duy nhất:
 1. Tự động kiểm tra / khởi động MQTT Broker (Mosquitto hoặc Embedded Broker).
 2. Kiểm tra và huấn luyện mô hình ML nếu chưa có.
 3. Khởi động ML Real-time Inference Engine.
 4. Khởi động FastAPI WebSocket Web Dashboard (http://localhost:8000).
 5. Khởi động ESP32 Simulator phát telemetry thời gian thực.
 6. Tự động mở trình duyệt hiển thị Dashboard.
"""

import os
import sys
import time
import socket
import subprocess
import webbrowser
import signal

processes = []

def check_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.8)
        return s.connect_ex((host, port)) == 0

def cleanup(signum=None, frame=None):
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
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable

    print("=" * 70)
    print("   EDGE AI NETWORK ANOMALY DETECTION SYSTEM - ONE-CLICK LAUNCHER")
    print("=" * 70)

    # 1. Kiem tra MQTT Broker
    print("\n[1/5] Kiem tra MQTT Broker tai port 1883...")
    if check_port_in_use(1883):
        print("  -> Da phat hien MQTT Broker dang hoat dong (Mosquitto/Local Broker).")
    else:
        print("  -> Chua co Broker chay. Dang khoi dong Embedded Python MQTT Broker...")
        broker_script = os.path.join(root_dir, "broker", "embedded_broker.py")
        p_broker = subprocess.Popen([python_exe, broker_script])
        processes.append(p_broker)
        time.sleep(1.5)
        if check_port_in_use(1883):
            print("  -> Embedded MQTT Broker da san sang tren port 1883!")
        else:
            print("  [Canh bao] Chua khoi dong duoc broker, se tiep tuc thu...")

    # 2. Kiem tra Model Weights
    print("\n[2/5] Kiem tra mo hinh Machine Learning...")
    model_path = os.path.join(root_dir, "ml_engine", "models", "attack_classifier.joblib")
    if not os.path.exists(model_path):
        print("  -> Chua tim thay weights, bat dau huan luyen Isolation Forest & Classifier...")
        subprocess.run([python_exe, os.path.join(root_dir, "ml_engine", "train.py")], check=True)
        subprocess.run([python_exe, os.path.join(root_dir, "ml_engine", "export_tinyml.py")], check=True)
    else:
        print("  -> Models da ton tai va san sang suy luan!")

    # 3. Khoi dong ML Inference Service
    print("\n[3/5] Khoi dong ML Real-time Inference Engine...")
    inference_script = os.path.join(root_dir, "ml_engine", "inference_service.py")
    p_inference = subprocess.Popen([python_exe, inference_script])
    processes.append(p_inference)
    time.sleep(1.0)

    # 4. Khoi dong Dashboard Backend (FastAPI)
    print("\n[4/5] Khoi dong Web Dashboard Server (FastAPI + WebSockets)...")
    dashboard_script = os.path.join(root_dir, "dashboard", "backend", "app.py")
    p_dashboard = subprocess.Popen([python_exe, dashboard_script])
    processes.append(p_dashboard)
    time.sleep(2.0)

    # 5. Khoi dong ESP32 Simulator
    print("\n[5/5] Khoi dong ESP32 Network Traffic Simulator (Auto-cycle mode)...")
    sim_script = os.path.join(root_dir, "firmware", "simulator", "esp32_simulator.py")
    p_sim = subprocess.Popen([python_exe, sim_script, "--auto-cycle"])
    processes.append(p_sim)

    # Mo trinh duyet
    dashboard_url = "http://localhost:8000"
    print("\n" + "=" * 70)
    print(f" [OK] HE THONG DA HOAT DONG TOAN DIEN!")
    print(f"  -> Truy cap Web Dashboard: {dashboard_url}")
    print(f"  -> Luong Telemetry: ESP32 -> Mosquitto MQTT:1883 -> ML Engine -> WebSocket")
    print(f"  -> Nhan Ctrl + C de dung toan bo he thong.")
    print("=" * 70 + "\n")

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
