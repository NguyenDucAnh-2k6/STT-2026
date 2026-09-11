#!/usr/bin/env python3
"""
ESP32 Network Traffic Probe Simulator
======================================
Giả lập luồng telemetry gói tin mạng từ ESP32 gửi lên MQTT Mosquitto Broker.
Hỗ trợ cả chế độ:
 - Tự động đổi kịch bản (Auto-cycle) phục vụ demo và kiểm thử tự động.
 - Điều khiển bằng tay (Interactive Keyboard) để kích hoạt tấn công theo ý muốn.
"""

import os
import sys
import time
import json
import random
import paho.mqtt.client as mqtt
import threading
# Kịch bản giao thông mạng chuẩn hóa theo tập dữ liệu Edge-IIoTset (15 Classes)
MODES = {
    "0": "Normal",
    "1": "Port_Scanning",
    "2": "Vulnerability_scanner",
    "3": "DDoS_TCP",
    "4": "DDoS_UDP",
    "5": "Uploading",
    "6": "Backdoor"
}

ALIASES = {
    "NORMAL": "Normal",
    "0": "Normal",
    "PORT_SCAN": "Port_Scanning",
    "PORT_SCANNING": "Port_Scanning",
    "1": "Port_Scanning",
    "VULNERABILITY_SCANNER": "Vulnerability_scanner",
    "2": "Vulnerability_scanner",
    "SYN_FLOOD": "DDoS_TCP",
    "DDOS_TCP": "DDoS_TCP",
    "3": "DDoS_TCP",
    "VOLUMETRIC_DDOS": "DDoS_UDP",
    "DDOS_UDP": "DDoS_UDP",
    "4": "DDoS_UDP",
    "DATA_EXFILTRATION": "Uploading",
    "UPLOADING": "Uploading",
    "5": "Uploading",
    "BACKDOOR": "Backdoor",
    "6": "Backdoor"
}

current_mode = "Normal"
running = True

def generate_telemetry(mode: str, device_id: str = "ESP32-Simulated-Probe-01") -> dict:
    """Tạo bộ đặc trưng lưu lượng mạng theo kịch bản tương ứng khớp với Edge-IIoTset."""
    now_ms = int(time.time() * 1000)
    canon_mode = ALIASES.get(mode.upper(), mode)
    
    if canon_mode == "Normal":
        packet_rate = random.uniform(40.0, 180.0)
        avg_packet_size = random.uniform(320.0, 850.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.02, 0.08)
        ack_ratio = random.uniform(0.65, 0.85)
        udp_ratio = random.uniform(0.10, 0.30)
        icmp_ratio = random.uniform(0.00, 0.02)
        unique_dst_ports = random.randint(3, 16)
        tcp_count = int(packet_rate * (1.0 - udp_ratio - icmp_ratio) * 2)
        udp_count = int(packet_rate * udp_ratio * 2)
        icmp_count = int(packet_rate * icmp_ratio * 2)
        edge_flag = False
        edge_pred = "Normal"
        src_ip = "192.168.137.149"
        dst_ip = "192.168.137.1"
        src_port = 5683
        dst_port = 5683
        protocol = "CoAP"
        info_str = f"CON, MID:{random.randint(10000, 60000)}, GET /runtime"

    elif canon_mode == "Port_Scanning":
        packet_rate = random.uniform(350.0, 850.0)
        avg_packet_size = random.uniform(54.0, 90.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.65, 0.88)
        ack_ratio = random.uniform(0.05, 0.15)
        udp_ratio = random.uniform(0.10, 0.25)
        icmp_ratio = random.uniform(0.01, 0.05)
        unique_dst_ports = random.randint(80, 350)  # Quét liên tục hàng trăm port
        tcp_count = int(packet_rate * 0.75 * 2)
        udp_count = int(packet_rate * 0.20 * 2)
        icmp_count = int(packet_rate * 0.05 * 2)
        edge_flag = True
        edge_pred = "Port_Scanning"
        src_ip = "192.168.137.205"
        dst_ip = "192.168.137.1"
        src_port = random.randint(40000, 60000)
        dst_port = random.randint(1, 1024)
        protocol = "TCP"
        info_str = f"SYN Scan -> Target Port {dst_port}"

    elif canon_mode == "Vulnerability_scanner":
        packet_rate = random.uniform(220.0, 460.0)
        avg_packet_size = random.uniform(110.0, 240.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.35, 0.60)
        ack_ratio = random.uniform(0.35, 0.55)
        udp_ratio = random.uniform(0.05, 0.15)
        icmp_ratio = 0.0
        unique_dst_ports = random.randint(15, 60)  # Thăm dò một nhóm cổng dịch vụ
        tcp_count = int(packet_rate * 0.85 * 2)
        udp_count = int(packet_rate * 0.15 * 2)
        icmp_count = 0
        edge_flag = True
        edge_pred = "Vulnerability_scanner"
        src_ip = "192.168.137.210"
        dst_ip = "192.168.137.1"
        src_port = random.randint(30000, 50000)
        dst_port = random.choice([80, 443, 8080, 8443, 21, 22])
        protocol = "HTTP"
        info_str = f"Vulnerability Probe -> GET /wp-login.php?user=admin"

    elif canon_mode == "DDoS_TCP":
        packet_rate = random.uniform(1500.0, 3800.0)
        avg_packet_size = random.uniform(54.0, 74.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.88, 0.99)
        ack_ratio = random.uniform(0.01, 0.04)
        udp_ratio = random.uniform(0.01, 0.05)
        icmp_ratio = 0.0
        unique_dst_ports = random.randint(1, 4)
        tcp_count = int(packet_rate * 0.95 * 2)
        udp_count = int(packet_rate * 0.05 * 2)
        icmp_count = 0
        edge_flag = True
        edge_pred = "DDoS_TCP"
        src_ip = f"192.168.137.{random.randint(180, 240)}"
        dst_ip = "192.168.137.1"
        src_port = random.randint(10000, 65000)
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        info_str = f"[SYN] Flood -> Target Port {dst_port}"

    elif canon_mode == "DDoS_UDP":
        packet_rate = random.uniform(4000.0, 9500.0)
        avg_packet_size = random.uniform(900.0, 1450.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.05, 0.15)
        ack_ratio = random.uniform(0.10, 0.25)
        udp_ratio = random.uniform(0.75, 0.95)
        icmp_ratio = random.uniform(0.02, 0.08)
        unique_dst_ports = random.randint(5, 25)
        tcp_count = int(packet_rate * 0.15 * 2)
        udp_count = int(packet_rate * 0.80 * 2)
        icmp_count = int(packet_rate * 0.05 * 2)
        edge_flag = True
        edge_pred = "DDoS_UDP"
        src_ip = f"192.168.137.{random.randint(150, 254)}"
        dst_ip = "192.168.137.1"
        src_port = random.choice([53, 123, 1900])
        dst_port = random.randint(10000, 65000)
        protocol = "UDP"
        info_str = "UDP Amplification Volumetric Flood"

    elif canon_mode == "Uploading":
        packet_rate = random.uniform(120.0, 280.0)
        avg_packet_size = random.uniform(1420.0, 1490.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.01, 0.03)
        ack_ratio = random.uniform(0.90, 0.98)
        udp_ratio = random.uniform(0.00, 0.05)
        icmp_ratio = 0.0
        unique_dst_ports = random.randint(1, 2)
        tcp_count = int(packet_rate * 0.98 * 2)
        udp_count = int(packet_rate * 0.02 * 2)
        icmp_count = 0
        edge_flag = True
        edge_pred = "Uploading"
        src_ip = "192.168.137.149"
        dst_ip = "198.51.100.44"
        src_port = 54321
        dst_port = 443
        protocol = "TCP"
        info_str = "TLS Chunked Stream Exfiltration (Uploading)"

    else:  # Backdoor
        packet_rate = random.uniform(80.0, 180.0)
        avg_packet_size = random.uniform(450.0, 800.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.10, 0.25)
        ack_ratio = random.uniform(0.70, 0.85)
        udp_ratio = random.uniform(0.05, 0.15)
        icmp_ratio = 0.0
        unique_dst_ports = 1
        tcp_count = int(packet_rate * 0.90 * 2)
        udp_count = int(packet_rate * 0.10 * 2)
        icmp_count = 0
        edge_flag = True
        edge_pred = "Backdoor"
        src_ip = "192.168.137.149"
        dst_ip = "203.0.113.88"
        src_port = 4444
        dst_port = 4444
        protocol = "TCP"
        info_str = "Reverse Shell C2 Communication (Backdoor)"

    return {
        "device_id": device_id,
        "timestamp": now_ms,
        "mode_label": canon_mode,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": int(avg_packet_size),
        "info": info_str,
        "packet_rate": round(packet_rate, 2),
        "byte_rate": round(byte_rate, 2),
        "avg_packet_size": round(avg_packet_size, 1),
        "syn_ratio": round(syn_ratio, 3),
        "ack_ratio": round(ack_ratio, 3),
        "udp_ratio": round(udp_ratio, 3),
        "icmp_ratio": round(icmp_ratio, 3),
        "unique_dst_ports": unique_dst_ports,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "icmp_packets": icmp_count,
        "edge_prediction": edge_pred,
        "edge_flag": edge_flag
    }

def interactive_key_listener():
    """Lắng nghe phím bấm từ người dùng để đổi kịch bản tức thì."""
    global current_mode, running
    print("\n[Simulator Menu] Bam phim de kich hoat kich ban tan cong (Khop voi Edge-IIoTset):")
    print("  0: Normal (Giao thong binh thuong)")
    print("  1: Port_Scanning (Quet cong do tham)")
    print("  2: Vulnerability_scanner (Quet lo hong ung dung)")
    print("  3: DDoS_TCP (SYN Flood danh sap ket noi TCP)")
    print("  4: DDoS_UDP (Volumetric UDP Flood nghet bang thong)")
    print("  5: Uploading (Danh cap & trich xuat du lieu)")
    print("  6: Backdoor (Luu luong cua sau doc hai)")
    print("  q: Thoat simulator\n")
    
    while running:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            choice = line.strip()
            if choice.lower() == 'q':
                running = False
                break
            elif choice in MODES:
                current_mode = MODES[choice]
                print(f" >>> Chuyen trang thai sang: [{current_mode}] <<<")
            else:
                print(" Phim khong hop le. Chon tu 0 den 6 hoac q.")
        except Exception:
            break

def start_simulator(
    host: str = "127.0.0.1",
    port: int = 1883,
    interval: float = 2.0,
    auto_cycle: bool = True,
    device_id: str = "ESP32-Simulated-Probe-01"
):
    """
    Khởi động vòng lặp phát sinh lưu lượng mạng giả lập gửi lên MQTT Broker.
    Có thể gọi trực tiếp từ run_system.py hoặc script khác.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=device_id)

    def on_control_message(c, userdata, msg):
        global current_mode
        try:
            data = json.loads(msg.payload.decode("utf-8"))
            if data.get("command") == "INJECT_MODE":
                req_mode = data.get("mode", "")
                canon = ALIASES.get(req_mode.upper(), req_mode)
                current_mode = canon
                print(f"\n[Remote Control] >>> Web Dashboard chuyen kịch ban sang: [{current_mode}] <<<\n")
        except Exception as err:
            print(f"[Remote Control] Loi parse lenh: {err}")

    client.on_message = on_control_message

    try:
        client.connect(host, port, keepalive=60)
        client.subscribe("edge/simulator/control")
        client.loop_start()
        print(f"[Simulator] Da ket noi den MQTT Broker {host}:{port}")
    except Exception as e:
        print(f"[Simulator] Khong the ket noi den MQTT Broker tai {host}:{port}: {e}")
        print("  -> Vui long kiem tra Mosquitto Broker hoac chay broker/embedded_broker.py!")
        return

    # Gửi thông điệp online
    client.publish("edge/nodes/status", json.dumps({"status": "online", "device_id": device_id}))

    global current_mode, running

    if not auto_cycle:
        # Bật luồng đọc phím tương tác nếu có terminal
        if sys.stdin.isatty():
            t = threading.Thread(target=interactive_key_listener, daemon=True)
            t.start()
        else:
            print("[Simulator] Dang chay che do non-interactive. Chay voi NORMAL traffic.")
    else:
        print("[Simulator] Che do AUTO-CYCLE bat. Se tu dong chuyen kịch ban moi 15 giay.")

    cycle_modes = ["Normal", "Port_Scanning", "Normal", "Vulnerability_scanner", "Normal", "DDoS_TCP", "Normal", "DDoS_UDP", "Normal", "Uploading"]
    cycle_idx = 0
    last_cycle_time = time.time()

    try:
        while running:
            if auto_cycle:
                if time.time() - last_cycle_time > 15.0:
                    last_cycle_time = time.time()
                    cycle_idx = (cycle_idx + 1) % len(cycle_modes)
                    current_mode = cycle_modes[cycle_idx]
                    print(f"\n[AUTO-CYCLE] >>> Chuyen sang kich ban: [{current_mode}] <<<\n")

            payload = generate_telemetry(current_mode, device_id)
            json_str = json.dumps(payload)

            client.publish("edge/telemetry/traffic", json_str)
            
            # Nếu có cờ bất thường cục bộ từ edge
            if payload["edge_flag"]:
                client.publish("edge/alerts/high_priority", json_str)

            print(f"[{payload['mode_label']:^15}] Pkts/s: {payload['packet_rate']:>7.1f} | "
                  f"Bytes/s: {payload['byte_rate']:>9.0f} | SYN: {payload['syn_ratio']:>5.2f} | "
                  f"Ports: {payload['unique_dst_ports']:>3} | Edge Pred: {payload['edge_prediction']}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[Simulator] Dang dung simulator...")
    finally:
        client.publish("edge/nodes/status", json.dumps({"status": "offline", "device_id": device_id}))
        client.loop_stop()
        client.disconnect()
        print("[Simulator] Da thoat.")


def main():
    host = os.getenv("MQTT_HOST", "127.0.0.1")
    port = int(os.getenv("MQTT_PORT", 1883))
    interval = float(os.getenv("SIMULATOR_INTERVAL", 2.0))
    auto_cycle = os.getenv("SIMULATOR_AUTO_CYCLE", "true").lower() in ("1", "true", "yes")
    device_id = os.getenv("SIMULATOR_DEVICE_ID", "ESP32-Simulated-Probe-01")

    start_simulator(
        host=host,
        port=port,
        interval=interval,
        auto_cycle=auto_cycle,
        device_id=device_id
    )


if __name__ == "__main__":
    main()
