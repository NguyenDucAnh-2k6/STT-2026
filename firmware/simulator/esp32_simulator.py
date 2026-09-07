#!/usr/bin/env python3
"""
ESP32 Network Traffic Probe Simulator
======================================
Giả lập luồng telemetry gói tin mạng từ ESP32 gửi lên MQTT Mosquitto Broker.
Hỗ trợ cả chế độ:
 - Tự động đổi kịch bản (Auto-cycle) phục vụ demo và kiểm thử tự động.
 - Điều khiển bằng tay (Interactive Keyboard) để kích hoạt tấn công theo ý muốn.
"""

import sys
import time
import json
import random
import argparse
import threading
import paho.mqtt.client as mqtt

# Kịch bản giao thông mạng
MODES = {
    "0": "NORMAL",
    "1": "SYN_FLOOD",
    "2": "PORT_SCAN",
    "3": "VOLUMETRIC_DDOS",
    "4": "DATA_EXFILTRATION"
}

current_mode = "NORMAL"
running = True

def generate_telemetry(mode: str, device_id: str = "ESP32-Simulated-Probe-01") -> dict:
    """Tạo bộ đặc trưng lưu lượng mạng theo kịch bản tương ứng."""
    now_ms = int(time.time() * 1000)
    
    if mode == "NORMAL":
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

    elif mode == "SYN_FLOOD":
        packet_rate = random.uniform(1500.0, 3800.0)
        avg_packet_size = random.uniform(54.0, 74.0)  # Gói TCP SYN thường chỉ 60-70 bytes
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.88, 0.99)
        ack_ratio = random.uniform(0.01, 0.04)
        udp_ratio = random.uniform(0.01, 0.05)
        icmp_ratio = 0.0
        unique_dst_ports = random.randint(1, 5)  # Thường nhắm vào 1 hoặc vài port cụ thể (80, 443)
        tcp_count = int(packet_rate * 0.95 * 2)
        udp_count = int(packet_rate * 0.05 * 2)
        icmp_count = 0
        edge_flag = True
        edge_pred = "SYN Flood (Detected on Edge)"

    elif mode == "PORT_SCAN":
        packet_rate = random.uniform(350.0, 850.0)
        avg_packet_size = random.uniform(54.0, 90.0)
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.60, 0.85)
        ack_ratio = random.uniform(0.05, 0.15)
        udp_ratio = random.uniform(0.15, 0.35)
        icmp_ratio = random.uniform(0.02, 0.08)
        unique_dst_ports = random.randint(80, 350)  # Quét liên tục hàng trăm port
        tcp_count = int(packet_rate * 0.70 * 2)
        udp_count = int(packet_rate * 0.25 * 2)
        icmp_count = int(packet_rate * 0.05 * 2)
        edge_flag = True
        edge_pred = "Port Scan (Detected on Edge)"

    elif mode == "VOLUMETRIC_DDOS":
        packet_rate = random.uniform(4000.0, 9500.0)
        avg_packet_size = random.uniform(900.0, 1450.0)  # Packet to làm đầy băng thông
        byte_rate = packet_rate * avg_packet_size
        syn_ratio = random.uniform(0.05, 0.20)
        ack_ratio = random.uniform(0.10, 0.30)
        udp_ratio = random.uniform(0.70, 0.92)  # Thường là UDP Flood (NTP/DNS amplification)
        icmp_ratio = random.uniform(0.05, 0.15)
        unique_dst_ports = random.randint(5, 25)
        tcp_count = int(packet_rate * 0.15 * 2)
        udp_count = int(packet_rate * 0.80 * 2)
        icmp_count = int(packet_rate * 0.05 * 2)
        edge_flag = True
        edge_pred = "Volumetric DDoS (Detected on Edge)"

    elif mode == "DATA_EXFILTRATION":
        packet_rate = random.uniform(120.0, 280.0)
        avg_packet_size = random.uniform(1420.0, 1490.0)  # Đầy kích thước MTU (~1500 bytes)
        byte_rate = packet_rate * avg_packet_size  # Lưu lượng byte rất cao dù số gói ít
        syn_ratio = random.uniform(0.01, 0.03)
        ack_ratio = random.uniform(0.90, 0.98)
        udp_ratio = random.uniform(0.00, 0.05)
        icmp_ratio = 0.0
        unique_dst_ports = random.randint(1, 2)
        tcp_count = int(packet_rate * 0.98 * 2)
        udp_count = int(packet_rate * 0.02 * 2)
        icmp_count = 0
        edge_flag = False  # Khó phát hiện nếu chỉ dùng rule đơn giản trên ESP32, cần ML phát hiện!
        edge_pred = "Normal"

    return {
        "device_id": device_id,
        "timestamp": now_ms,
        "mode_label": mode,
        "packet_rate": round(packet_rate, 2),
        "byte_rate": round(byte_rate, 2),
        "avg_packet_size": round(avg_packet_size, 1),
        "syn_ratio": round(syn_ratio, 4),
        "ack_ratio": round(ack_ratio, 4),
        "udp_ratio": round(udp_ratio, 4),
        "icmp_ratio": round(icmp_ratio, 4),
        "unique_dst_ports": unique_dst_ports,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "edge_flag": edge_flag,
        "edge_prediction": edge_pred
    }

def interactive_key_listener():
    """Lắng nghe phím bấm từ người dùng để đổi kịch bản tức thì."""
    global current_mode, running
    print("\n[Simulator Menu] Bam phim de kich hoat kich ban tan cong:")
    print("  0: NORMAL (Giao thong binh thuong)")
    print("  1: SYN_FLOOD (Tan cong tran ngap goi SYN)")
    print("  2: PORT_SCAN (Tan cong quet cong lien tuc)")
    print("  3: VOLUMETRIC_DDOS (Tan cong nghet bang thong UDP)")
    print("  4: DATA_EXFILTRATION (Ranh ma danh cap du lieu dung luong lon)")
    print("  q: Thoat simulator\n")
    
    while running:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            choice = line.strip().lower()
            if choice == 'q':
                running = False
                break
            elif choice in MODES:
                current_mode = MODES[choice]
                print(f" >>> Chuyen trang thai sang: [{current_mode}] <<<")
            else:
                print(" Phim khong hop le. Chon tu 0 den 4 hoac q.")
        except Exception:
            break

def main():
    parser = argparse.ArgumentParser(description="ESP32 Network Traffic Probe Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="MQTT Broker Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT Broker Port (default: 1883)")
    parser.add_argument("--interval", type=float, default=2.0, help="Sampling interval in seconds (default: 2.0s)")
    parser.add_argument("--auto-cycle", action="store_true", help="Tu dong luan phien cac loai tan cong sau moi 15 giay")
    parser.add_argument("--device-id", default="ESP32-Simulated-Probe-01", help="Device ID")
    args = parser.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.device_id)

    def on_control_message(c, userdata, msg):
        global current_mode
        try:
            data = json.loads(msg.payload.decode("utf-8"))
            if data.get("command") == "INJECT_MODE":
                req_mode = data.get("mode", "").upper()
                if req_mode in ["NORMAL", "SYN_FLOOD", "PORT_SCAN", "VOLUMETRIC_DDOS", "DATA_EXFILTRATION"]:
                    current_mode = req_mode
                    print(f"\n[Remote Control] >>> Web Dashboard chuyen kịch ban sang: [{current_mode}] <<<\n")
        except Exception as err:
            print(f"[Remote Control] Loi parse lenh: {err}")

    client.on_message = on_control_message

    try:
        client.connect(args.host, args.port, keepalive=60)
        client.subscribe("edge/simulator/control")
        client.loop_start()
        print(f"[Simulator] Da ket noi den MQTT Broker {args.host}:{args.port}")
    except Exception as e:
        print(f"[Simulator] Khong the ket noi den MQTT Broker tai {args.host}:{args.port}: {e}")
        print("  -> Vui long kiem tra Mosquitto Broker hoac chay broker/embedded_broker.py!")
        sys.exit(1)

    # Gửi thông điệp online
    client.publish("edge/nodes/status", json.dumps({"status": "online", "device_id": args.device_id}))

    global current_mode, running

    if not args.auto_cycle:
        # Bật luồng đọc phím tương tác nếu có terminal
        if sys.stdin.isatty():
            t = threading.Thread(target=interactive_key_listener, daemon=True)
            t.start()
        else:
            print("[Simulator] Dang chay che do non-interactive. Chay voi NORMAL traffic.")
    else:
        print("[Simulator] Che do AUTO-CYCLE bat. Se tu dong chuyen kịch ban moi 15 giay.")

    cycle_modes = ["NORMAL", "SYN_FLOOD", "NORMAL", "PORT_SCAN", "NORMAL", "VOLUMETRIC_DDOS", "NORMAL", "DATA_EXFILTRATION"]
    cycle_idx = 0
    last_cycle_time = time.time()

    try:
        while running:
            if args.auto_cycle:
                if time.time() - last_cycle_time > 15.0:
                    last_cycle_time = time.time()
                    cycle_idx = (cycle_idx + 1) % len(cycle_modes)
                    current_mode = cycle_modes[cycle_idx]
                    print(f"\n[AUTO-CYCLE] >>> Chuyen sang kich ban: [{current_mode}] <<<\n")

            payload = generate_telemetry(current_mode, args.device_id)
            json_str = json.dumps(payload)

            client.publish("edge/telemetry/traffic", json_str)
            
            # Nếu có cờ bất thường cục bộ từ edge
            if payload["edge_flag"]:
                client.publish("edge/alerts/high_priority", json_str)

            print(f"[{payload['mode_label']:^15}] Pkts/s: {payload['packet_rate']:>7.1f} | "
                  f"Bytes/s: {payload['byte_rate']:>9.0f} | SYN: {payload['syn_ratio']:>5.2f} | "
                  f"Ports: {payload['unique_dst_ports']:>3} | Edge Pred: {payload['edge_prediction']}")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[Simulator] Dang dung simulator...")
    finally:
        client.publish("edge/nodes/status", json.dumps({"status": "offline", "device_id": args.device_id}))
        client.loop_stop()
        client.disconnect()
        print("[Simulator] Da thoat.")

if __name__ == "__main__":
    main()
