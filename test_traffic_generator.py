#!/usr/bin/env python3
"""
Real-Air Wi-Fi Traffic Generator for Testing ESP32 Sniffer
=========================================================
Bắn lưu lượng mạng thật qua sóng Wi-Fi từ Laptop để ESP32 bắt được:
1. Port Scan: Quét đồng thời hàng trăm cổng -> ESP32 tăng vọt 'unique_dst_ports' và 'syn_ratio'.
2. UDP Flood: Bắn dồn dập hàng nghìn gói UDP -> ESP32 tăng vọt 'packet_rate' và 'byte_rate'.
"""

import os
import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def run_port_scan(target_ip: str, num_ports: int = 400, repeat: int = 5):
    print(f"\n[>>>] BẮT ĐẦU GIẢ LẬP PORT SCAN THẬT TỚI {target_ip}...")
    print(f"     -> Quét {num_ports} cổng liên tục trong {repeat} đợt.")
    print("     -> Quan sát ESP32 Serial Monitor và Web Dashboard:\n")
    
    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            s.connect_ex((target_ip, port))
            s.close()
        except Exception:
            pass

    for r in range(repeat):
        print(f"  [Đợt {r+1}/{repeat}] Đang gửi hàng loạt gói TCP SYN...")
        with ThreadPoolExecutor(max_workers=60) as ex:
            ex.map(probe, range(20, 20 + num_ports))
        time.sleep(0.5)
    print("\n[V] Hoàn tất đợt Port Scan!")

def run_udp_flood(target_ip: str, target_port: int = 9999, packets: int = 8000):
    print(f"\n[>>>] BẮT ĐẦU GIẢ LẬP UDP VOLUMETRIC FLOOD TỚI {target_ip}:{target_port}...")
    print(f"     -> Bắn {packets} gói tin UDP dung lượng cao...")
    print("     -> Quan sát biểu đồ Pkts/s và KBytes/s vọt lên đỉnh:\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"AERO_SECURITY_TEST_PACKET_OVER_THE_AIR_" * 16 # ~600 bytes
    
    start = time.time()
    sent = 0
    for i in range(packets):
        try:
            s.sendto(payload, (target_ip, target_port))
            sent += 1
        except Exception:
            pass
        if (i + 1) % 2000 == 0:
            print(f"  -> Đã bắn {i + 1}/{packets} gói tin...")
            time.sleep(0.1) # Nhả nhẹ để không nghẽn buffer card mạng
    duration = time.time() - start
    s.close()
    print(f"\n[V] Hoàn tất UDP Flood! Đã gửi {sent} gói trong {duration:.2f}s ({sent/duration:.0f} pkts/s).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real Wi-Fi Traffic Generator for AERO ESP32 Demo")
    parser.add_argument("--mode", choices=["scan", "flood", "all"], default="all",
                        help="Chế độ: 'scan' (Port Scan), 'flood' (UDP Flood), 'all' (Chạy cả hai)")
    parser.add_argument("--target", default="10.24.47.189",
                        help="IP đích (mặc định là Gateway Nokia 5.3: 10.24.47.189)")
    args = parser.parse_args()

    if args.mode in ["scan", "all"]:
        run_port_scan(args.target)
        if args.mode == "all":
            time.sleep(2)
    if args.mode in ["flood", "all"]:
        run_udp_flood(args.target)
