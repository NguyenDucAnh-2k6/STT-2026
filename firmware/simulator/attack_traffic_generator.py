"""
Attack Traffic Generator Module
===============================
Module phát sinh các đợt tấn công mạng thật 100% qua socket (TCP/UDP/IP):
1. Port Scanning: Quét hàng trăm cổng TCP SYN (tăng unique_dst_ports, syn_ratio).
2. DDoS UDP Flood: Bắn hàng nghìn gói UDP dung lượng cao liên tục (tăng packet_rate, byte_rate, udp_ratio).
3. DDoS TCP SYN Flood: Gửi dồn dập gói tin TCP SYN tới cổng dịch vụ (tăng syn_ratio, packet_rate).
4. Vulnerability Scanner: Quét các cổng dịch vụ web và quản trị đặc thù.
5. Uploading (Data Exfiltration): Truyền tải luồng dữ liệu TCP dung lượng lớn.

Đặc tính:
- Bắn duy trì liên tục (Sustained Continuous Attack Flow) khi kích hoạt kịch bản,
  đảm bảo tốc độ gói tin (pkts/s) và băng thông (bytes/s) duy trì ở mức cao
  cho đến khi người dùng nhấn Normal Traffic / Stop.
- Tích hợp điều khiển qua MQTT topic:
  + Lắng nghe: 'edge/attack/control'
  + Báo cáo trạng thái: 'edge/attack/status'
"""

import os
import sys
import time
import json
import socket
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
import paho.mqtt.client as mqtt

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def detect_target_ip() -> str:
    """Tự động xác định chính xác IP Default Gateway thực tế trên hệ thống."""
    env_target = os.getenv("ATTACK_TARGET_IP")
    if env_target and env_target.strip():
        return env_target.strip()

    # 1. Hệ điều hành Windows: Quét trực tiếp card Wi-Fi hoặc route print
    if sys.platform == "win32":
        try:
            import subprocess, re
            out_if = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, stderr=subprocess.DEVNULL)
            m_iface = re.search(r"^\s*Name\s*:\s*(.+)$", out_if, re.M)
            iface = m_iface.group(1).strip() if m_iface else "Wi-Fi"
            out_addr = subprocess.check_output(f'netsh interface ipv4 show addresses "{iface}"', shell=True, text=True, stderr=subprocess.DEVNULL)
            m_gw = re.search(r"Default Gateway:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out_addr)
            if m_gw:
                return m_gw.group(1).strip()
        except Exception:
            pass

        try:
            import subprocess
            out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] not in ("On-link", "0.0.0.0", "127.0.0.1"):
                        return parts[2]
        except Exception:
            pass

    # 2. Hệ điều hành Linux / macOS: Quét bảng định tuyến default
    try:
        import subprocess
        out = subprocess.check_output("ip route show default", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "default via" in line:
                return line.split()[2]
    except Exception:
        pass

    # 3. Fallback: Lấy local IP và suy đoán gateway hoặc fallback DNS
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        if not local_ip.startswith("127."):
            parts = local_ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        pass

    return "8.8.8.8"


def burst_udp_flood(target_ip: str, target_port: int = 9999, packets: int = 1500) -> int:
    """Bắn 1 burst UDP tốc độ cao qua socket thật (~1500 pkts/burst), hướng vào Gateway/Broadcast để ESP32 Promiscuous bắt qua sóng Wi-Fi."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    payload = b"EDGEGUARD_AI_ATTACK_SIM_UDP_PAYLOAD_" * 16  # ~608 bytes
    sent = 0

    # Tự động tính địa chỉ Broadcast mạng con (ví dụ 192.168.1.255)
    bcast_ip = None
    if "." in target_ip:
        parts = target_ip.split(".")
        if len(parts) == 4 and parts[0] in ("192", "10", "172"):
            bcast_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.255"

    for i in range(packets):
        try:
            s.sendto(payload, (target_ip, target_port))
            if bcast_ip and (i % 3 == 0):
                s.sendto(payload, (bcast_ip, target_port))
            sent += 1
            if i % 150 == 0:
                time.sleep(0.002)  # Micro-sleep giải phóng buffer hệ điều hành
        except Exception:
            pass

    s.close()
    return sent


def burst_port_scan(target_ip: str, num_ports: int = 350) -> int:
    """Bắn 1 burst quét cổng TCP SYN phân tán qua socket thật."""
    def probe(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.03)
            s.connect_ex((target_ip, port))
            s.close()
        except Exception:
            pass

    start_port = random.randint(20, 1000)
    ports = list(range(start_port, start_port + num_ports))

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(probe, ports)
    return num_ports


def burst_tcp_syn_flood(target_ip: str, target_port: int = 80, count: int = 600) -> int:
    """Bắn 1 burst TCP SYN flood dồn dập qua socket thật."""
    def send_syn(_):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.04)
            s.connect_ex((target_ip, target_port))
            s.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(send_syn, range(count))
    return count


def burst_vulnerability_scan(target_ip: str) -> int:
    """Bắn 1 burst quét thăm dò các cổng dịch vụ tiêu biểu."""
    common_vuln_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000]

    def probe_service(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.04)
            s.connect_ex((target_ip, port))
            s.close()
        except Exception:
            pass

    ports_to_probe = common_vuln_ports * 4
    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(probe_service, ports_to_probe)
    return len(ports_to_probe)


def burst_uploading(target_ip: str, target_port: int = 443, count: int = 1200) -> int:
    """Bắn luồng truyền tải dữ liệu TCP/UDP dung lượng lớn (Data Exfiltration / Uploading)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_chunk = b"EXFILTRATION_DATA_STREAM_CHUNK_" * 45  # ~1400 bytes (MTU size)
    sent = 0
    for _ in range(count):
        try:
            s.sendto(data_chunk, (target_ip, target_port))
            sent += 1
        except Exception:
            pass
    s.close()
    return sent


class AttackTrafficController:
    """
    Bộ điều khiển tấn công mạng thật tích hợp MQTT:
    - Nhận lệnh từ Web Dashboard và phát động tấn công DUY TRÌ LIÊN TỤC (Sustained).
    - Duy trì tốc độ hàng nghìn gói tin/giây qua sóng Wi-Fi (hướng vào Gateway/Broadcast để ESP32 Promiscuous bắt được).
    - TUYỆT ĐỐI KHÔNG bắn unicast trực tiếp vào IP của ESP32 để bảo vệ chip không bị sập lwIP stack.
    """

    def __init__(self, target_ip: str, broker_host: str = "127.0.0.1", broker_port: int = 1883, cycle_interval: float = 12.0):
        self.target_ip = target_ip
        self.gateway_ip = target_ip
        self.esp32_ip: Optional[str] = None
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.cycle_interval = cycle_interval
        self.auto_cycle = False
        self.running = True
        self.current_scenario = "Normal"
        self.is_attacking = False
        self.attack_start_time = 0.0
        self.max_attack_duration = 60.0  # Tự động ngắt an toàn sau 60s
        self.lock = threading.Lock()
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="AttackTrafficGenerator")

    def publish_status(self):
        """Báo cáo trạng thái hiện tại lên MQTT để Dashboard và Sniffer nắm bắt."""
        try:
            payload = {
                "status": "ATTACKING" if self.is_attacking else "IDLE",
                "scenario": self.current_scenario,
                "target_ip": self.target_ip,
                "auto_cycle": self.auto_cycle,
                "timestamp": int(time.time() * 1000)
            }
            self.mqtt_client.publish("edge/attack/status", json.dumps(payload), retain=True)
        except Exception:
            pass

    def set_scenario(self, scenario: str):
        """Kích hoạt kịch bản tấn công duy trì liên tục hoặc đưa về Normal."""
        with self.lock:
            s_upper = scenario.upper()
            if "NORMAL" in s_upper or "STOP" in s_upper:
                self.is_attacking = False
                self.current_scenario = "Normal"
                print(f"[AttackGenerator] [NORMAL] Da dung tan cong, luu luong tro ve binh thuong.")
            else:
                self.is_attacking = True
                self.current_scenario = scenario
                self.attack_start_time = time.time()
                print(f"\n[AttackGenerator] >>> KICH HOAT TAN CONG LIEN TUC: [{scenario}] qua Wi-Fi toi {self.target_ip} <<<")

            self.publish_status()

    def attack_worker_loop(self):
        """
        Vòng lặp chạy nền liên tục duy trì luồng tấn công qua socket thật:
        Cứ mỗi 0.65s lại phát 1 burst để ESP32 Promiscuous liên tục đo được hàng nghìn pkts/s.
        """
        burst_count = 0
        while self.running:
            if self.is_attacking and self.current_scenario != "Normal":
                # Kiểm tra timeout an toàn
                if time.time() - self.attack_start_time > self.max_attack_duration:
                    print("[AttackGenerator] [Timeout] Tu dong dung dot tan cong sau 60s an toan.")
                    self.set_scenario("Normal")
                    continue

                sc = self.current_scenario.upper()
                t0 = time.perf_counter()

                # Bảo vệ ESP32: Không bắn thẳng vào IP của ESP32
                effective_target = self.gateway_ip if (self.esp32_ip and self.target_ip == self.esp32_ip) else self.target_ip

                try:
                    if "UDP" in sc:
                        burst_udp_flood(effective_target, target_port=9999, packets=1500)
                    elif "PORT" in sc:
                        burst_port_scan(effective_target, num_ports=180)
                    elif "TCP" in sc or "SYN" in sc:
                        burst_tcp_syn_flood(effective_target, target_port=80, count=300)
                    elif "VULN" in sc:
                        burst_vulnerability_scan(effective_target)
                    elif "UPLOAD" in sc or "EXFIL" in sc:
                        burst_uploading(effective_target, target_port=443, count=600)
                    else:
                        burst_udp_flood(effective_target, target_port=9999, packets=1500)
                except Exception as e:
                    print(f"[AttackGenerator] Loi khi ban burst socket ({self.current_scenario}): {e}")

                burst_count += 1
                if burst_count % 4 == 0:
                    print(f"  -> [AttackSim] Dang phat luong [{self.current_scenario}] tren song Wi-Fi toi {effective_target}...")

                elapsed = time.perf_counter() - t0
                sleep_time = max(0.05, 0.65 - elapsed)
                time.sleep(sleep_time)
            else:
                burst_count = 0
                time.sleep(0.2)

    def auto_cycle_worker(self):
        """Thread tự động xoay tua các kịch bản sau mỗi cycle_interval (khi bật Auto-Cycle)."""
        scenarios = ["Port_Scanning", "DDoS_UDP", "DDoS_TCP", "Vulnerability_scanner", "Uploading"]
        idx = 0
        while self.running:
            if self.auto_cycle:
                # 1. Bật tấn công kịch bản trong 10 giây
                scenario = scenarios[idx]
                idx = (idx + 1) % len(scenarios)
                print(f"\n[AutoCycle] Chuyen sang kich ban: {scenario} (chay trong 10s)...")
                self.set_scenario(scenario)
                time.sleep(10.0)

                # 2. Nghỉ về Normal 8 giây để người dùng thấy biểu đồ hạ xuống
                print(f"[AutoCycle] Nghi 8s ve trang thai Normal...")
                self.set_scenario("Normal")
                time.sleep(8.0)
            else:
                time.sleep(1.0)

    def on_mqtt_message(self, client, userdata, msg):
        """Xử lý lệnh điều khiển nhận từ Web Dashboard và cập nhật trạng thái node."""
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            topic = msg.topic

            # Ghi nhận IP của ESP32 phần cứng để TUYỆT ĐỐI TRÁNH bắn unicast trực diện vào nó
            if topic in ("edge/nodes/status", "edge/telemetry/traffic"):
                dev_ip = payload.get("ip") or payload.get("device_ip")
                if dev_ip and str(dev_ip).strip() and not str(dev_ip).startswith("127."):
                    self.esp32_ip = str(dev_ip).strip()
                    if self.target_ip == self.esp32_ip:
                        self.target_ip = self.gateway_ip
                        print(f"\n[AttackGenerator] [Bao ve ESP32] Dieu huong target khoi ESP32 ({self.esp32_ip}) sang Gateway ({self.target_ip})")
                        self.publish_status()
                return

            cmd = payload.get("command", "").upper()
            mode = payload.get("mode", "Normal")
            target = payload.get("target_ip")
            if target and str(target).strip() and str(target).strip().lower() != "null":
                candidate = str(target).strip()
                if self.esp32_ip and candidate == self.esp32_ip:
                    self.target_ip = self.gateway_ip
                    print(f"\n[AttackGenerator] [Bao ve ESP32] Chuyen target tu ESP32 sang Gateway ({self.target_ip}) de ESP32 sniffer khong bi ngat ket noi.")
                else:
                    self.target_ip = candidate

            if cmd in ("TRIGGER", "INJECT_MODE"):
                effective = self.gateway_ip if (self.esp32_ip and self.target_ip == self.esp32_ip) else self.target_ip
                print(f"\n[AttackGenerator] Nhan lenh tu Web UI: Kich hoat [{mode}] tren song Wi-Fi toi {effective}")
                self.set_scenario(mode)

            elif cmd == "STOP":
                print("\n[AttackGenerator] Nhan lenh tu Web UI: DUNG TAN CONG (Normal)")
                self.auto_cycle = False
                self.set_scenario("Normal")

            elif cmd == "AUTO_CYCLE":
                self.auto_cycle = bool(payload.get("enabled", True))
                state_str = "BAT" if self.auto_cycle else "TAT"
                print(f"\n[AttackGenerator] Che do Tu dong xoay tua: {state_str}")
                if not self.auto_cycle:
                    self.set_scenario("Normal")
                self.publish_status()

        except Exception as e:
            print(f"[AttackGenerator] Loi phan tich lenh MQTT: {e}")

    def on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"  -> Attack Traffic Generator da ket noi MQTT Broker tai {self.broker_host}:{self.broker_port}")
            client.subscribe("edge/attack/control")
            client.subscribe("edge/simulator/control")
            client.subscribe("edge/nodes/status")
            client.subscribe("edge/telemetry/traffic")
            self.publish_status()
        else:
            print(f"  [Canh bao] Attack Generator khong the ket noi MQTT Broker (RC={rc})")

    def start(self):
        """Khởi chạy bộ điều khiển phát sinh tấn công mạng thật."""
        print("=" * 72)
        print("  [AttackTrafficGenerator] BO BAN GOI TIN MANG THAT (SUSTAINED RAW SOCKET)")
        print(f"  * Target IP           : {self.target_ip}")
        print(f"  * MQTT Control Topic  : edge/attack/control")
        print(f"  * Status Topic        : edge/attack/status")
        print("  * Che do              : Duy tri luong ban lien tuc theo lenh Web Dashboard")
        print("=" * 72)

        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_message = self.on_mqtt_message

        connected = False
        for _ in range(5):
            try:
                self.mqtt_client.connect(self.broker_host, self.broker_port, 60)
                connected = True
                break
            except Exception:
                time.sleep(1.0)

        if not connected:
            print(f"  [Canh bao] Khong the ket noi MQTT Broker tai {self.broker_host}:{self.broker_port}")

        self.mqtt_client.loop_start()

        # Khởi động thread liên tục duy trì luồng tấn công
        t_runner = threading.Thread(target=self.attack_worker_loop, daemon=True)
        t_runner.start()

        # Khởi động thread tự động xoay tua nếu bật Auto-Cycle
        t_auto = threading.Thread(target=self.auto_cycle_worker, daemon=True)
        t_auto.start()

        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[AttackGenerator] Dung tien trinh phat sinh tan cong.")
        finally:
            self.running = False
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()


def start_attack_traffic_generator(
    target_ip: Optional[str] = None,
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    cycle_interval: float = 12.0
):
    if not target_ip:
        target_ip = detect_target_ip()

    controller = AttackTrafficController(
        target_ip=target_ip,
        broker_host=broker_host,
        broker_port=broker_port,
        cycle_interval=cycle_interval
    )
    controller.start()


if __name__ == "__main__":
    target = os.getenv("ATTACK_TARGET_IP", None)
    start_attack_traffic_generator(target_ip=target)
