"""
Attack Traffic Generator Module
===============================
Module phát sinh traffic thử nghiệm qua socket tới target lab cấu hình tường minh.
Các pattern chưa được xác minh tái hiện attack của benchmark; nhãn UI là context.
1. Port Scanning: TCP connect scan, không phải SYN-only scan.
2. DDoS UDP Flood: Bắn hàng nghìn gói UDP dung lượng cao liên tục (tăng packet_rate, byte_rate, udp_ratio).
3. DDoS TCP legacy: TCP connect workload, chưa xác minh SYN flood.
4. Vulnerability Scanner legacy: Port probes, chưa xác minh vulnerability.
5. Uploading legacy: UDP workload, chưa khớp web upload trong paper.
6. DDoS HTTP: bounded local HTTP workload, chưa xác minh DoS impact.

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
import uuid
import http.client
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
import paho.mqtt.client as mqtt
from digital_twin.lab.flows import FlowRecorder, lab_socket
from firmware.simulator.scenarios import require_implemented
from firmware.simulator.lab_config import configured_target, validate_lab_target, http_port
from firmware.simulator.http_variants import HttpVariantGenerator

LOG = logging.getLogger(__name__)


def _send_http_request(target_ip: str, target_port: int, request: bytes,
                       recorder: Optional[FlowRecorder] = None,
                       request_context: Optional[dict[str, str]] = None) -> bool:
    """Finish a bounded HTTP exchange before closing; success means transport only."""
    validate_lab_target(target_ip)
    connection = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
    response = None
    try:
        connection.settimeout(2)
        connection.connect((target_ip, target_port))
        if recorder and request_context:
            recorder.annotate_request(connection.getsockname(), (target_ip, target_port), "tcp", request_context)
        connection.sendall(request)
        response = http.client.HTTPResponse(connection)
        response.begin()
        if response.length is not None and response.length > 65536:
            raise ValueError("Lab HTTP response exceeds 64 KiB limit")
        if len(response.read(65537)) > 65536:
            raise ValueError("Lab HTTP response exceeds 64 KiB limit")
        if response.length not in (None, 0):
            raise ValueError("Lab HTTP response ended before Content-Length")
        return True
    except (OSError, http.client.HTTPException, ValueError) as error:
        LOG.debug("Lab HTTP exchange failed: %s", type(error).__name__)
        return False
    finally:
        if response is not None:
            response.close()
        connection.close()

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


def detect_target_ip() -> str:
    """Use explicit lab configuration; never infer an attack target."""
    return configured_target()


def get_broadcast_ip(ip_str: str) -> str:
    """Xác định địa chỉ IP Broadcast của mạng con (Subnet Broadcast)."""
    try:
        if ip_str and "." in ip_str:
            parts = ip_str.split(".")
            if len(parts) == 4 and parts[0] in ("192", "10", "172"):
                return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
    except Exception:
        pass
    return "255.255.255.255"


def burst_udp_flood(target_ip: str, target_port: int = 9999, packets: int = 1500, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None) -> int:
    """Send a UDP workload only to the configured lab target."""
    s = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, recorder)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    payload = b"EDGEGUARD_AI_ATTACK_SIM_UDP_PAYLOAD_" * 16  # ~608 bytes
    sent = 0

    targets = [target_ip]

    for i in range(packets):
        if cancel_event is not None and cancel_event.is_set():
            break
        try:
            dest = targets[i % len(targets)]
            s.sendto(payload, (dest, target_port))
            sent += 1
            if i % 150 == 0:
                time.sleep(0.002)  # Micro-sleep giải phóng buffer hệ điều hành
        except Exception:
            pass

    s.close()
    return sent


def burst_port_scan(target_ip: str, num_ports: int = 350, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None, ports: Optional[list[int]] = None) -> int:
    """TCP connect scan; no unrelated UDP broadcast traffic."""
    def probe_tcp(target, port):
        if cancel_event is not None and cancel_event.is_set():
            return
        s = None
        try:
            s = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
            s.settimeout(0.03)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
        finally:
            if s is not None:
                s.close()

    start_port = random.randint(20, 1000)
    ports = ports if ports is not None else list(range(start_port, start_port + num_ports))

    # 1. Quét TCP tới target_ip
    with ThreadPoolExecutor(max_workers=40) as ex:
        ex.map(lambda p: probe_tcp(target_ip, p), ports)



    return num_ports


def burst_tcp_syn_flood(target_ip: str, target_port: int = 80, count: int = 600, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None) -> int:
    """Legacy TCP connection workload; not verified half-open SYN flooding."""
    def send_syn(target):
        if cancel_event is not None and cancel_event.is_set():
            return
        s = None
        try:
            s = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
            s.settimeout(0.03)
            s.connect_ex((target, target_port))
            s.close()
        except Exception:
            pass
        finally:
            if s is not None:
                s.close()

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(lambda _: send_syn(target_ip), range(count))



    return count


def burst_vulnerability_scan(target_ip: str, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None, ports: Optional[list[int]] = None) -> int:
    """Bắn 1 burst quét thăm dò các cổng dịch vụ tiêu biểu trên toàn mạng."""
    common_vuln_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000]

    def probe_service(target, port):
        if cancel_event is not None and cancel_event.is_set():
            return
        s = None
        try:
            s = lab_socket(socket.AF_INET, socket.SOCK_STREAM, recorder)
            s.settimeout(0.04)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
        finally:
            if s is not None:
                s.close()

    ports_to_probe = (ports if ports is not None else common_vuln_ports) * 4
    with ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(lambda p: probe_service(target_ip, p), ports_to_probe)



    return len(ports_to_probe)


def burst_uploading(target_ip: str, target_port: int = 443, count: int = 1200, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None) -> int:
    """Bắn luồng truyền tải dữ liệu TCP/UDP dung lượng lớn (Data Exfiltration / Uploading)."""
    s = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, recorder)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    data_chunk = b"EXFILTRATION_DATA_STREAM_CHUNK_" * 45  # ~1400 bytes (MTU size)
    sent = 0

    destinations = [target_ip]

    for i in range(count):
        if cancel_event is not None and cancel_event.is_set():
            break
        try:
            dest = destinations[i % len(destinations)]
            s.sendto(data_chunk, (dest, target_port))
            sent += 1
        except Exception:
            pass
    s.close()
    return sent


def burst_adversarial_evasion(target_ip: str, target_port: int = 80, count: int = 250, esp32_ip: Optional[str] = None, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None) -> int:
    """
    Legacy random UDP workload, not GAN-generated or validated model evasion:
    - Kỹ thuật Low & Slow: giảm đột biến packet_rate, chèn độ trễ ngẫu nhiên (jitter 5-25ms).
    - Biến thiên kích thước payload (dummy padding 40-520 bytes).
    - Does not create or manipulate TCP ACK flags.
    """
    s = lab_socket(socket.AF_INET, socket.SOCK_DGRAM, recorder)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    destinations = [target_ip]

    sent = 0
    for i in range(count):
        if cancel_event is not None and cancel_event.is_set():
            break
        try:
            rand_size = random.randint(40, 520)
            payload = os.urandom(rand_size)
            dest = destinations[i % len(destinations)]
            s.sendto(payload, (dest, target_port))
            sent += 1
            if i % 10 == 0:
                time.sleep(random.uniform(0.005, 0.025))
        except Exception:
            pass
    s.close()
    return sent


def burst_sql_injection(target_ip: str, target_port: int = 8000, count: int = 35, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None, variant_generator: Optional[HttpVariantGenerator] = None) -> int:
    """Bounded SQLi grammar requests for lab; transport completion is not exploit success."""
    variants = variant_generator or HttpVariantGenerator(random.SystemRandom().getrandbits(63))
    sent = 0
    hosts_to_target = [target_ip]
    for i in range(count):
        if cancel_event is not None and cancel_event.is_set():
            break
        h = hosts_to_target[i % len(hosts_to_target)]
        variant = variants.next("SQL_injection")
        sent += int(_send_http_request(h, target_port, variant.wire_request(h, target_port), recorder, request_context=variant.context()))
    return sent


def burst_xss_attack(target_ip: str, target_port: int = 8000, count: int = 35, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None, variant_generator: Optional[HttpVariantGenerator] = None) -> int:
    """Bounded XSS grammar requests for lab; content is not executed by the target."""
    variants = variant_generator or HttpVariantGenerator(random.SystemRandom().getrandbits(63))
    sent = 0
    hosts_to_target = [target_ip]
    for i in range(count):
        if cancel_event is not None and cancel_event.is_set():
            break
        h = hosts_to_target[i % len(hosts_to_target)]
        variant = variants.next("XSS")
        sent += int(_send_http_request(h, target_port, variant.wire_request(h, target_port), recorder, request_context=variant.context()))
    return sent


def burst_http_load(target_ip: str, target_port: int, count: int = 20, cancel_event: Optional[threading.Event] = None, recorder: Optional[FlowRecorder] = None) -> int:
    """Bounded HTTP workload; records successful transactions, not claimed DoS impact."""
    validate_lab_target(target_ip)
    completed = 0
    for _ in range(count):
        if cancel_event is not None and cancel_event.is_set():
            break
        connection = http.client.HTTPConnection(target_ip, target_port, timeout=0.2)
        try:
            started_ms = int(time.time() * 1000)
            connection.connect()
            if recorder:
                recorder.record(connection.sock.getsockname(), (target_ip, target_port), "tcp", started_ms)
            connection.request("GET", "/health")
            response = connection.getresponse()
            response.read(4096)
            completed += 1
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
    return completed


class AttackTrafficController:
    """
    Bộ điều khiển tấn công mạng thật tích hợp MQTT:
    - Nhận lệnh từ Web Dashboard và phát động tấn công DUY TRÌ LIÊN TỤC (Sustained).
    - Duy trì tốc độ hàng nghìn gói tin/giây qua sóng Wi-Fi (hướng vào Gateway/Broadcast để ESP32 Promiscuous bắt được).
    - TUYỆT ĐỐI KHÔNG bắn unicast trực tiếp vào IP của ESP32 để bảo vệ chip không bị sập lwIP stack.
    """

    def __init__(self, target_ip: str, broker_host: str = "127.0.0.1", broker_port: int = 1883, cycle_interval: float = 12.0):
        self.target_ip = validate_lab_target(target_ip)
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
        self.lock = threading.RLock()
        self.cancel_event = threading.Event()
        self.cycle_wakeup = threading.Event()
        self.command_id: Optional[str] = None
        self.seen_commands: list[str] = []
        self.experiment_id: Optional[str] = None
        self.last_error: Optional[str] = None
        self.failure_status = "UNSUPPORTED"
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="AttackTrafficGenerator")

    def publish_status(self):
        """Báo cáo trạng thái hiện tại lên MQTT để Dashboard và Sniffer nắm bắt."""
        try:
            payload = {
                "status": self.failure_status if self.last_error else "ATTACKING" if self.is_attacking else "IDLE",
                "scenario": self.current_scenario,
                "target_ip": self.target_ip,
                "auto_cycle": self.auto_cycle,
                "timestamp": int(time.time() * 1000),
                "experiment_id": self.experiment_id,
                "expires_at_ms": int((self.attack_start_time + self.max_attack_duration) * 1000) if self.is_attacking else int(time.time() * 1000),
                "implementation_status": "traffic_pattern_unverified",
                "label_verified": False,
                "error": self.last_error,
                "command_id": self.command_id
            }
            self.mqtt_client.publish("edge/attack/status", json.dumps(payload), qos=1, retain=True)
        except Exception:
            pass

    def set_scenario(self, scenario: str) -> None:
        """Kích hoạt kịch bản tấn công duy trì liên tục hoặc đưa về Normal."""
        with self.lock:
            self.cancel_event.set()
            self.cancel_event = threading.Event()
            try:
                scenario = require_implemented(scenario)
            except ValueError as exc:
                self.is_attacking = False
                self.current_scenario = scenario
                self.experiment_id = None
                self.last_error = str(exc)
                self.failure_status = "UNSUPPORTED"
                self.publish_status()
                return
            self.last_error = None
            if scenario == "Normal":
                self.is_attacking = False
                self.current_scenario = "Normal"
                print(f"[AttackGenerator] [NORMAL] Da dung tan cong, luu luong tro ve binh thuong.")
            else:
                self.is_attacking = True
                self.current_scenario = scenario
                self.experiment_id = uuid.uuid4().hex
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
            with self.lock:
                if self.is_attacking and time.time() - self.attack_start_time > self.max_attack_duration:
                    self.set_scenario("Normal")
                sc = self.current_scenario.upper()
                attacking = self.is_attacking
                cancel_event = self.cancel_event
                effective_target = self.target_ip
                esp_target = self.esp32_ip
            if attacking and sc != "NORMAL":
                t0 = time.perf_counter()

                try:
                    if sc == "DDOS_HTTP":
                        completed = burst_http_load(effective_target, http_port(), cancel_event=cancel_event)
                        if not completed and not cancel_event.is_set():
                            raise RuntimeError("HTTP lab service unavailable; start lab_http_service first")
                    elif sc == "DDOS_UDP":
                        burst_udp_flood(effective_target, target_port=9999, packets=1500, esp32_ip=esp_target, cancel_event=cancel_event)
                    elif sc == "PORT_SCANNING":
                        burst_port_scan(effective_target, num_ports=180, esp32_ip=esp_target, cancel_event=cancel_event)
                    elif sc == "DDOS_TCP":
                        burst_tcp_syn_flood(effective_target, target_port=80, count=300, esp32_ip=esp_target, cancel_event=cancel_event)
                    elif sc == "SQL_INJECTION":
                        burst_sql_injection(effective_target, target_port=http_port(), count=40, cancel_event=cancel_event)
                    elif sc == "XSS":
                        burst_xss_attack(effective_target, target_port=http_port(), count=40, cancel_event=cancel_event)
                    elif sc == "VULNERABILITY_SCANNER":
                        burst_vulnerability_scan(effective_target, esp32_ip=esp_target, cancel_event=cancel_event)
                    elif sc == "UPLOADING":
                        burst_uploading(effective_target, target_port=443, count=600, esp32_ip=esp_target, cancel_event=cancel_event)
                    elif sc == "ADVERSARIAL":
                        burst_adversarial_evasion(effective_target, target_port=80, count=250, esp32_ip=esp_target, cancel_event=cancel_event)
                    else:
                        raise ValueError("Unsupported scenario; no fallback traffic generated")
                except Exception as e:
                    with self.lock:
                        if self.cancel_event is cancel_event:
                            cancel_event.set()
                            self.is_attacking = False
                            self.failure_status = "ERROR"
                            self.last_error = str(e)
                            self.publish_status()
                    print(f"[AttackGenerator] Loi khi ban burst socket ({sc}): {e}")

                burst_count += 1
                if burst_count % 4 == 0:
                    esp_info = f" + ESP32 {esp_target}" if esp_target else ""
                    if not cancel_event.is_set():
                        print(f"  -> [AttackSim] Dang phat luong [{sc}] qua Wi-Fi toi {effective_target}{esp_info}...")

                elapsed = time.perf_counter() - t0
                sleep_time = max(0.05, 0.65 - elapsed)
                cancel_event.wait(sleep_time)
            else:
                burst_count = 0
                time.sleep(0.2)

    def auto_cycle_worker(self) -> None:
        """Manual commands wake the cycle and invalidate its pending transition."""
        scenarios = ["Port_Scanning", "DDoS_UDP", "DDoS_TCP", "Vulnerability_scanner", "Uploading"]
        idx = 0
        while self.running:
            with self.lock:
                self.cycle_wakeup.clear()
                enabled = self.auto_cycle
                if enabled:
                    self.set_scenario(scenarios[idx % len(scenarios)])
                    idx += 1
            if not enabled:
                self.cycle_wakeup.wait(1.0)
                continue
            if self.cycle_wakeup.wait(10.0):
                continue
            with self.lock:
                if not self.auto_cycle:
                    continue
                self.set_scenario("Normal")
            self.cycle_wakeup.wait(8.0)

    def on_mqtt_message(self, client, userdata, msg):
        """Xử lý lệnh điều khiển nhận từ Web Dashboard và cập nhật trạng thái node."""
        try:
            raw_text = msg.payload.decode("utf-8", errors="ignore").strip()
            if not raw_text or not (raw_text.startswith("{") and raw_text.endswith("}")):
                return
            payload = json.loads(raw_text)
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

            if getattr(msg, "retain", False):
                return  # A retained command must never start a fresh workload.
            command_id = payload.get("command_id")
            if command_id and command_id in self.seen_commands:
                self.publish_status()
                return
            if command_id:
                self.seen_commands.append(command_id)
                self.seen_commands = self.seen_commands[-128:]
            self.command_id = command_id
            cmd = payload.get("command", "").upper()
            mode = payload.get("mode", "Normal")
            target = payload.get("target_ip")
            if target and str(target).strip() and str(target).strip().lower() != "null":
                candidate = validate_lab_target(str(target).strip())
                if self.esp32_ip and candidate == self.esp32_ip:
                    self.target_ip = self.gateway_ip
                    print(f"\n[AttackGenerator] [Bao ve ESP32] Chuyen target tu ESP32 sang Gateway ({self.target_ip}) de ESP32 sniffer khong bi ngat ket noi.")
                else:
                    self.target_ip = candidate

            if cmd in ("TRIGGER", "INJECT_MODE"):
                with self.lock:
                    self.auto_cycle = False
                    self.cycle_wakeup.set()
                effective = self.gateway_ip if (self.esp32_ip and self.target_ip == self.esp32_ip) else self.target_ip
                print(f"\n[AttackGenerator] Nhan lenh tu Web UI: Kich hoat [{mode}] tren song Wi-Fi toi {effective}")
                self.set_scenario(mode)

            elif cmd == "STOP":
                print("\n[AttackGenerator] Nhan lenh tu Web UI: DUNG TAN CONG (Normal)")
                with self.lock:
                    self.auto_cycle = False
                    self.cycle_wakeup.set()
                    self.set_scenario("Normal")

            elif cmd == "AUTO_CYCLE":
                with self.lock:
                    self.auto_cycle = bool(payload.get("enabled", True))
                    self.cycle_wakeup.set()
                state_str = "BAT" if self.auto_cycle else "TAT"
                print(f"\n[AttackGenerator] Che do Tu dong xoay tua: {state_str}")
                if not self.auto_cycle:
                    self.set_scenario("Normal")
                self.publish_status()

        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"[AttackGenerator] Loi phan tich lenh MQTT: {e}")

    def on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"  -> Attack Traffic Generator da ket noi MQTT Broker tai {self.broker_host}:{self.broker_port}")
            client.subscribe("edge/attack/control", qos=1)
            client.subscribe("edge/simulator/control", qos=1)
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
            self.cancel_event.set()
            self.cycle_wakeup.set()
            t_runner.join(timeout=5.0)
            t_auto.join(timeout=2.0)
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
