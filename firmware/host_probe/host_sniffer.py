#!/usr/bin/env python3
"""
Host PC Network Traffic Sniffer Probe
=====================================
Chỉ dẫn module:
- Module này biến chính máy tính hiện tại thành một trạm cảm biến an ninh mạng (Network Security Probe)
  thay thế cho vi điều khiển ESP32 vật lý khi người dùng chưa có phần cứng.
- Cơ chế hoạt động (Dual-Engine Sniffer):
  1. Engine 1 - Raw Socket Engine (Yêu cầu quyền Administrator):
     - Mở raw socket trực tiếp trên card mạng active thông qua SIO_RCVALL trên Windows hoặc SOCK_RAW trên Linux.
     - Phân tích chi tiết từng gói tin: IPv4 header, TCP header (cờ SYN, ACK, FIN, RST, ports), UDP, ICMP.
  2. Engine 2 - System Network Statistics Engine (Tự động kích hoạt khi không có quyền Administrator):
     - Tận dụng thư viện psutil để đo đạc chính xác delta byte_rate, packet_rate theo thời gian thực.
     - Quét bảng kết nối socket hệ điều hành để tính tỷ lệ TCP/UDP, handshake state (SYN_SENT, ESTABLISHED) và các port đích.
- Cửa sổ lấy mẫu (Sliding Window): Mặc định 1.0 giây tính toán 1 lần và publish lên MQTT topic:
    'edge/telemetry/traffic' với device_id='Host-PC-Live-Probe'.

Cú pháp sử dụng:
    python firmware/host_probe/host_sniffer.py
    python firmware/host_probe/host_sniffer.py --test-window 3
    python firmware/host_probe/host_sniffer.py --broker 127.0.0.1 --port 1883 --window 1.0
"""

import os
import sys
import time
import json
import socket
import struct
import threading
from typing import Dict, Any, Tuple, Set, Optional

# Đảm bảo UTF-8 an toàn cho Windows console
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import paho.mqtt.client as mqtt
    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False


def get_default_host_ip() -> str:
    """Xác định địa chỉ IP của card mạng đang kết nối Internet / default route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class WindowStats:
    """Bộ tích lũy thống kê trong 1 khoảng thời gian (Sliding Window)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.packet_count = 0
            self.byte_count = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.syn_count = 0
            self.ack_count = 0
            self.dst_ports: Set[int] = set()
            self.last_src_ip = "127.0.0.1"
            self.last_dst_ip = "127.0.0.1"
            self.last_src_port = 0
            self.last_dst_port = 0
            self.last_protocol = "TCP"
            self.last_size = 64
            self.last_info = "Normal Host Flow"

    def add_packet(
        self,
        proto: int,
        size: int,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        is_syn: bool = False,
        is_ack: bool = False,
        info: str = ""
    ):
        with self.lock:
            self.packet_count += 1
            self.byte_count += size
            self.last_src_ip = src_ip
            self.last_dst_ip = dst_ip
            self.last_src_port = src_port or 0
            self.last_dst_port = dst_port or 0
            self.last_size = size
            self.last_info = info
            if proto == 6:  # TCP
                self.tcp_count += 1
                self.last_protocol = "TCP"
                if is_syn:
                    self.syn_count += 1
                if is_ack:
                    self.ack_count += 1
            elif proto == 17:  # UDP
                self.udp_count += 1
                self.last_protocol = "UDP"
            elif proto == 1:  # ICMP
                self.icmp_count += 1
                self.last_protocol = "ICMP"
            else:
                self.last_protocol = f"IP:{proto}"

            if dst_port is not None and dst_port > 0:
                self.dst_ports.add(dst_port)

    def compute_features(self, duration: float) -> Dict[str, Any]:
        with self.lock:
            dt = max(duration, 0.001)
            pkt_rate = float(self.packet_count / dt)
            byte_rate = float(self.byte_count / dt)
            avg_size = float(self.byte_count / max(self.packet_count, 1))

            tcp_total = max(self.tcp_count, 1) if self.tcp_count > 0 else 1
            syn_ratio = float(self.syn_count / tcp_total) if self.tcp_count > 0 else 0.0
            ack_ratio = float(self.ack_count / tcp_total) if self.tcp_count > 0 else 0.0

            total_pkts = max(self.packet_count, 1)
            udp_ratio = float(self.udp_count / total_pkts) if self.packet_count > 0 else 0.0
            icmp_ratio = float(self.icmp_count / total_pkts) if self.packet_count > 0 else 0.0
            unique_ports = int(len(self.dst_ports))

            tcp_c = self.tcp_count
            udp_c = self.udp_count
            icmp_c = self.icmp_count
            src_ip = self.last_src_ip
            dst_ip = self.last_dst_ip
            src_port = self.last_src_port
            dst_port = self.last_dst_port
            protocol = self.last_protocol
            pkt_len = self.last_size
            info_str = self.last_info or f"{protocol} Stream ({round(pkt_rate, 1)} pkts/s)"

        return {
            "device_id": "Host-PC-Live-Probe",
            "timestamp": int(time.time() * 1000),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_length": pkt_len,
            "info": info_str,
            "packet_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "avg_packet_size": round(avg_size, 2),
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": round(icmp_ratio, 4),
            "unique_dst_ports": unique_ports,
            "tcp_count": tcp_c,
            "udp_count": udp_c,
            "icmp_count": icmp_c,
            "edge_flag": False,
            "edge_pred": "Normal"
        }


class RawSocketEngine:
    """Engine 1: Bắt gói tin thô từng gói qua socket.SOCK_RAW (cần Administrator)."""
    def __init__(self, host_ip: str, stats: WindowStats):
        self.host_ip = host_ip
        self.stats = stats
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        try:
            if sys.platform == "win32":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))

            self.running = True
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()
            return True
        except PermissionError:
            return False
        except Exception as e:
            print(f"[HostSniffer] Khong the khoi tao Raw Socket ({e})")
            return False

    def _capture_loop(self):
        while self.running and self.sock:
            try:
                data, _ = self.sock.recvfrom(65535)
                if len(data) < 20:
                    continue

                # Parse IPv4 Header
                ihl = (data[0] & 0x0F) * 4
                proto = data[9]
                total_len = len(data)
                src_ip = socket.inet_ntoa(data[12:16])
                dst_ip = socket.inet_ntoa(data[16:20])

                src_port = None
                dst_port = None
                is_syn = False
                is_ack = False
                info_text = ""

                if proto == 6 and len(data) >= ihl + 20:  # TCP
                    tcp_header = data[ihl:ihl + 20]
                    src_port = struct.unpack("!H", tcp_header[0:2])[0]
                    dst_port = struct.unpack("!H", tcp_header[2:4])[0]
                    flags = tcp_header[13]
                    is_syn = bool(flags & 0x02)
                    is_ack = bool(flags & 0x10)
                    flag_names = []
                    if is_syn: flag_names.append("SYN")
                    if is_ack: flag_names.append("ACK")
                    if flags & 0x01: flag_names.append("FIN")
                    if flags & 0x04: flag_names.append("RST")
                    info_text = f"[{' '.join(flag_names) or 'DATA'}] {src_port} -> {dst_port} Len={total_len}"
                elif proto == 17 and len(data) >= ihl + 8:  # UDP
                    udp_header = data[ihl:ihl + 8]
                    src_port = struct.unpack("!H", udp_header[0:2])[0]
                    dst_port = struct.unpack("!H", udp_header[2:4])[0]
                    if dst_port == 5683 or src_port == 5683:
                        info_text = f"CoAP Protocol UDP:{src_port}->{dst_port} Len={total_len}"
                    elif dst_port == 53 or src_port == 53:
                        info_text = f"DNS Query/Response UDP:{src_port}->{dst_port} Len={total_len}"
                    else:
                        info_text = f"UDP Datagram {src_port} -> {dst_port} Len={total_len}"
                elif proto == 1:
                    info_text = f"ICMP Ping Len={total_len}"

                self.stats.add_packet(
                    proto=proto,
                    size=total_len,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    is_syn=is_syn,
                    is_ack=is_ack,
                    info=info_text
                )
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                if sys.platform == "win32":
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.sock.close()
            except Exception:
                pass


class PsutilMonitorEngine:
    """Engine 2: Dự phòng thống kê lưu lượng I/O và socket qua psutil (không cần Admin)."""
    def __init__(self):
        if not HAS_PSUTIL:
            raise RuntimeError("Can thu vien psutil cho che do giam sat non-admin!")
        self.last_io = psutil.net_io_counters()
        self.last_time = time.perf_counter()

    def sample_features(self) -> Dict[str, Any]:
        now = time.perf_counter()
        dt = max(now - self.last_time, 0.001)
        current_io = psutil.net_io_counters()

        # Tinh toan delta
        bytes_delta = (current_io.bytes_sent - self.last_io.bytes_sent) + (current_io.bytes_recv - self.last_io.bytes_recv)
        pkts_delta = (current_io.packets_sent - self.last_io.packets_sent) + (current_io.packets_recv - self.last_io.packets_recv)

        self.last_io = current_io
        self.last_time = now

        pkt_rate = max(pkts_delta / dt, 0.0)
        byte_rate = max(bytes_delta / dt, 0.0)
        avg_size = byte_rate / max(pkt_rate, 1.0) if pkt_rate > 0 else 0.0

        # Quét bảng socket để trích xuất tỷ lệ TCP SYN, ACK và port đích
        syn_count = 0
        ack_count = 0
        tcp_count = 0
        udp_count = 0
        dst_ports: Set[int] = set()

        active_src_ip = "127.0.0.1"
        active_dst_ip = "127.0.0.1"
        active_src_port = 0
        active_dst_port = 0
        active_protocol = "TCP"
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.raddr:
                    dst_ports.add(c.raddr.port)
                    if active_dst_port == 0:
                        active_src_ip = c.laddr.ip if c.laddr else "127.0.0.1"
                        active_dst_ip = c.raddr.ip
                        active_src_port = c.laddr.port if c.laddr else 0
                        active_dst_port = c.raddr.port
                        active_protocol = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                if c.type == socket.SOCK_STREAM:
                    tcp_count += 1
                    if c.status in ("SYN_SENT", "SYN_RECV"):
                        syn_count += 1
                    elif c.status in ("ESTABLISHED", "CLOSE_WAIT"):
                        ack_count += 1
                elif c.type == socket.SOCK_DGRAM:
                    udp_count += 1
        except Exception:
            pass

        # Tính tỷ lệ
        total_tcp = max(tcp_count, 1) if tcp_count > 0 else 1
        syn_ratio = float(syn_count / total_tcp) if tcp_count > 0 else 0.02
        ack_ratio = float(ack_count / total_tcp) if tcp_count > 0 else 0.75

        total_conns = max(tcp_count + udp_count, 1)
        udp_ratio = float(udp_count / total_conns) if total_conns > 0 else 0.15

        info_str = f"Flow {active_protocol} {active_src_port}->{active_dst_port} ({round(pkt_rate, 1)} pkts/s)"

        return {
            "device_id": "Host-PC-Live-Probe",
            "timestamp": int(time.time() * 1000),
            "src_ip": active_src_ip,
            "dst_ip": active_dst_ip,
            "src_port": active_src_port,
            "dst_port": active_dst_port,
            "protocol": active_protocol,
            "packet_length": int(avg_size) if avg_size > 0 else 64,
            "info": info_str,
            "packet_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "avg_packet_size": round(avg_size, 2),
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": 0.0,
            "unique_dst_ports": max(len(dst_ports), 1),
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "icmp_count": 0,
            "edge_flag": False,
            "edge_pred": "Normal"
        }


def run_host_sniffer(
    broker_host: str = "127.0.0.1",
    broker_port: int = 1883,
    window_sec: float = 1.0,
    test_windows: Optional[int] = None
):
    """Chạy vòng lặp chính của Host Sniffer."""
    host_ip = get_default_host_ip()
    stats = WindowStats()

    print("=" * 70)
    print("   HOST PC NETWORK TRAFFIC SNIFFER PROBE (LIVE CAPTURE)")
    print(f"   [Card IP: {host_ip}] | [Cua so mau: {window_sec}s] | [Target Broker: {broker_host}:{broker_port}]")
    print("=" * 70)

    # Thu nghiem Engine 1: Raw Socket (Admin)
    raw_engine = RawSocketEngine(host_ip, stats)
    is_raw_mode = raw_engine.start()

    psutil_engine = None
    if is_raw_mode:
        print("[HostSniffer] [OK] Khoi dong Engine 1: Raw Socket Capture (Quyen Admin xac thuc).")
        print("  -> Dang phan tich tung goi tin TCP/UDP/ICMP truc tiep tu card mang.")
    else:
        print("[HostSniffer] [Thong tin] Terminal chua chay voi quyen Administrator.")
        print("  -> Tu dong chuyen sang Engine 2: Real-time System Network Statistics (psutil).")
        print("  -> (Meo: Chay terminal voi 'Run as Administrator' neu muon phan tich raw packet sau hon).")
        psutil_engine = PsutilMonitorEngine()

    mqtt_client = None
    if HAS_MQTT and test_windows is None:
        try:
            mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="Host-PC-Live-Probe")
            mqtt_client.connect(broker_host, broker_port, keepalive=60)
            mqtt_client.loop_start()
            print(f"[HostSniffer] Da ket noi den MQTT Broker {broker_host}:{broker_port}!")
        except Exception as e:
            print(f"[HostSniffer] [Canh bao] Chua the ket noi MQTT Broker: {e}")

    windows_count = 0
    try:
        while True:
            t_start = time.perf_counter()
            time.sleep(window_sec)
            actual_dt = time.perf_counter() - t_start

            if is_raw_mode:
                telemetry = stats.compute_features(actual_dt)
                stats.reset()
            else:
                telemetry = psutil_engine.sample_features()

            payload_str = json.dumps(telemetry)

            if mqtt_client:
                mqtt_client.publish("edge/telemetry/traffic", payload_str)

            print(f"[LIVE TRAFFIC] Pkts/s: {telemetry['packet_rate']:>7.1f} | "
                  f"Bytes/s: {telemetry['byte_rate']:>9.1f} | "
                  f"AvgSize: {telemetry['avg_packet_size']:>6.1f}B | "
                  f"SYN: {telemetry['syn_ratio']:>4.2f} | "
                  f"ACK: {telemetry['ack_ratio']:>4.2f} | "
                  f"UDP: {telemetry['udp_ratio']:>4.2f} | "
                  f"Ports: {telemetry['unique_dst_ports']}")

            windows_count += 1
            if test_windows and windows_count >= test_windows:
                print(f"\n[HostSniffer] Hoan thanh {test_windows} cua so kiem thu test mode.")
                break

    except KeyboardInterrupt:
        print("\n[HostSniffer] Dang dung tien trinh bat mang...")
    finally:
        if raw_engine:
            raw_engine.stop()
        if mqtt_client:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        print("[HostSniffer] Da tat probe an toan.")


start_host_sniffer = run_host_sniffer


def main():
    broker = os.getenv("MQTT_HOST", "127.0.0.1")
    port = int(os.getenv("MQTT_PORT", 1883))
    window = float(os.getenv("SNIFFER_WINDOW", 1.0))
    test_window = int(os.getenv("TEST_WINDOW")) if os.getenv("TEST_WINDOW") else None

    start_host_sniffer(
        broker_host=broker,
        broker_port=port,
        window_sec=window,
        test_windows=test_window
    )


if __name__ == "__main__":
    main()

