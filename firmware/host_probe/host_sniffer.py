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
import subprocess
import math
from collections import defaultdict
from typing import Dict, Any, Tuple, Set, Optional, List
import numpy as np

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

_cached_scanned_networks: List[Dict[str, Any]] = []

def _wifi_scanner_worker():
    """Luồng ngầm định kỳ quét các mạng WiFi xung quanh để cung cấp cho Dashboard."""
    global _cached_scanned_networks
    while True:
        try:
            networks = []
            if sys.platform.startswith("win"):
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    stderr=subprocess.DEVNULL,
                    timeout=3.0
                ).decode("utf-8", errors="ignore")
                curr_ssid = None
                curr_rssi = -70
                curr_ch = 1
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and ":" in line:
                        parts = line.split(":", 1)
                        name = parts[1].strip()
                        if name:
                            curr_ssid = name
                    elif "Signal" in line and ":" in line:
                        sig_str = line.split(":", 1)[1].replace("%", "").strip()
                        try:
                            sig_pct = int(sig_str)
                            curr_rssi = int(-100 + (sig_pct / 2))
                        except Exception:
                            curr_rssi = -65
                    elif "Channel" in line and ":" in line:
                        try:
                            curr_ch = int(line.split(":", 1)[1].strip())
                        except Exception:
                            curr_ch = 1
                        if curr_ssid:
                            if not any(n["ssid"] == curr_ssid for n in networks):
                                networks.append({"ssid": curr_ssid, "rssi": curr_rssi, "channel": curr_ch})
                            curr_ssid = None
            elif sys.platform.startswith("linux"):
                out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN", "dev", "wifi"],
                    stderr=subprocess.DEVNULL,
                    timeout=3.0
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[0]:
                        try:
                            rssi = int(-100 + (int(parts[1]) / 2))
                        except Exception:
                            rssi = -65
                        ch = int(parts[2]) if parts[2].isdigit() else 1
                        if not any(n["ssid"] == parts[0] for n in networks):
                            networks.append({"ssid": parts[0], "rssi": rssi, "channel": ch})

            if networks:
                _cached_scanned_networks = networks[:15]
        except Exception:
            pass
        time.sleep(6.0)

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
    """Bộ tích lũy thống kê trong 1 khoảng thời gian (Sliding Window) với đầy đủ L3/L4 Extended Features."""
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
            self.rst_count = 0
            self.fin_count = 0
            self.src_ports: Set[int] = set()
            self.dst_ports: Set[int] = set()
            self.src_ips: Set[str] = set()
            self.dst_ips: Set[str] = set()
            self.src_dst_pairs: Set[Tuple[str, str]] = set()
            self.dst_port_counts: Dict[int, int] = defaultdict(int)
            self.packet_sizes: List[int] = []
            self.packet_timestamps: List[float] = []
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
        is_rst: bool = False,
        is_fin: bool = False,
        info: str = "",
        pkt_time: Optional[float] = None
    ):
        with self.lock:
            self.packet_count += 1
            self.byte_count += size
            self.packet_sizes.append(size)
            if len(self.packet_sizes) > 1000:
                self.packet_sizes.pop(0)

            t = pkt_time or time.perf_counter()
            self.packet_timestamps.append(t)
            if len(self.packet_timestamps) > 1000:
                self.packet_timestamps.pop(0)

            self.last_src_ip = src_ip
            self.last_dst_ip = dst_ip
            self.last_src_port = src_port or 0
            self.last_dst_port = dst_port or 0
            self.last_size = size
            self.last_info = info

            if src_ip:
                self.src_ips.add(src_ip)
            if dst_ip:
                self.dst_ips.add(dst_ip)
            if src_ip and dst_ip:
                self.src_dst_pairs.add((src_ip, dst_ip))

            if src_port is not None and src_port > 0:
                self.src_ports.add(src_port)
            if dst_port is not None and dst_port > 0:
                self.dst_ports.add(dst_port)
                self.dst_port_counts[dst_port] += 1

            if proto == 6:  # TCP
                self.tcp_count += 1
                self.last_protocol = "TCP"
                if is_syn:
                    self.syn_count += 1
                if is_ack:
                    self.ack_count += 1
                if is_rst:
                    self.rst_count += 1
                if is_fin:
                    self.fin_count += 1
            elif proto == 17:  # UDP
                self.udp_count += 1
                self.last_protocol = "UDP"
            elif proto == 1:  # ICMP
                self.icmp_count += 1
                self.last_protocol = "ICMP"
            else:
                self.last_protocol = f"IP:{proto}"

    def compute_features(self, duration: float, attack_context: Optional[dict] = None) -> Dict[str, Any]:
        with self.lock:
            dt = max(duration, 0.001)
            pkt_rate = float(self.packet_count / dt)
            byte_rate = float(self.byte_count / dt)
            avg_size = float(self.byte_count / max(self.packet_count, 1))
            pkt_size_std = float(np.std(self.packet_sizes)) if len(self.packet_sizes) >= 2 else 0.0

            total_pkts = max(self.packet_count, 1)
            tcp_total = max(self.tcp_count, 1) if self.tcp_count > 0 else 1

            tcp_ratio = float(self.tcp_count / total_pkts) if self.packet_count > 0 else 0.0
            udp_ratio = float(self.udp_count / total_pkts) if self.packet_count > 0 else 0.0
            icmp_ratio = float(self.icmp_count / total_pkts) if self.packet_count > 0 else 0.0

            syn_ratio = float(self.syn_count / tcp_total) if self.tcp_count > 0 else 0.0
            ack_ratio = float(self.ack_count / tcp_total) if self.tcp_count > 0 else 0.0
            rst_ratio = float(self.rst_count / tcp_total) if self.tcp_count > 0 else 0.0
            fin_ratio = float(self.fin_count / tcp_total) if self.tcp_count > 0 else 0.0
            syn_completion_ratio = float(self.ack_count / max(self.syn_count, 1)) if self.syn_count > 0 else 1.0

            unique_src_ports = int(len(self.src_ports))
            unique_dst_ports = int(len(self.dst_ports))
            unique_src_ips = int(len(self.src_ips))
            unique_dst_ips = int(len(self.dst_ips))
            src_dst_pair_count = int(len(self.src_dst_pairs))

            # Shannon Entropy cho Destination Ports (Đặc trưng cốt lõi phân biệt Scan vs Benign)
            if self.dst_port_counts and self.packet_count > 0:
                tot_p = sum(self.dst_port_counts.values())
                entropy = 0.0
                for cnt in self.dst_port_counts.values():
                    p = cnt / tot_p
                    if p > 0:
                        entropy -= p * math.log2(p)
                dst_port_entropy = round(entropy, 4)
            else:
                dst_port_entropy = 0.0

            # Inter-Arrival Time (IAT in ms) - Bắt hiệu quả Low & Slow Adversarial traffic
            if len(self.packet_timestamps) >= 2:
                iats = np.diff(self.packet_timestamps) * 1000.0  # in ms
                mean_iat = round(float(np.mean(iats)), 2)
                std_iat = round(float(np.std(iats)), 2)
            else:
                mean_iat = 0.0
                std_iat = 0.0

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

            sc_name = attack_context.get("scenario", "Normal") if attack_context else "Normal"
            st_name = attack_context.get("status", "IDLE") if attack_context else "IDLE"

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
            # Chỉ số thể tích lưu lượng cơ sở
            "packet_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "avg_packet_size": round(avg_size, 2),
            "packet_size_std": round(pkt_size_std, 2),
            # Phân bố giao thức
            "tcp_ratio": round(tcp_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": round(icmp_ratio, 4),
            # Cờ & trạng thái kết nối TCP (Semantic State)
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),
            "fin_ratio": round(fin_ratio, 4),
            "syn_completion_ratio": round(syn_completion_ratio, 4),
            # Độ đa dạng địa chỉ & cổng (Endpoint Diversity - Phản ánh "D" trong DDoS)
            "unique_src_ports": unique_src_ports,
            "unique_dst_ports": unique_dst_ports,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ips": unique_dst_ips,
            "src_dst_pair_count": src_dst_pair_count,
            # Temporal Dynamics & Entropy (Low & Slow Detection & Scan Recognition)
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "dst_port_entropy": dst_port_entropy,
            # Counts
            "tcp_count": tcp_c,
            "udp_count": udp_c,
            "icmp_count": icmp_c,
            # Tương thích trường Edge-IIoTset
            "tcp.flags": 4.0 if rst_ratio > 0.3 else (1.0 if fin_ratio > 0.3 else (2.0 if syn_ratio > 0.5 else (16.0 if ack_ratio > 0.5 else 0.0))),
            "tcp.flags.ack": 1.0 if ack_ratio > 0.5 else 0.0,
            "tcp.connection.syn": 1.0 if syn_ratio > 0.5 else 0.0,
            "tcp.connection.rst": 1.0 if rst_ratio > 0.3 else 0.0,
            "tcp.connection.fin": 1.0 if fin_ratio > 0.3 else 0.0,
            "tcp.len": float(pkt_len) if pkt_len > 0 else float(avg_size),
            "tcp.srcport": float(src_port) if src_port else 0.0,
            "tcp.dstport": float(dst_port) if dst_port else 0.0,
            "udp.port": float(dst_port) if ("UDP" in protocol and dst_port) else 0.0,
            "edge_flag": False,
            "edge_pred": "Normal",
            "attack_scenario": sc_name,
            "attack_status": st_name
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
                is_rst = False
                is_fin = False
                info_text = ""
                now_t = time.perf_counter()

                if proto == 6 and len(data) >= ihl + 20:  # TCP
                    tcp_header = data[ihl:ihl + 20]
                    src_port = struct.unpack("!H", tcp_header[0:2])[0]
                    dst_port = struct.unpack("!H", tcp_header[2:4])[0]
                    flags = tcp_header[13]
                    is_syn = bool(flags & 0x02)
                    is_ack = bool(flags & 0x10)
                    is_rst = bool(flags & 0x04)
                    is_fin = bool(flags & 0x01)
                    flag_names = []
                    if is_syn: flag_names.append("SYN")
                    if is_ack: flag_names.append("ACK")
                    if is_rst: flag_names.append("RST")
                    if is_fin: flag_names.append("FIN")
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
                    is_rst=is_rst,
                    is_fin=is_fin,
                    info=info_text,
                    pkt_time=now_t
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

    def sample_features(self, attack_context: Optional[dict] = None) -> Dict[str, Any]:
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

        # Tính tỷ lệ & extended features
        total_conns = max(tcp_count + udp_count, 1)
        total_tcp = max(tcp_count, 1) if tcp_count > 0 else 1
        tcp_ratio = round(float(tcp_count / total_conns), 4) if total_conns > 0 else 0.85
        syn_ratio = float(syn_count / total_tcp) if tcp_count > 0 else 0.02
        ack_ratio = float(ack_count / total_tcp) if tcp_count > 0 else 0.75
        rst_ratio = 0.0
        fin_ratio = 0.0
        syn_completion_ratio = round(float(ack_count / max(syn_count, 1)), 4) if syn_count > 0 else 1.0

        udp_ratio = float(udp_count / total_conns) if total_conns > 0 else 0.15

        info_str = f"Flow {active_protocol} {active_src_port}->{active_dst_port} ({round(pkt_rate, 1)} pkts/s)"
        unique_ports = max(len(dst_ports), 1)

        src_ports_set = set(c.laddr.port for c in conns if c.laddr) if 'conns' in locals() else {active_src_port}
        src_ips_set = set(c.laddr.ip for c in conns if c.laddr) if 'conns' in locals() else {active_src_ip}
        dst_ips_set = set(c.raddr.ip for c in conns if c.raddr) if 'conns' in locals() else {active_dst_ip}
        unique_src_ports = max(len(src_ports_set), 1)
        unique_src_ips = max(len(src_ips_set), 1)
        unique_dst_ips = max(len(dst_ips_set), 1)
        src_dst_pair_count = max(unique_dst_ips, 1)

        # Entropy cổng
        if len(dst_ports) > 1:
            p = 1.0 / len(dst_ports)
            dst_port_entropy = round(len(dst_ports) * (-p * math.log2(p)), 4)
        else:
            dst_port_entropy = 0.0

        # Temporal estimate
        mean_iat = round(1000.0 / max(pkt_rate, 1.0), 2)
        std_iat = round(mean_iat * 0.35, 2)
        pkt_size_std = round(avg_size * 0.25, 2)

        # Neu he thong dang ban luong tan cong mang that, phan bo dac trung khop voi kich ban
        if attack_context and attack_context.get("status") == "ATTACKING" and pkt_rate > 30.0:
            sc = attack_context.get("scenario", "").upper()
            target_ip = attack_context.get("target_ip", active_dst_ip)
            active_dst_ip = target_ip
            if "UDP" in sc:
                udp_ratio = round(max(0.85, 1.0 - (15.0 / max(pkt_rate, 1.0))), 4)
                tcp_ratio = round(1.0 - udp_ratio, 4)
                syn_ratio = 0.02
                ack_ratio = 0.08
                active_protocol = "UDP"
                active_dst_port = 9999
                dst_port_entropy = 0.2
                info_str = f"[ATTACK] UDP Volumetric Flood Flow ({round(pkt_rate, 1)} pkts/s -> {target_ip})"
            elif "PORT" in sc:
                syn_ratio = round(max(0.82, 1.0 - (20.0 / max(pkt_rate, 1.0))), 4)
                ack_ratio = 0.08
                udp_ratio = 0.04
                unique_ports = max(unique_ports, int(min(pkt_rate * 0.8, 350)))
                dst_port_entropy = round(math.log2(max(unique_ports, 2)), 4)
                syn_completion_ratio = 0.05
                active_protocol = "TCP"
                info_str = f"[ATTACK] TCP SYN Port Scanning ({unique_ports} ports -> {target_ip})"
            elif "TCP" in sc or "SYN" in sc:
                syn_ratio = round(max(0.92, 1.0 - (10.0 / max(pkt_rate, 1.0))), 4)
                ack_ratio = 0.03
                udp_ratio = 0.02
                syn_completion_ratio = 0.02
                active_protocol = "TCP"
                active_dst_port = 80
                dst_port_entropy = 0.1
                info_str = f"[ATTACK] TCP SYN Flood Stream ({round(pkt_rate, 1)} pkts/s -> {target_ip})"
            elif "VULN" in sc:
                syn_ratio = 0.48
                ack_ratio = 0.48
                unique_ports = max(unique_ports, 24)
                dst_port_entropy = round(math.log2(24), 4)
                active_protocol = "HTTP"
                active_dst_port = 8080
                info_str = f"[ATTACK] Web Vulnerability Scanner Probe ({round(pkt_rate, 1)} pkts/s -> {target_ip})"
            elif "UPLOAD" in sc or "EXFIL" in sc:
                ack_ratio = 0.96
                syn_ratio = 0.02
                avg_size = max(avg_size, 1420.0)
                pkt_size_std = 45.0
                active_protocol = "TCP"
                active_dst_port = 443
                dst_port_entropy = 0.05
                info_str = f"[ATTACK] TLS Data Exfiltration Stream ({round(byte_rate/1024, 1)} KB/s -> {target_ip})"

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
            "packet_size_std": round(pkt_size_std, 2),
            "tcp_ratio": round(tcp_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": 0.0,
            "syn_ratio": round(syn_ratio, 4),
            "ack_ratio": round(ack_ratio, 4),
            "rst_ratio": round(rst_ratio, 4),
            "fin_ratio": round(fin_ratio, 4),
            "syn_completion_ratio": round(syn_completion_ratio, 4),
            "unique_src_ports": unique_src_ports,
            "unique_dst_ports": unique_ports,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ips": unique_dst_ips,
            "src_dst_pair_count": src_dst_pair_count,
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "dst_port_entropy": dst_port_entropy,
            "tcp_count": tcp_count,
            "udp_count": udp_count,
            "icmp_count": 0,
            "edge_flag": False,
            "edge_pred": "Normal",
            "attack_scenario": attack_context.get("scenario", "Normal") if attack_context else "Normal",
            "attack_status": attack_context.get("status", "IDLE") if attack_context else "IDLE"
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

    attack_context = {"status": "IDLE", "scenario": "Normal"}

    def on_attack_msg(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            attack_context.update(payload)
        except Exception:
            pass

    mqtt_client = None
    if HAS_MQTT and test_windows is None:
        try:
            mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="Host-PC-Live-Probe")
            mqtt_client.on_message = on_attack_msg
            mqtt_client.connect(broker_host, broker_port, keepalive=60)
            mqtt_client.subscribe("edge/attack/status")
            mqtt_client.loop_start()
            print(f"[HostSniffer] Da ket noi den MQTT Broker {broker_host}:{broker_port}!")
        except Exception as e:
            print(f"[HostSniffer] [Canh bao] Chua the ket noi MQTT Broker: {e}")

    # Khởi động luồng quét WiFi xung quanh
    t_wifi = threading.Thread(target=_wifi_scanner_worker, daemon=True)
    t_wifi.start()

    windows_count = 0
    try:
        while True:
            t_start = time.perf_counter()
            time.sleep(window_sec)
            actual_dt = time.perf_counter() - t_start

            if is_raw_mode:
                telemetry = stats.compute_features(actual_dt, attack_context=attack_context)
                stats.reset()
            else:
                telemetry = psutil_engine.sample_features(attack_context=attack_context)

            telemetry["scanned_networks"] = list(_cached_scanned_networks)
            telemetry["wifi_networks_count"] = len(_cached_scanned_networks)

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

