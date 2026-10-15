#!/usr/bin/env python3
"""
TShark DPI & L7 Textual Inspection Engine
==========================================
Công cụ bắt gói tin & kiểm tra tầng ứng dụng chuyên sâu sử dụng TShark (CLI của Wireshark):
1. Chạy ngầm tự động (Headless background subprocess), không cần mở GUI Wireshark.
2. Trích xuất đồng thời:
   - L3/L4 Flow Metrics: IP, Port, Protocol, TCP flags, Length, IAT.
   - L7 Textual Fields: HTTP Method, URI/Query, HTTP Body, DNS Name, MQTT Topic, Packet Info.
3. Deep Packet Inspection (DPI) & Textual Signature Matching:
   - SQL Injection (SQLi): Union-based, Boolean/Tautology, Stacked queries, information_schema, sleep().
   - Cross-Site Scripting (XSS): <script>, onerror=, onload=, javascript:, alert().
   - Path Traversal / LFI: ../.., /etc/passwd, boot.ini.
   - Command Injection (RCE): ; cat, ; id, | whoami, curl http.
4. Tương thích chéo hệ điều hành (Windows Npcap, Linux libpcap, macOS).
"""

import os
import sys
import re
import time
import shutil
import urllib.parse
import subprocess
import threading
import logging
from typing import Optional, List, Dict, Any, Tuple
from .interface_discovery import active_adapter_ids, interface_guid, physical_capture_interface


# Regex phát hiện các dấu hiệu tấn công tầng ứng dụng (L7 Signatures)
SQLI_REGEX = re.compile(
    r"(\bunion\b\s+(all\s+)?\bselect\b|"
    r"'\s*or\s*('?\d+'?\s*=\s*'?\d+|true|'[^']*'='[^']*')|"
    r";\s*(drop|insert|update|delete|create|alter)\b|"
    r"\binformation_schema\b|"
    r"\b(sleep|benchmark)\s*\(\s*\d+\s*\)|"
    r"('\s*and\s+\d+=\d+)|"
    r"(--\s+|--$|/\*.*?\*/|#\s+))",
    re.IGNORECASE
)

XSS_REGEX = re.compile(
    r"(<\s*script\b[^>]*>|"
    r"\b(onerror|onload|onclick|onmouseover|onfocus)\s*=|"
    r"\bjavascript:\s*|"
    r"\b(alert|prompt|confirm|eval)\s*\()",
    re.IGNORECASE
)

PATH_TRAVERSAL_REGEX = re.compile(
    r"((\.\.[/\\]){2,}|(/etc/passwd|/etc/shadow|boot\.ini|win\.ini))",
    re.IGNORECASE
)

RCE_REGEX = re.compile(
    r"([;&|`]\s*(cat\s+/|id\b|whoami|uname|curl\s+http|wget\s+http|nc\s+-e|bash\s+-i))",
    re.IGNORECASE
)


def is_likely_text(data: str) -> bool:
    """Kiểm tra chuỗi giải mã có phải là dạng văn bản (ASCII/UTF-8) không để tránh quét nhầm dữ liệu nhị phân/TLS."""
    if not data or len(data) < 4:
        return False
    printable = sum(1 for c in data if 32 <= ord(c) <= 126 or c in ('\r', '\n', '\t'))
    return (printable / len(data)) >= 0.70


def find_tshark_path() -> Optional[str]:
    """Tự động tìm kiếm đường dẫn thực thi của tshark.exe trên hệ thống."""
    # 1. Biến môi trường chỉ định
    env_p = os.getenv("TSHARK_PATH") or os.getenv("WIRESHARK_PATH")
    if env_p and os.path.isfile(env_p):
        return env_p

    # 2. Các đường dẫn mặc định trên Windows
    if sys.platform == "win32":
        default_win_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
        ]
        for p in default_win_paths:
            if os.path.isfile(p):
                return p

    # 3. Quét qua biến môi trường PATH
    which_p = shutil.which("tshark")
    if which_p and os.path.isfile(which_p):
        return which_p

    return None


def get_available_interfaces(tshark_path: str, *, strict: bool = False) -> List[Dict[str, str]]:
    """Lấy danh sách các card mạng có thể bắt gói từ tshark -D."""
    try:
        out = subprocess.check_output(
            [tshark_path, "-D"],
            text=True,
            stderr=subprocess.PIPE,
            timeout=15.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        interfaces = []
        for line in out.strip().splitlines():
            m = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
            if m:
                idx = m.group(1)
                dev = m.group(2)
                name = m.group(3) or ""
                interfaces.append({"index": idx, "device": dev, "name": name})
        return interfaces
    except subprocess.TimeoutExpired as error:
        if strict:
            raise ValueError("TShark interface discovery timed out after 15 seconds; check tshark -D and Npcap") from error
        return []
    except subprocess.CalledProcessError as error:
        if strict:
            detail = (error.stderr or "").strip()
            raise ValueError(f"TShark interface discovery failed (exit {error.returncode}): {detail or 'check tshark -D and Npcap'}") from error
        return []
    except (OSError, UnicodeError) as error:
        if strict:
            raise ValueError(f"Cannot read TShark capture interfaces: {error}") from error
        return []


def select_best_interfaces(interfaces: List[Dict[str, str]], configured_value: Optional[str] = None) -> List[str]:
    """Honor explicit scope, otherwise discover active physical Npcap adapters."""
    value = os.getenv("HOST_CAPTURE_INTERFACES", "") if configured_value is None else configured_value
    configured = [item.strip() for item in value.split(",") if item.strip()]
    if configured and configured != ["auto"]:
        selected = []
        for value in configured:
            matches = [entry for entry in interfaces if value.casefold() in
                       (entry["index"].casefold(), entry["device"].casefold(), entry["name"].casefold())]
            if len(matches) != 1:
                raise ValueError("Capture interface missing/ambiguous; restart run_system.py to rediscover current physical adapters")
            selected.append(matches[0]["device"])
        return list(dict.fromkeys(selected))
    physical = [entry for entry in interfaces if physical_capture_interface(entry)]
    active = active_adapter_ids()
    if active is not None:
        matched = [entry["device"] for entry in physical if
                   entry["name"].casefold() in active or entry["device"].casefold() in active or
                   interface_guid(entry["device"]) in active]
        if matched:
            return matched
        raise ValueError("No active physical adapter maps to TShark; check Npcap and adapter link state")
    logging.getLogger(__name__).warning("OS link state unavailable; selecting first physical capture adapter")
    return [physical[0]["device"]] if physical else []


class DpiTextualInspector:
    """Bộ phân tích nội dung văn bản gói tin (Deep Packet Inspection)."""

    @staticmethod
    def inspect_text(raw_text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Quét và đối soát chữ ký các đòn tấn công ứng dụng trong chuỗi văn bản:
        Trả về (threat_type, snippet) nếu phát hiện, hoặc (None, None).
        """
        if not raw_text or len(raw_text) < 4:
            return None, None

        # URL decode nếu có
        try:
            decoded_text = urllib.parse.unquote(raw_text)
        except Exception:
            decoded_text = raw_text

        # 1. SQL Injection
        m_sql = SQLI_REGEX.search(decoded_text)
        if m_sql:
            snippet = decoded_text[max(0, m_sql.start() - 10):min(len(decoded_text), m_sql.end() + 25)]
            return "SQL_Injection", snippet.strip()

        # 2. Cross-Site Scripting (XSS)
        m_xss = XSS_REGEX.search(decoded_text)
        if m_xss:
            snippet = decoded_text[max(0, m_xss.start() - 10):min(len(decoded_text), m_xss.end() + 25)]
            return "XSS_Attack", snippet.strip()

        # 3. Path Traversal
        m_path = PATH_TRAVERSAL_REGEX.search(decoded_text)
        if m_path:
            snippet = decoded_text[max(0, m_path.start() - 5):min(len(decoded_text), m_path.end() + 20)]
            return "Path_Traversal", snippet.strip()

        # 4. Command Injection
        m_rce = RCE_REGEX.search(decoded_text)
        if m_rce:
            snippet = decoded_text[max(0, m_rce.start() - 5):min(len(decoded_text), m_rce.end() + 20)]
            return "Command_Injection", snippet.strip()

        return None, None


class TSharkDpiEngine:
    """
    Engine bắt gói tin ngầm qua TShark tích hợp DPI & L7 Textual Analysis.
    """

    def __init__(self, stats_collector: Any, tshark_path: Optional[str] = None):
        self.stats = stats_collector
        self.tshark_path = tshark_path or find_tshark_path()
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.inspector = DpiTextualInspector()
        self.captured_packets = 0
        self.l7_threats_found = 0
        self.selected_interfaces: List[str] = []

    def is_available(self) -> bool:
        """Kiểm tra TShark có sẵn sàng khởi chạy không."""
        return bool(self.tshark_path and os.path.isfile(self.tshark_path))

    def start(self) -> bool:
        """Khởi động tiến trình TShark chạy nền."""
        if not self.is_available():
            return False

        interfaces = get_available_interfaces(self.tshark_path)
        self.selected_interfaces = select_best_interfaces(interfaces)
        if not self.selected_interfaces:
            return False

        # Xây dựng danh sách trường bóc tách: L3/L4 + L7
        # Separator: '|'
        cmd = [
            self.tshark_path,
            "-l",  # Flush buffer liên tục
            "-n",  # Không resolve DNS để tối ưu CPU
        ]

        # Bổ sung ép giải mã HTTP cho các cổng Web thông dụng nếu chưa chuẩn hóa
        cmd.extend(["-d", "tcp.port==8000,http"])
        cmd.extend(["-d", "tcp.port==8080,http"])

        for iface in self.selected_interfaces:
            cmd.extend(["-i", iface])

        cmd.extend([
            "-T", "fields",
            "-E", "separator=|",
            "-e", "frame.time_epoch",     # 0
            "-e", "frame.len",            # 1
            "-e", "ip.src",               # 2
            "-e", "ip.dst",               # 3
            "-e", "ip.proto",             # 4
            "-e", "tcp.srcport",          # 5
            "-e", "tcp.dstport",          # 6
            "-e", "udp.srcport",          # 7
            "-e", "udp.dstport",          # 8
            "-e", "tcp.flags",            # 9
            "-e", "_ws.col.Protocol",     # 10
            "-e", "http.request.method",  # 11
            "-e", "http.request.uri",     # 12
            "-e", "http.file_data",       # 13
            "-e", "dns.qry.name",         # 14
            "-e", "mqtt.topic",           # 15
            "-e", "tcp.payload",          # 16
            "-e", "_ws.col.Info"          # 17
        ])

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.running = True
            self.thread = threading.Thread(target=self._read_stream_loop, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            print(f"[TSharkEngine] Khong the khoi dong TShark subprocess: {e}")
            self.running = False
            return False

    def _read_stream_loop(self):
        """Đọc và xử lý luồng gói tin stdout từ tshark trong thời gian thực."""
        while self.running and self.process and self.process.stdout:
            try:
                line = self.process.stdout.readline()
                if not line:
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue

                line = line.strip()
                if not line:
                    continue

                parts = line.split("|")
                if len(parts) < 11:
                    continue

                # 1. Trích xuất L3/L4 cơ bản
                pkt_time_str = parts[0].strip()
                try:
                    pkt_time = float(pkt_time_str)
                except ValueError:
                    pkt_time = time.perf_counter()

                try:
                    size = int(parts[1].strip())
                except ValueError:
                    size = 64

                src_ip = parts[2].strip() or "127.0.0.1"
                dst_ip = parts[3].strip() or "127.0.0.1"

                try:
                    proto = int(parts[4].strip())
                except ValueError:
                    proto = 6  # Mặc định TCP

                # Ports
                src_port = None
                dst_port = None
                tcp_src = parts[5].strip()
                tcp_dst = parts[6].strip()
                udp_src = parts[7].strip()
                udp_dst = parts[8].strip()

                if tcp_src and tcp_dst:
                    try:
                        src_port = int(tcp_src.split(",")[0])
                        dst_port = int(tcp_dst.split(",")[0])
                    except ValueError:
                        pass
                elif udp_src and udp_dst:
                    try:
                        src_port = int(udp_src.split(",")[0])
                        dst_port = int(udp_dst.split(",")[0])
                    except ValueError:
                        pass

                # TCP Flags
                flags_hex = parts[9].strip()
                is_syn = False
                is_ack = False
                is_rst = False
                is_fin = False
                if flags_hex:
                    try:
                        val = int(flags_hex.split(",")[0], 16)
                        is_syn = bool(val & 0x02)
                        is_ack = bool(val & 0x10)
                        is_rst = bool(val & 0x04)
                        is_fin = bool(val & 0x01)
                    except ValueError:
                        pass

                protocol_name = parts[10].strip() or "TCP"

                # 2. Trích xuất L7 Textual fields & Payload
                http_method = parts[11].strip() if len(parts) > 11 else ""
                http_uri = parts[12].strip() if len(parts) > 12 else ""
                http_data = parts[13].strip() if len(parts) > 13 else ""
                dns_name = parts[14].strip() if len(parts) > 14 else ""
                mqtt_topic = parts[15].strip() if len(parts) > 15 else ""
                tcp_payload_hex = parts[16].strip() if len(parts) > 16 else ""
                info_text = parts[17].strip() if len(parts) > 17 else ""

                decoded_payload = ""
                if tcp_payload_hex:
                    try:
                        clean_hex = tcp_payload_hex.replace(":", "").replace(",", "")
                        raw_bytes = bytes.fromhex(clean_hex)
                        try:
                            candidate = raw_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            candidate = raw_bytes.decode("latin1", errors="ignore")
                        if is_likely_text(candidate):
                            decoded_payload = candidate
                    except Exception:
                        decoded_payload = ""

                # Nếu http_uri rỗng nhưng payload có dạng HTTP request, bóc tách nhanh method & URI
                if not http_uri and decoded_payload:
                    m_http = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s\r\n]+)", decoded_payload)
                    if m_http:
                        if not http_method:
                            http_method = m_http.group(1)
                        http_uri = m_http.group(2)

                # 3. Deep Packet Inspection (DPI) quét tìm textual clues
                text_to_scan = f"{http_method} {http_uri} {http_data} {decoded_payload} {info_text}".strip()
                detected_threat, threat_snippet = self.inspector.inspect_text(text_to_scan)

                if detected_threat:
                    self.l7_threats_found += 1
                    # Gán thông tin đe dọa vào info_text để hiển thị nổi bật
                    info_text = f"[🚨 L7 DPI: {detected_threat}] {threat_snippet or http_uri[:60]}"

                self.captured_packets += 1

                # 4. Ghi nhận vào thống kê chung
                self.stats.add_packet(
                    proto=proto,
                    size=size,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    is_syn=is_syn,
                    is_ack=is_ack,
                    is_rst=is_rst,
                    is_fin=is_fin,
                    info=info_text,
                    pkt_time=pkt_time
                )

                # Bổ sung L7 Context vào WindowStats nếu có
                if hasattr(self.stats, "add_l7_content"):
                    self.stats.add_l7_content(
                        method=http_method,
                        uri=http_uri,
                        body=http_data or (decoded_payload[:180] if detected_threat else ""),
                        dns_name=dns_name,
                        mqtt_topic=mqtt_topic,
                        threat_type=detected_threat,
                        snippet=threat_snippet
                    )

            except Exception:
                if not self.running:
                    break

            except Exception:
                if not self.running:
                    break

    def stop(self):
        """Dừng tiến trình tshark an toàn."""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=1.5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
