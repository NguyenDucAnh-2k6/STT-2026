"""
Launcher Package
================
Gói tiện ích hỗ trợ khởi động và quản lý vòng đời hệ sinh thái AERO:
- `network`: Quản lý IP, phát hiện SSID/Password Wi-Fi ngầm (Zero-Config), kiểm tra port.
- `workers`: Các luồng ngầm UDP Beacon, Network Roaming Watcher, USB Serial Bridge.
- `flasher`: Tìm kiếm arduino-cli, phát hiện cổng COM và nạp firmware qua dòng lệnh.
"""

from .network import (
    detect_host_lan_ip,
    auto_detect_wifi_credentials,
    update_env_file,
    sync_env_to_firmware,
    check_port_in_use,
)
from .workers import (
    udp_broker_beacon_worker,
    network_roaming_watcher_worker,
    serial_telemetry_bridge_worker,
)
from .flasher import (
    find_arduino_cli,
    find_esp32_com_port,
    flash_esp32_cli,
)

__all__ = [
    "detect_host_lan_ip",
    "auto_detect_wifi_credentials",
    "update_env_file",
    "sync_env_to_firmware",
    "check_port_in_use",
    "udp_broker_beacon_worker",
    "network_roaming_watcher_worker",
    "serial_telemetry_bridge_worker",
    "find_arduino_cli",
    "find_esp32_com_port",
    "flash_esp32_cli",
]
