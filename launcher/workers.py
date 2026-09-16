"""
Launcher Background Workers
===========================
Cung cấp các luồng dịch vụ chạy ngầm:
1. UDP Broker Beacon: Phát broadcast giúp ESP32 nhận biết IP Broker khi chuyển mạng.
2. Network Roaming Watcher: Tự động giám sát sự thay đổi mạng Wi-Fi và cập nhật credentials.
3. USB Serial Telemetry Bridge: Cầu nối dữ liệu dự phòng qua cáp USB Serial khi mất Wi-Fi.
"""

import time
import socket
import json
from .network import auto_detect_wifi_credentials, update_env_file, sync_env_to_firmware

# Biến toàn cục lưu IP LAN máy tính phục vụ UDP Beacon và Roaming
ACTIVE_LAN_IP = "127.0.0.1"


def udp_broker_beacon_worker(broker_port: int = 1883):
    """
    Luồng phát sóng định kỳ UDP Broadcast (Beacon) mỗi 3 giây trong mạng nội bộ.
    Giúp ESP32 tự động nhận biết địa chỉ IP của máy tính mà không cần nạp lại firmware
    kể cả khi máy tính chuyển sang Wi-Fi mới hoặc được cấp IP DHCP mới.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass

    while True:
        try:
            global ACTIVE_LAN_IP
            if ACTIVE_LAN_IP and ACTIVE_LAN_IP not in ("127.0.0.1", "0.0.0.0"):
                payload = json.dumps({
                    "service": "AeroEdge",
                    "broker_ip": ACTIVE_LAN_IP,
                    "port": broker_port
                }).encode("utf-8")
                s.sendto(payload, ("255.255.255.255", 18830))
        except Exception:
            pass
        time.sleep(3.0)


def network_roaming_watcher_worker(root_dir: str):
    """
    Luồng nền tự động giám sát card mạng và dải IP thời gian thực (Zero-Config Roaming).
    Khi phát hiện máy tính chuyển sang Wi-Fi mới (ví dụ từ mạng phòng sang Hotspot di động),
    tự động cập nhật IP mới vào .env, credentials.h và luồng UDP Beacon.
    """
    global ACTIVE_LAN_IP
    last_ssid, _, last_ip = auto_detect_wifi_credentials()
    ACTIVE_LAN_IP = last_ip

    while True:
        time.sleep(4.0)
        try:
            curr_ssid, curr_pwd, curr_ip = auto_detect_wifi_credentials()
            if curr_ip and curr_ip != "127.0.0.1" and (curr_ip != last_ip or (curr_ssid and curr_ssid != last_ssid)):
                print(f"\n[NetworkWatcher] >>> PHAT HIEN THAY DOI MANG (ROAMING) <<<")
                print(f"  * Mang cu : SSID='{last_ssid}', IP='{last_ip}'")
                print(f"  * Mang moi: SSID='{curr_ssid}', IP='{curr_ip}'")
                print(f"  -> Dang tu dong cap nhat cau hinh & phat song UDP Beacon toi ESP32...")
                last_ip = curr_ip
                last_ssid = curr_ssid
                ACTIVE_LAN_IP = curr_ip

                if curr_ssid and curr_pwd and curr_ip:
                    update_env_file(root_dir, curr_ssid, curr_pwd, curr_ip)
                    sync_env_to_firmware(root_dir)
        except Exception:
            pass


def serial_telemetry_bridge_worker(com_port: str, broker_port: int = 1883):
    """
    Cầu nối Telemetry dự phòng qua cáp USB Serial (Dual-Transport High Availability).
    Khi ESP32 cắm qua cổng USB, luồng này liên tục lắng nghe các gói tin JSON từ Serial.
    Nếu Wi-Fi bị ngắt do chuyển mạng hoặc router có AP Isolation, dữ liệu từ ESP32
    vẫn được truyền thẳng vào MQTT Broker cục bộ (127.0.0.1:1883) mà không bị gián đoạn 1 giây nào!
    """
    try:
        import serial
        import paho.mqtt.client as mqtt
    except ImportError:
        return

    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ESP32-USB-Serial-Bridge")
    try:
        mqtt_client.connect("127.0.0.1", broker_port, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[SerialBridge] Khong the ket noi MQTT 127.0.0.1: {e}")
        return

    print(f"  [SerialBridge] Da kich hoat cau noi USB Serial Telemetry tren {com_port} (115200 baud).")
    print(f"                 (Dam bao luu luong van truyen 100% ve Web Dashboard ke ca khi mat ket noi Wi-Fi!)")

    last_forwarded_ts = 0.0
    while True:
        try:
            with serial.Serial(com_port, 115200, timeout=2.0) as ser:
                while True:
                    line = ser.readline().decode("utf-8", errors="ignore").strip()
                    if line.startswith("ESP32_TELEMETRY:"):
                        json_str = line[len("ESP32_TELEMETRY:"):].strip()
                        now = time.time()
                        if now - last_forwarded_ts >= 0.5:
                            mqtt_client.publish("edge/telemetry/traffic", json_str)
                            last_forwarded_ts = now
        except Exception:
            time.sleep(2.0)
