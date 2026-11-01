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
import logging
import threading
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
                    # Keep explicit .env values intact. A changed SSID requires a new build/flash.
                    sync_env_to_firmware(root_dir)
        except Exception:
            pass


def serial_telemetry_bridge_worker(com_port: str, broker_port: int = 1883,
                                   broker_host: str = "127.0.0.1",
                                   stop_event: threading.Event | None = None) -> None:
    """
    Forward bounded radio frames and windows; MQTT/USB identities are deduplicated downstream.
    """
    try:
        import serial
        import paho.mqtt.client as mqtt
    except ImportError as exc:
        logging.getLogger(__name__).error("USB bridge unavailable: install pyserial and paho-mqtt (%s)", exc.name)
        return
    stop = stop_event if stop_event is not None else threading.Event()
    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ESP32-USB-Serial-Bridge")
    mqtt_client.max_queued_messages_set(128)
    try:
        mqtt_client.connect(broker_host, broker_port, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[SerialBridge] Khong the ket noi MQTT: {type(e).__name__}")
        mqtt_client.disconnect()
        return

    print(f"  [SerialBridge] Da kich hoat cau noi USB Serial Telemetry tren {com_port} (115200 baud).")
    try:
        while not stop.is_set():
            try:
                with serial.Serial(com_port, 115200, timeout=0.5) as ser:
                    while not stop.is_set():
                        raw = ser.read_until(b"\n", size=8193)
                        if len(raw) > 8192 or not raw.endswith(b"\n"):
                            continue
                        line = raw.decode("utf-8", errors="replace").strip()
                        if line.startswith("[Gateway"):
                            print(f"  {line}")
                            if line.startswith("[Gateway Monitor]"):
                                try:
                                    parts = line.split("|")
                                    if len(parts) >= 4:
                                        length = int(parts[0].split("Len:")[1].strip())
                                        ports = parts[1].split("->")
                                        src_p = int(ports[0].replace("Port", "").strip())
                                        dst_p = int(ports[1].strip())
                                        pred_part = parts[2].split("Pred:")[1].strip()
                                        threat = pred_part.split("(")[0].strip()
                                        conf_pct = float(pred_part.split("(")[1].split("%")[0].strip()) / 100.0
                                        is_anom = threat != "Normal"
                                        gw_pred = {
                                            "device_id": "AERO-ESP32-Gateway",
                                            "inference_status": "ok",
                                            "inference_source": "esp32_gateway",
                                            "anomaly_score": 0.85 if is_anom else 0.15,
                                            "is_anomaly": is_anom,
                                            "threat_type": threat,
                                            "confidence": conf_pct,
                                            "severity": "CRITICAL" if is_anom else "NORMAL",
                                            "raw_telemetry": {
                                                "record_kind": "packet",
                                                "protocol": "TCP" if dst_p in (80, 443, 853) else "IP",
                                                "src_port": src_p,
                                                "dst_port": dst_p,
                                                "frame_length": length
                                            }
                                        }
                                        mqtt_client.publish("edge/telemetry/prediction", json.dumps(gw_pred), qos=0)
                                        if is_anom:
                                            gw_alert = {
                                                "device_id": "AERO-ESP32-Gateway",
                                                "threat_type": threat,
                                                "severity": "CRITICAL",
                                                "anomaly_score": 0.85,
                                                "confidence": conf_pct,
                                                "raw_telemetry": {
                                                    "protocol": "TCP" if dst_p in (80, 443, 853) else "IP",
                                                    "src_port": src_p,
                                                    "dst_port": dst_p,
                                                    "packet_length": length
                                                }
                                            }
                                            mqtt_client.publish("edge/alerts/high_priority", json.dumps(gw_alert), qos=1)
                                except Exception:
                                    pass
                            continue

                        if line.startswith("ESP32_RADIO:"):
                            topic = "edge/telemetry/radio"
                        elif line.startswith("ESP32_TELEMETRY:"):
                            topic = "edge/telemetry/traffic"
                        elif line.startswith("ESP32_PREDICTION:"):
                            topic = "edge/telemetry/prediction"
                        elif line.startswith("ESP32_ALERT:"):
                            topic = "edge/alerts/high_priority"
                        else:
                            topic = None

                        if topic is None:
                            continue
                        try:
                            payload = json.loads(line.split(":", 1)[1], parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
                            if not isinstance(payload, dict) or not isinstance(payload.get("device_id"), str):
                                raise ValueError("Invalid telemetry identity/shape")
                            if topic == "edge/telemetry/radio":
                                from firmware.esp32_probe.radio_capture import parse_radio_sample
                                parse_radio_sample(payload, int(time.time() * 1000))
                            encoded = json.dumps(payload, allow_nan=False)
                            result = mqtt_client.publish(topic, encoded, qos=1, retain=False)
                            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                                logging.getLogger(__name__).warning("USB bridge MQTT publish failed: rc=%s", result.rc)
                            if topic == "edge/telemetry/traffic" and payload.get("radio_capture_version") == 1:
                                window_result = mqtt_client.publish("edge/telemetry/window", encoded, qos=0, retain=False)
                                if window_result.rc != mqtt.MQTT_ERR_SUCCESS:
                                    logging.getLogger(__name__).warning("USB window publish failed: rc=%s", window_result.rc)
                        except (ValueError, TypeError):
                            logging.getLogger(__name__).warning("USB bridge rejected malformed telemetry")
            except (serial.SerialException, OSError, UnicodeError):
                logging.getLogger(__name__).warning("USB telemetry disconnected; retrying")
                stop.wait(2)
    finally:
        mqtt_client.disconnect()
        mqtt_client.loop_stop()
