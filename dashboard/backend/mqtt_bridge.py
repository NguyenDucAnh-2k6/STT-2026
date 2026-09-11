"""
Dashboard MQTT to WebSocket Bridge Service
==========================================
Lắng nghe các topic telemetry, prediction, alerts từ MQTT và chuyển tiếp đến Web Dashboard.
"""

import time
import json
import asyncio
import paho.mqtt.client as mqtt

from dashboard.backend.config import MQTT_BROKER_HOST, MQTT_BROKER_PORT
from dashboard.backend.state import state
from dashboard.backend.websocket_manager import manager

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="EdgeAI-Web-Dashboard-Backend")
loop_holder = {}


def on_mqtt_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        state.broker_connected = True
        print(f"[DashboardBackend] Da ket noi MQTT Broker {MQTT_BROKER_HOST}:{MQTT_BROKER_PORT}")
        client.subscribe("edge/telemetry/traffic")
        client.subscribe("edge/telemetry/prediction")
        client.subscribe("edge/alerts/high_priority")
        client.subscribe("edge/nodes/status")
    else:
        state.broker_connected = False
        print(f"[DashboardBackend] Ket noi broker that bai (rc={rc})")


def on_mqtt_disconnect(client, userdata, disconnect_flags, rc, properties=None):
    state.broker_connected = False
    print("[DashboardBackend] Mat ket noi MQTT Broker")


def on_mqtt_message(client, userdata, msg):
    topic = msg.topic
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
    except Exception:
        return

    main_loop = loop_holder.get("loop")
    if not main_loop or main_loop.is_closed():
        return

    now_ts = int(time.time() * 1000)

    if topic == "edge/nodes/status":
        dev_id = payload.get("device_id", "unknown")
        status = payload.get("status", "online")
        state.connected_nodes[dev_id] = {
            "device_id": dev_id,
            "status": status,
            "last_seen": now_ts
        }
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"type": "NODE_UPDATE", "node": state.connected_nodes[dev_id]}),
            main_loop
        )

    elif topic == "edge/telemetry/prediction":
        anomaly_score = float(payload.get("anomaly_score", 0.0))
        is_anomaly = bool(payload.get("is_anomaly", False))
        threat_type = payload.get("threat_type", "Normal")
        severity = payload.get("severity", "NORMAL")
        raw = payload.get("raw_telemetry", {})

        state.current_anomaly_score = anomaly_score
        state.current_threat_level = severity
        state.total_packets_inspected += int(raw.get("packet_rate", 0))

        data_point = {
            "timestamp": now_ts if (not raw.get("timestamp") or raw.get("timestamp") < 1000000000000) else raw.get("timestamp"),
            "device_id": payload.get("device_id", "probe"),
            "src_ip": raw.get("src_ip", "192.168.137.149"),
            "dst_ip": raw.get("dst_ip", "192.168.137.1"),
            "src_port": raw.get("src_port", 5683),
            "dst_port": raw.get("dst_port", 5683),
            "protocol": raw.get("protocol", "CoAP"),
            "packet_length": raw.get("packet_length", int(raw.get("avg_packet_size", 64))),
            "info": raw.get("info", ""),
            "packet_rate": raw.get("packet_rate", 0.0),
            "byte_rate": raw.get("byte_rate", 0.0),
            "avg_packet_size": raw.get("avg_packet_size", 0.0),
            "syn_ratio": raw.get("syn_ratio", 0.0),
            "ack_ratio": raw.get("ack_ratio", 0.0),
            "udp_ratio": raw.get("udp_ratio", 0.0),
            "icmp_ratio": raw.get("icmp_ratio", 0.0),
            "unique_dst_ports": raw.get("unique_dst_ports", 0),
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": float(payload.get("confidence", 1.0)),
            "top_probabilities": payload.get("top_probabilities", {}),
            "class_probabilities": payload.get("class_probabilities", {}),
            "edge_prediction": payload.get("edge_prediction") or raw.get("edge_prediction", "Normal"),
            "edge_flag": bool(payload.get("edge_flag") or raw.get("edge_flag", False)),
            "latency_ms": payload.get("latency_ms", 0.0)
        }

        state.add_telemetry(data_point)

        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "TELEMETRY_UPDATE",
                "data": data_point,
                "total_packets": state.total_packets_inspected,
                "total_threats": state.total_threats_detected
            }),
            main_loop
        )

    elif topic == "edge/alerts/high_priority":
        raw_alert = payload.get("raw_telemetry", {})
        alert_entry = {
            "id": f"alert_{int(time.time()*1000)}_{len(state.alerts_history)+1}",
            "timestamp": now_ts,
            "device_id": payload.get("device_id", "probe"),
            "threat_type": payload.get("threat_type", payload.get("edge_prediction", "Unknown Threat")),
            "severity": payload.get("severity", "CRITICAL"),
            "anomaly_score": payload.get("anomaly_score", 0.95),
            "src_ip": raw_alert.get("src_ip", "192.168.137.149"),
            "dst_ip": raw_alert.get("dst_ip", "192.168.137.1"),
            "protocol": raw_alert.get("protocol", "TCP"),
            "details": f"{raw_alert.get('protocol', 'TCP')} {raw_alert.get('src_ip', '')}:{raw_alert.get('src_port', '')}->{raw_alert.get('dst_ip', '')}:{raw_alert.get('dst_port', '')} | PktRate: {raw_alert.get('packet_rate', 0)}/s | SYN: {raw_alert.get('syn_ratio', 0)}"
        }
        state.add_alert(alert_entry)

        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "ALERT_TRIGGERED",
                "alert": alert_entry,
                "total_threats": state.total_threats_detected
            }),
            main_loop
        )


mqtt_client.on_connect = on_mqtt_connect
mqtt_client.on_disconnect = on_mqtt_disconnect
mqtt_client.on_message = on_mqtt_message


def start_mqtt_bridge(loop):
    """Khởi động client MQTT trong luồng nền gắn kết với asyncio loop."""
    loop_holder["loop"] = loop
    try:
        mqtt_client.connect_async(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[DashboardBackend] Chua the ket noi MQTT Broker: {e}")


def stop_mqtt_bridge():
    """Dừng client MQTT khi ứng dụng tắt."""
    try:
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
    except Exception:
        pass
