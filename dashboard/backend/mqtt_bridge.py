"""
Dashboard MQTT to WebSocket Bridge Service
==========================================
Lắng nghe các topic telemetry, prediction, alerts và attack status từ MQTT
và chuyển tiếp tức thời đến Web Dashboard qua WebSocket.
"""

import time
import json
import asyncio
import math
import paho.mqtt.client as mqtt

from dashboard.backend.config import MQTT_BROKER_HOST, MQTT_BROKER_PORT
from dashboard.backend.state import state
from dashboard.backend.websocket_manager import manager

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="EdgeAI-Web-Dashboard-Backend")
loop_holder = {}


def on_mqtt_connect(client: mqtt.Client, userdata, flags, rc, properties=None):
    if rc == 0:
        state.broker_connected = True
        print(f"[DashboardBackend] Da ket noi MQTT Broker {MQTT_BROKER_HOST}:{MQTT_BROKER_PORT}")
        client.subscribe("edge/telemetry/traffic")
        client.subscribe("edge/telemetry/window")
        client.subscribe("edge/telemetry/prediction")
        client.subscribe("edge/alerts/high_priority")
        client.subscribe("edge/nodes/status")
        client.subscribe("edge/attack/status", qos=1)
        client.subscribe("edge/digital_twin/state")
        client.subscribe("edge/defense/action")
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

    if not isinstance(payload, dict):
        return
    main_loop = loop_holder.get("loop")
    if not main_loop or main_loop.is_closed():
        return
    main_loop.call_soon_threadsafe(process_mqtt_payload, topic, payload)


def process_mqtt_payload(topic: str, payload: dict) -> None:
    """Mutate dashboard state only on the owning asyncio loop."""
    main_loop = loop_holder.get("loop")
    if not main_loop or main_loop.is_closed():
        return
    if topic == "edge/telemetry/traffic" and payload.get("record_kind") == "packet":
        return

    if topic == "edge/telemetry/window":
        rates = [payload.get(name) for name in ("packet_rate", "byte_rate")]
        if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in rates):
            return
        key = (payload.get("device_id"), payload.get("capture_id"))
        count = payload.get("captured_packets")
        if isinstance(count, int) and count >= 0:
            previous = state.capture_totals.get(key, 0)
            state.total_packets_inspected += max(0, count - previous)
            state.capture_totals[key] = max(count, previous)
            if len(state.capture_totals) > 128:
                del state.capture_totals[next(iter(state.capture_totals))]
        state.latest_traffic_window = payload
        if payload.get("scanned_networks"):
            state.update_wifi_networks(payload["scanned_networks"])
        asyncio.run_coroutine_threadsafe(manager.broadcast({
            "type": "TRAFFIC_WINDOW_UPDATE", "data": payload,
            "total_packets": state.total_packets_inspected}), main_loop)
        return

    now_ts = int(time.time() * 1000)

    if topic == "edge/attack/status":
        state.attack_status = payload.get("status", "IDLE")
        state.attack_scenario = payload.get("scenario", "Normal")
        state.attack_target_ip = payload.get("target_ip", "127.0.0.1")
        state.attack_auto_cycle = bool(payload.get("auto_cycle", False))
        state.attack_details = {key: payload.get(key) for key in (
            "command_id", "timestamp", "expires_at_ms", "error", "experiment_id", "implementation_status")}

        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "ATTACK_STATUS_UPDATE",
                "attack_status": {
                    "status": state.attack_status,
                    "scenario": state.attack_scenario,
                    "target_ip": state.attack_target_ip,
                    "auto_cycle": state.attack_auto_cycle,
                    **state.attack_details,
                    "error": payload.get("error"),
                    "experiment_id": payload.get("experiment_id"),
                    "implementation_status": payload.get("implementation_status")
                }
            }),
            main_loop
        )

    elif topic == "edge/nodes/status":
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
        raw = payload.get("raw_telemetry", {})
        if not isinstance(raw, dict):
            return
        if raw.get("record_kind") == "packet":
            device = str(payload.get("device_id", "probe"))
            now = time.monotonic()
            if now - state.prediction_broadcast_times.get(device, -float("inf")) < 0.2:
                return  # Display samples at most 5/s/device; inference still runs on each packet.
            state.prediction_broadcast_times[device] = now
            if len(state.prediction_broadcast_times) > 128:
                del state.prediction_broadcast_times[next(iter(state.prediction_broadcast_times))]
        inference_status = payload.get("inference_status", "ok")
        anomaly_score = float(payload.get("anomaly_score") or 0.0)
        # TÔN TRỌNG TRIỆT ĐỂ NGƯỠNG ANOMALY DO USER THIẾT LẬP HOẶC KÉO THANH TRÊN UI
        current_thresh = float(getattr(state, "anomaly_threshold", 0.55))
        is_anomaly = inference_status == "ok" and bool(payload.get("is_anomaly", anomaly_score >= current_thresh))
        if inference_status != "ok":
            threat_type, severity = "Unknown", "UNKNOWN"
        elif not is_anomaly:
            threat_type = "Normal"
            severity = "NORMAL"
        else:
            threat_type = payload.get("threat_type", "Normal")
            severity = payload.get("severity", "CRITICAL")

        raw = payload.get("raw_telemetry", {})

        state.current_anomaly_score = anomaly_score if inference_status == "ok" else None
        state.current_threat_level = severity
        if raw.get("record_kind") != "packet":
            state.total_packets_inspected += int(raw.get("packet_rate", 0))

        data_point = {
            "record_kind": raw.get("record_kind", "window"),
            "inference_status": inference_status,
            "inference_source": payload.get("inference_source", "host"),
            "inference_error": payload.get("error"),
            "timestamp": now_ts if (not raw.get("timestamp") or raw.get("timestamp") < 1000000000000) else raw.get("timestamp"),
            "device_id": payload.get("device_id", "probe"),
            "src_ip": raw.get("src_ip", "Unknown"),
            "dst_ip": raw.get("dst_ip", "Unknown"),
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dst_port"),
            "protocol": raw.get("protocol", "Unknown"),
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
            "anomaly_score": anomaly_score if inference_status == "ok" else None,
            "is_anomaly": is_anomaly,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": float(payload.get("confidence", 1.0)),
            "top_probabilities": payload.get("top_probabilities", {}),
            "class_probabilities": payload.get("class_probabilities", {}),
            "edge_prediction": payload.get("edge_prediction") or raw.get("edge_prediction", "Normal"),
            "edge_flag": bool(payload.get("edge_flag") or raw.get("edge_flag", False)),
            "edge_inference_status": payload.get("edge_inference_status") or raw.get("edge_inference_status"),
            "edge_model_version": payload.get("edge_model_version"),
            "edge_input_profile": payload.get("edge_input_profile"),
            "edge_threshold": payload.get("edge_threshold"),
            "edge_model": payload.get("edge_model") or raw.get("edge_model", "Edge TinyML"),
            "edge_features_count": payload.get("edge_features_count", raw.get("edge_features_count", 56)),
            "host_classifier": payload.get("host_classifier", "Host Classifier"),
            "host_anomaly_detector": payload.get("host_anomaly_detector", "Anomaly Detector"),
            "host_features_count": payload.get("host_features_count", 56),
            "traffic_mode": payload.get("traffic_mode") or getattr(state, "traffic_mode", "encrypted"),
            "dataset_name": payload.get("dataset_name") or getattr(state, "dataset_name", "USTC-TFC2016"),
            "profile": payload.get("profile") or getattr(state, "profile", "esp32-l234-packet-v1"),
            "is_encrypted": bool(payload.get("traffic_mode") == "encrypted" or raw.get("record_kind") == "packet" or getattr(state, "traffic_mode", "") == "encrypted"),
            "latency_ms": payload.get("latency_ms", 0.0),
            "scanned_networks": raw.get("scanned_networks", [])
        }

        if raw.get("record_kind") == "packet":
            # A packet has no window rate: do not overwrite the independent throughput stream.
            for name in ("packet_rate", "byte_rate", "avg_packet_size", "syn_ratio", "ack_ratio", "udp_ratio", "icmp_ratio", "unique_dst_ports"):
                data_point.pop(name, None)
            data_point["packet_length"] = raw.get("frame_length") or raw.get("tcp.len")
            data_point["src_port"] = raw.get("tcp.srcport") or raw.get("udp.port")
            data_point["dst_port"] = raw.get("tcp.dstport")
            data_point["tcp_flags"] = raw.get("tcp.flags")
            data_point["tcp_len"] = raw.get("tcp.len")
            data_point["tcp_ack_raw"] = raw.get("tcp.ack_raw")
            data_point["tcp_checksum"] = raw.get("tcp.checksum")
            data_point["arp_opcode"] = raw.get("arp.opcode")
            data_point["arp_hw_size"] = raw.get("arp.hw.size")
            data_point["icmp_checksum"] = raw.get("icmp.checksum")

        # Cập nhật danh sách mạng WiFi bắt được từ ESP32 / Host
        scanned_nets = raw.get("scanned_networks", [])
        if scanned_nets:
            state.update_wifi_networks(scanned_nets)

        state.add_telemetry(data_point)

        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "TELEMETRY_UPDATE",
                "data": data_point,
                "total_packets": state.total_packets_inspected,
                "total_threats": state.total_threats_detected,
                "detected_wifi_networks": state.detected_wifi_networks
            }),
            main_loop
        )

    elif topic == "edge/telemetry/traffic":
        # Hỗ trợ nhận trực tiếp scanned_networks nếu chưa qua inference service
        scanned_nets = payload.get("scanned_networks", [])
        if scanned_nets:
            state.update_wifi_networks(scanned_nets)
            asyncio.run_coroutine_threadsafe(
                manager.broadcast({
                    "type": "WIFI_NETWORKS_UPDATE",
                    "networks": state.detected_wifi_networks
                }),
                main_loop
            )

    elif topic == "edge/alerts/high_priority":
        packet_id = payload.get("packet_id")
        if isinstance(packet_id, str) and packet_id:
            if packet_id in state.alert_packet_ids:
                return
            state.alert_packet_ids[packet_id] = True
            if len(state.alert_packet_ids) > 8192:
                del state.alert_packet_ids[next(iter(state.alert_packet_ids))]
        raw_alert = payload.get("raw_telemetry", {})
        alert_entry = {
            "id": f"alert_{int(time.time()*1000)}_{len(state.alerts_history)+1}",
            "timestamp": now_ts,
            "device_id": payload.get("device_id", "probe"),
            "threat_type": payload.get("threat_type", payload.get("edge_prediction", "Unknown Threat")),
            "severity": payload.get("severity", "CRITICAL"),
            "anomaly_score": payload.get("anomaly_score"),
            "src_ip": raw_alert.get("src_ip", "Unknown"),
            "dst_ip": raw_alert.get("dst_ip", "Unknown"),
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

    elif topic == "edge/digital_twin/state":
        state.digital_twin_state = payload
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "DIGITAL_TWIN_UPDATE",
                "digital_twin": payload
            }),
            main_loop
        )

    elif topic == "edge/defense/action":
        if not hasattr(state, "defense_actions"):
            state.defense_actions = []
        state.defense_actions.append(payload)
        if len(state.defense_actions) > 100:
            state.defense_actions.pop(0)
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({
                "type": "DEFENSE_ACTION_EVENT",
                "action_event": payload
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
