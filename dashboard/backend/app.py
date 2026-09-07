#!/usr/bin/env python3
"""
Edge AI Network Security Dashboard - Backend Server
====================================================
FastAPI + WebSocket + MQTT Bridge
- Kết nối MQTT broker nhận luồng telemetry & alerts từ ESP32 probe và ML engine.
- Phát sóng thời gian thực qua WebSocket /ws/telemetry tới giao diện Web Dashboard.
- Cung cấp REST API điều khiển simulator và điều chỉnh cấu hình ngưỡng cảnh báo.
"""

import os
import sys
import time
import json
import asyncio
from typing import List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import paho.mqtt.client as mqtt

# Cấu hình
MQTT_BROKER_HOST = os.getenv("MQTT_HOST", "127.0.0.1")
MQTT_BROKER_PORT = int(os.getenv("MQTT_PORT", 1883))
WEB_PORT = int(os.getenv("PORT", 8000))

# Trạng thái hệ thống lưu trong bộ nhớ
class SystemState:
    def __init__(self):
        self.connected_nodes: Dict[str, dict] = {}
        self.telemetry_history: List[dict] = []
        self.alerts_history: List[dict] = []
        self.total_packets_inspected: int = 0
        self.total_threats_detected: int = 0
        self.current_anomaly_score: float = 0.0
        self.current_threat_level: str = "NORMAL"
        self.anomaly_threshold: float = 0.55
        self.broker_connected: bool = False
        self.active_websockets: List[WebSocket] = []

state = SystemState()

# WebSocket Connection Manager
class ConnectionManager:
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        state.active_websockets.append(websocket)
        # Gửi dữ liệu khởi tạo ban đầu cho client mới
        initial_payload = {
            "type": "INITIAL_STATE",
            "connected_nodes": list(state.connected_nodes.values()),
            "history": state.telemetry_history[-30:],
            "alerts": state.alerts_history[-20:],
            "total_packets": state.total_packets_inspected,
            "total_threats": state.total_threats_detected,
            "anomaly_threshold": state.anomaly_threshold,
            "broker_connected": state.broker_connected
        }
        await websocket.send_text(json.dumps(initial_payload))

    def disconnect(self, websocket: WebSocket):
        if websocket in state.active_websockets:
            state.active_websockets.remove(websocket)

    async def broadcast(self, message: dict):
        msg_str = json.dumps(message)
        disconnected = []
        for ws in state.active_websockets:
            try:
                await ws.send_text(msg_str)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)

manager = ConnectionManager()

# Khởi tạo MQTT Client cho FastAPI
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
        # Dữ liệu đã qua suy luận ML Engine
        anomaly_score = float(payload.get("anomaly_score", 0.0))
        is_anomaly = bool(payload.get("is_anomaly", False))
        threat_type = payload.get("threat_type", "Normal")
        severity = payload.get("severity", "NORMAL")
        raw = payload.get("raw_telemetry", {})

        state.current_anomaly_score = anomaly_score
        state.current_threat_level = severity
        state.total_packets_inspected += int(raw.get("packet_rate", 0) * 2)

        data_point = {
            "timestamp": now_ts,
            "device_id": payload.get("device_id", "probe"),
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
            "edge_prediction": raw.get("edge_prediction", "Unknown"),
            "latency_ms": payload.get("latency_ms", 0.0)
        }

        state.telemetry_history.append(data_point)
        if len(state.telemetry_history) > 200:
            state.telemetry_history.pop(0)

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
        state.total_threats_detected += 1
        alert_entry = {
            "id": f"alert_{int(time.time()*1000)}_{len(state.alerts_history)+1}",
            "timestamp": now_ts,
            "device_id": payload.get("device_id", "probe"),
            "threat_type": payload.get("threat_type", payload.get("edge_prediction", "Unknown Threat")),
            "severity": payload.get("severity", "CRITICAL"),
            "anomaly_score": payload.get("anomaly_score", 0.95),
            "details": f"Packet Rate: {payload.get('raw_telemetry', payload).get('packet_rate', 0)} pkts/s | SYN: {payload.get('raw_telemetry', payload).get('syn_ratio', 0)}"
        }
        state.alerts_history.append(alert_entry)
        if len(state.alerts_history) > 100:
            state.alerts_history.pop(0)

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Khởi động MQTT client trong nền
    loop_holder["loop"] = asyncio.get_running_loop()
    try:
        mqtt_client.connect_async(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"[DashboardBackend] Chua the ket noi MQTT Broker: {e}")
    yield
    mqtt_client.loop_stop()
    mqtt_client.disconnect()

app = FastAPI(
    title="Edge AI Network Anomaly Detection Dashboard",
    description="Real-time telemetry and cybersecurity monitoring on edge",
    version="1.0.0",
    lifespan=lifespan
)

# Request Models
class InjectAttackRequest(BaseModel):
    attack_type: str  # NORMAL, SYN_FLOOD, PORT_SCAN, VOLUMETRIC_DDOS, DATA_EXFILTRATION

class ThresholdRequest(BaseModel):
    threshold: float

# REST API Endpoints
@app.get("/api/status")
async def get_status():
    return {
        "status": "healthy",
        "broker_connected": state.broker_connected,
        "active_nodes_count": len(state.connected_nodes),
        "total_packets_inspected": state.total_packets_inspected,
        "total_threats_detected": state.total_threats_detected,
        "current_threat_level": state.current_threat_level,
        "current_anomaly_score": state.current_anomaly_score,
        "anomaly_threshold": state.anomaly_threshold
    }

@app.get("/api/history")
async def get_history(limit: int = 50):
    return state.telemetry_history[-limit:]

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    return state.alerts_history[-limit:]

@app.post("/api/settings/threshold")
async def update_threshold(req: ThresholdRequest):
    if 0.0 <= req.threshold <= 1.0:
        state.anomaly_threshold = req.threshold
        await manager.broadcast({"type": "THRESHOLD_UPDATED", "threshold": state.anomaly_threshold})
        return {"status": "ok", "anomaly_threshold": state.anomaly_threshold}
    return JSONResponse(status_code=400, content={"error": "Threshold must be between 0.0 and 1.0"})

@app.post("/api/simulator/inject")
async def inject_attack(req: InjectAttackRequest):
    """Gửi lệnh điều khiển mô phỏng tới Simulator qua MQTT"""
    cmd_payload = json.dumps({"command": "INJECT_MODE", "mode": req.attack_type})
    try:
        mqtt_client.publish("edge/simulator/control", cmd_payload)
        return {"status": "command_sent", "attack_type": req.attack_type}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# WebSocket Endpoint
@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Nhận ping hoặc message từ frontend nếu có
            data = await websocket.receive_text()
            try:
                parsed = json.loads(data)
                if parsed.get("action") == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# Mount Static Files (Frontend)
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def serve_index():
    index_file = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Frontend index.html not found"}

def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="info")

if __name__ == "__main__":
    main()
