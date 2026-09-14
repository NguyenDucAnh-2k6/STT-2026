"""
Dashboard REST API Endpoints Router
===================================
Cung cấp các API kiểm tra trạng thái, điều khiển bắn gói tin mạng thật, điều chỉnh ngưỡng phát hiện.
"""

import json
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dashboard.backend.state import state
from dashboard.backend.models import (
    InjectAttackRequest,
    AttackTriggerRequest,
    AutoCycleRequest,
    ThresholdRequest,
)
from dashboard.backend.mqtt_bridge import mqtt_client

router = APIRouter(prefix="/api", tags=["Monitoring & Control"])


@router.get("/status")
async def get_status():
    """Lấy trạng thái tổng quan hệ thống."""
    return {
        "status": "healthy",
        "broker_connected": state.broker_connected,
        "active_nodes_count": len(state.connected_nodes),
        "total_packets_inspected": state.total_packets_inspected,
        "total_threats_detected": state.total_threats_detected,
        "current_anomaly_score": state.current_anomaly_score,
        "current_threat_level": state.current_threat_level,
        "anomaly_threshold": state.anomaly_threshold,
        "attack_status": {
            "status": state.attack_status,
            "scenario": state.attack_scenario,
            "target_ip": state.attack_target_ip,
            "auto_cycle": state.attack_auto_cycle
        }
    }


@router.get("/history")
async def get_history(limit: int = 50):
    """Lấy lịch sử telemetry gần đây."""
    return state.telemetry_history[-limit:]


@router.get("/alerts")
async def get_alerts(limit: int = 20):
    """Lấy danh sách các cảnh báo bảo mật gần đây."""
    return state.alerts_history[-limit:]


@router.get("/nodes")
async def get_nodes():
    """Lấy danh sách các thiết bị/probe đang kết nối."""
    return list(state.connected_nodes.values())


@router.get("/attack/status")
async def get_attack_status():
    """Lấy trạng thái hiện tại của bộ phát sinh tấn công mạng thật."""
    return {
        "status": state.attack_status,
        "scenario": state.attack_scenario,
        "target_ip": state.attack_target_ip,
        "auto_cycle": state.attack_auto_cycle
    }


@router.post("/attack/trigger")
async def trigger_attack(req: AttackTriggerRequest):
    """Phát động cuộc tấn công mạng thật (socket) tới Target IP."""
    try:
        payload = {
            "command": "TRIGGER",
            "mode": req.attack_type,
            "target_ip": req.target_ip
        }
        mqtt_client.publish("edge/attack/control", json.dumps(payload))
        return {
            "status": "success",
            "message": f"Da kich hoat ban goi tin doc hai: {req.attack_type}",
            "scenario": req.attack_type
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/attack/stop")
async def stop_attack():
    """Dừng đợt tấn công và đưa lưu lượng mạng về Normal."""
    try:
        payload = {"command": "STOP", "mode": "Normal"}
        mqtt_client.publish("edge/attack/control", json.dumps(payload))
        return {"status": "success", "message": "Da dung tan cong, luu luong tro ve binh thuong"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/attack/auto-cycle")
async def toggle_auto_cycle(req: AutoCycleRequest):
    """Bật hoặc tắt chế độ tự động xoay tua các đợt tấn công."""
    try:
        payload = {"command": "AUTO_CYCLE", "enabled": req.enabled}
        mqtt_client.publish("edge/attack/control", json.dumps(payload))
        return {
            "status": "success",
            "auto_cycle": req.enabled,
            "message": f"Che do Tu dong xoay tua da {'BAT' if req.enabled else 'TAT'}"
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/simulator/scenario")
async def set_simulator_scenario(req: InjectAttackRequest):
    """Tương thích ngược: Điều khiển chuyển kịch bản tấn công qua MQTT."""
    try:
        cmd = "STOP" if req.attack_type.upper() == "NORMAL" else "TRIGGER"
        payload = {"command": cmd, "mode": req.attack_type}
        mqtt_client.publish("edge/attack/control", json.dumps(payload))
        mqtt_client.publish("edge/simulator/control", json.dumps(payload))
        return {"status": "success", "message": f"Da chuyen kịch ban sang: {req.attack_type}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/config/threshold")
async def set_threshold(req: ThresholdRequest):
    """Cập nhật ngưỡng phát hiện bất thường Anomaly Score."""
    if 0.1 <= req.threshold <= 0.99:
        state.anomaly_threshold = round(req.threshold, 2)
        try:
            mqtt_client.publish(
                "edge/config/threshold",
                json.dumps({"threshold": state.anomaly_threshold})
            )
        except Exception:
            pass
        return {"status": "success", "anomaly_threshold": state.anomaly_threshold}
    return JSONResponse(status_code=400, content={"status": "error", "message": "Nguong threshold hop le: 0.10 - 0.99"})
