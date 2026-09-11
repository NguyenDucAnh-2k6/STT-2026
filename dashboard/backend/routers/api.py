"""
Dashboard REST API Endpoints Router
===================================
Cung cấp các API kiểm tra trạng thái, điều khiển kịch bản tấn công giả lập, điều chỉnh ngưỡng.
"""

import json
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dashboard.backend.state import state
from dashboard.backend.models import InjectAttackRequest, ThresholdRequest
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
        "anomaly_threshold": state.anomaly_threshold
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


@router.post("/simulator/scenario")
async def set_simulator_scenario(req: InjectAttackRequest):
    """Gửi lệnh thay đổi kịch bản lưu lượng tới simulator qua MQTT."""
    try:
        mqtt_client.publish(
            "edge/simulator/control",
            json.dumps({"command": "INJECT_MODE", "mode": req.attack_type})
        )
        return {"status": "success", "message": f"Da phat lenh chuyen kịch ban sang: {req.attack_type}"}
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
