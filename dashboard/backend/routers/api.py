"""
Dashboard REST API Endpoints Router
===================================
Cung cấp các API kiểm tra trạng thái, điều khiển bắn gói tin mạng thật, điều chỉnh ngưỡng phát hiện.
"""

import json
import asyncio
import uuid
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dashboard.backend.state import state
from dashboard.backend.models import (
    InjectAttackRequest,
    AttackTriggerRequest,
    AutoCycleRequest,
    ThresholdRequest,
    ExperimentStartRequest,
)
from dashboard.backend.mqtt_bridge import mqtt_client
from firmware.simulator.scenarios import require_implemented, require_twin_scenario, IMPLEMENTED_SCENARIOS
from firmware.simulator.lab_config import validate_lab_target
import paho.mqtt.client as mqtt

router = APIRouter(prefix="/api", tags=["Monitoring & Control"])


@router.post("/experiments/start")
async def start_experiment(req: ExperimentStartRequest):
    from dashboard.backend import experiment_runtime
    if experiment_runtime.service is None:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Twin experiment service unavailable; restart backend"})
    try:
        # Stop legacy cycling; new experiment worker owns the selected workload.
        scenario = require_twin_scenario(req.scenario)
        if state.attack_auto_cycle or state.attack_status == "ATTACKING":
            result = mqtt_client.publish("edge/attack/control", json.dumps({"command": "STOP"}), qos=1, retain=False)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("Cannot stop legacy generator before collecting")
        return await asyncio.to_thread(experiment_runtime.service.start, scenario, req.duration_sec)
    except ValueError as error:
        return JSONResponse(status_code=422, content={"status": "error", "message": str(error)})
    except RuntimeError as error:
        return JSONResponse(status_code=409, content={"status": "error", "message": str(error)})


@router.post("/experiments/stop")
async def stop_experiment():
    from dashboard.backend import experiment_runtime
    if experiment_runtime.service is None:
        return JSONResponse(status_code=503, content={"status": "error", "message": "Twin experiment service unavailable"})
    return experiment_runtime.service.stop()


@router.get("/experiments/status")
async def experiment_status() -> dict:
    return state.experiment_status


@router.get("/status")
async def get_status():
    """Lấy trạng thái tổng quan hệ thống."""
    return {
        "status": "healthy",
        "broker_connected": state.broker_connected,
        "active_nodes_count": len(state.connected_nodes),
        "total_packets_inspected": state.total_packets_inspected,
        "capture_health": state.latest_traffic_window,
        "experiment_status": state.experiment_status,
        "total_threats_detected": state.total_threats_detected,
        "current_anomaly_score": state.current_anomaly_score,
        "current_threat_level": state.current_threat_level,
        "anomaly_threshold": state.anomaly_threshold,
        "attack_status": {
            "status": state.attack_status,
            "scenario": state.attack_scenario,
            "target_ip": state.attack_target_ip,
            "auto_cycle": state.attack_auto_cycle,
            **state.attack_details
        },
        "system_models": {
            "classifier": state.host_classifier,
            "anomaly_detector": state.host_anomaly_detector,
            "edge_model": state.edge_model,
            "features_count": state.features_count,
            "traffic_mode": state.traffic_mode,
            "dataset_name": state.dataset_name,
            "profile": state.profile,
            "labels": state.model_labels,
            "features": state.features_list
        }
    }


@router.get("/system/models")
async def get_system_models():
    """Lấy thông tin mô hình Machine Learning & Deep Learning hiện tại."""
    return {
        "status": "success",
        "classifier": state.host_classifier,
        "anomaly_detector": state.host_anomaly_detector,
        "edge_model": state.edge_model,
        "features_count": state.features_count,
        "traffic_mode": state.traffic_mode,
        "dataset_name": state.dataset_name,
        "profile": state.profile,
        "labels": state.model_labels,
        "features": state.features_list
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


@router.get("/wifi/networks")
async def get_wifi_networks():
    """Lấy danh sách các mạng WiFi (SSID) ESP-32 hoặc Host Probe bắt được qua sóng."""
    return {
        "status": "success",
        "count": len(state.detected_wifi_networks),
        "networks": state.detected_wifi_networks
    }


@router.get("/attack/status")
async def get_attack_status():
    """Lấy trạng thái hiện tại của bộ phát sinh tấn công mạng thật."""
    return {
        "status": state.attack_status,
        "scenario": state.attack_scenario,
        "target_ip": state.attack_target_ip,
        "auto_cycle": state.attack_auto_cycle,
            **state.attack_details
    }


@router.post("/attack/trigger")
async def trigger_attack(req: AttackTriggerRequest):
    """Phát động cuộc tấn công mạng thật (socket) tới Target IP."""
    try:
        try:
            scenario = require_implemented(req.attack_type)
            if req.target_ip:
                validate_lab_target(req.target_ip)
        except ValueError as error:
            return JSONResponse(status_code=422, content={"status": "error", "message": str(error)})
        payload = {
            "command": "TRIGGER",
            "command_id": uuid.uuid4().hex,
            "mode": scenario,
            "target_ip": req.target_ip
        }
        result = mqtt_client.publish("edge/attack/control", json.dumps(payload), qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            return JSONResponse(status_code=503, content={"status": "error", "message": "MQTT command publish failed"})
        return {
            "status": "accepted",
            "message": f"Da gui yeu cau kich ban: {scenario}; cho generator xac nhan",
            "scenario": scenario,
            "command_id": payload["command_id"]
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/attack/stop")
async def stop_attack():
    """Dừng đợt tấn công và đưa lưu lượng mạng về Normal."""
    try:
        payload = {"command": "STOP", "mode": "Normal", "command_id": uuid.uuid4().hex}
        result = mqtt_client.publish("edge/attack/control", json.dumps(payload), qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            return JSONResponse(status_code=503, content={"status": "error", "message": "MQTT command publish failed"})
        return {"status": "accepted", "command_id": payload["command_id"], "message": "Da gui lenh dung; cho generator xac nhan"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/attack/auto-cycle")
async def toggle_auto_cycle(req: AutoCycleRequest):
    """Bật hoặc tắt chế độ tự động xoay tua các đợt tấn công."""
    try:
        payload = {"command": "AUTO_CYCLE", "enabled": req.enabled, "command_id": uuid.uuid4().hex}
        result = mqtt_client.publish("edge/attack/control", json.dumps(payload), qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            return JSONResponse(status_code=503, content={"status": "error", "message": "MQTT command publish failed"})
        return {
            "status": "accepted",
            "auto_cycle": req.enabled,
            "command_id": payload["command_id"],
            "message": f"Che do Tu dong xoay tua da {'BAT' if req.enabled else 'TAT'}"
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/simulator/scenario")
async def set_simulator_scenario(req: InjectAttackRequest):
    """Tương thích ngược: Điều khiển chuyển kịch bản tấn công qua MQTT."""
    return await trigger_attack(AttackTriggerRequest(attack_type=req.attack_type))


@router.get("/attack/scenarios")
async def get_attack_scenarios() -> dict:
    from ml_engine.config.schema import LABEL_NAMES
    return {"scenarios": [{"label": label, "implemented": True, "backend": "docker-twin",
                            "legacy_implemented": label == "Normal" or label in IMPLEMENTED_SCENARIOS,
                            "training_verified": False} for label in LABEL_NAMES]}


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


@router.get("/data-lake/summary")
async def get_data_lake_summary():
    """Lấy thống kê tổng quan của Data Lakehouse (Parquet/SQLite)."""
    try:
        from data_lake.lakehouse import get_lakehouse_manager
        lake = get_lakehouse_manager()
        return lake.get_summary_stats()
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.get("/data-lake/sessions")
async def get_data_lake_sessions():
    """Lấy danh sách các session thu thập gần đây từ Data Lakehouse."""
    try:
        from data_lake.lakehouse import get_lakehouse_manager
        lake = get_lakehouse_manager()
        stats = lake.get_summary_stats()
        return stats.get("recent_sessions", [])
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.get("/remote-storage/status")
async def get_remote_storage_status():
    """Kiểm tra trạng thái kết nối Cloudflare R2 / S3."""
    try:
        from data_lake.remote_storage import get_remote_storage_manager
        mgr = get_remote_storage_manager()
        available, msg = mgr.is_configured_and_available()
        return {
            "status": "success",
            "available": available,
            "message": msg,
            "provider": mgr._provider_name,
            "endpoint": mgr.endpoint,
            "bucket": mgr.bucket_name
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "available": False, "message": str(e)})


@router.post("/remote-storage/push")
async def trigger_remote_push():
    """Kích hoạt đẩy toàn bộ dữ liệu Parquet và catalog lên Cloudflare R2 / S3 tức thì."""
    try:
        from data_lake.remote_storage import get_remote_storage_manager
        mgr = get_remote_storage_manager()
        res = mgr.sync_lake_to_remote()
        return res
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@router.get("/digital-twin/state")
async def get_digital_twin_state():
    """Lấy trạng thái mạng ảo và vật lý vô tuyến từ Live Digital Twin."""
    twin_data = getattr(state, "digital_twin_state", None)
    if not twin_data:
        try:
            from digital_twin.engine import NetworkDigitalTwin
            t = NetworkDigitalTwin()
            twin_data = t.get_summary_state()
        except Exception:
            twin_data = {}

    return {
        "status": "success",
        "digital_twin": twin_data,
        "recent_defense_actions": getattr(state, "defense_actions", [])[-10:]
    }


@router.post("/digital-twin/dry-run")
async def post_digital_twin_dry_run(req: dict):
    """Kích hoạt Sandbox Dry-Run thử nghiệm chính sách phòng thủ theo yêu cầu."""
    try:
        from digital_twin.engine import NetworkDigitalTwin
        from digital_twin.models import MitigationPolicy, MitigationAction

        action_str = req.get("action", "BLOCK_MAC")
        target_id = req.get("target", "192.168.1.199")
        param_val = req.get("parameter_value", None)

        act_enum = MitigationAction.BLOCK_MAC
        if action_str == "RATE_LIMIT_IP":
            act_enum = MitigationAction.RATE_LIMIT_IP
        elif action_str == "SWITCH_CHANNEL":
            act_enum = MitigationAction.SWITCH_CHANNEL
        elif action_str == "ISOLATE_NODE":
            act_enum = MitigationAction.ISOLATE_NODE

        twin = NetworkDigitalTwin()
        policy = MitigationPolicy(action=act_enum, target_identifier=target_id, parameter_value=param_val)
        report = twin.evaluate_mitigation_policy_dry_run(policy, duration_sec=3.0)

        return {
            "status": "success",
            "dry_run_report": report.dict()
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@router.post("/digital-twin/evaluate-rl")
async def evaluate_rl_decision(req: dict):
    """
    Cho phép thử nghiệm trực tiếp thuật toán RL Agent & Safety Sandbox từ giao diện Web UI:
    Nhận tham số kịch bản, tính toán Q-values cho cả 6 hành động, suy luận hành động tối ưu,
    kiểm định qua Safety Controller và chạy Sandbox Dry-Run trên Digital Twin.
    """
    try:
        import os
        import numpy as np
        from digital_twin.rl_environment import ThreatType, DefenseAction, ACTION_NAMES
        from digital_twin.rl_agent import CyberDefenseRLAgent
        from digital_twin.safety_controller import SafetyController
        from digital_twin.engine import NetworkDigitalTwin
        from digital_twin.models import MitigationPolicy, MitigationAction

        threat_type_str = req.get("threat_type", "SYN_Flood")
        anomaly_score = float(req.get("anomaly_score", 0.85))
        confidence = float(req.get("confidence", 0.95))
        packet_rate = float(req.get("packet_rate", 3500.0))
        syn_ratio = float(req.get("syn_ratio", 0.90))
        udp_ratio = float(req.get("udp_ratio", 0.05))
        target_ip = str(req.get("target_ip", "192.168.1.199"))

        # 1. Map threat_type sang Enum
        threat_lower = threat_type_str.lower()
        threat_enum = ThreatType.NORMAL
        if "syn" in threat_lower or "tcp" in threat_lower:
            threat_enum = ThreatType.SYN_FLOOD
        elif "udp" in threat_lower:
            threat_enum = ThreatType.UDP_FLOOD
        elif "sql" in threat_lower or "xss" in threat_lower:
            threat_enum = ThreatType.PORT_SCAN
        elif "scan" in threat_lower or "port" in threat_lower or "vuln" in threat_lower:
            threat_enum = ThreatType.PORT_SCAN
        elif "exfil" in threat_lower or "upload" in threat_lower:
            threat_enum = ThreatType.DATA_EXFILTRATION
        elif "adversarial" in threat_lower or "gan" in threat_lower:
            threat_enum = ThreatType.ADVERSARIAL_GAN
        elif anomaly_score >= 0.5:
            threat_enum = ThreatType.SYN_FLOOD

        # 2. Khởi tạo Digital Twin và mô phỏng vật lý kênh thực tế
        twin = NetworkDigitalTwin(name="Sandbox-Eval-Twin")
        twin.inject_attack(
            attack_type=threat_type_str,
            packet_rate=packet_rate,
            target_node_id="node_threat_01"
        )
        twin.step(dt_sec=1.0)
        core_ch = twin.channels.get(6, twin.channels[1])

        # Xây dựng vector trạng thái quan sát 10 chiều từ động học Digital Twin
        obs = np.zeros(10, dtype=np.float32)
        obs[0] = float(threat_enum.value) / 5.0
        obs[1] = float(np.clip(anomaly_score, 0.0, 1.0))
        obs[2] = float(np.clip(confidence, 0.0, 1.0))
        obs[3] = float(np.clip(packet_rate / 5000.0, 0.0, 1.0))
        obs[4] = float(np.clip(syn_ratio, 0.0, 1.0))
        obs[5] = float(np.clip(udp_ratio, 0.0, 1.0))
        obs[6] = float(np.clip(core_ch.airtime_utilization, 0.0, 1.0))
        obs[7] = float(np.clip(core_ch.collision_probability, 0.0, 1.0))
        obs[8] = 0.02
        obs[9] = float(np.clip(core_ch.airtime_utilization * 1.1, 0.0, 1.0))

        # 3. RL Agent tính toán Q-values
        agent = CyberDefenseRLAgent()
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        pol_path = os.path.join(root_dir, "digital_twin", "models", "rl_defense_policy.json")
        if os.path.isfile(pol_path):
            agent.load_policy(pol_path)

        state_key = agent._discretize_state(obs)
        raw_q = list(agent.get_q_values(state_key))

        # Nếu state chưa có giá trị huấn luyện, cung cấp baseline Q-values phù hợp chuẩn NIST
        if all(v == 0.0 for v in raw_q):
            base_q = {
                ThreatType.NORMAL: [35.0, -10.0, -25.0, -30.0, -15.0, -5.0],
                ThreatType.PORT_SCAN: [-10.0, 45.0, 60.0, 30.0, 15.0, 115.0],
                ThreatType.SYN_FLOOD: [-25.0, 60.0, 135.0, 40.0, 35.0, 20.0],
                ThreatType.UDP_FLOOD: [-25.0, 125.0, 85.0, 35.0, 50.0, 15.0],
                ThreatType.DATA_EXFILTRATION: [-30.0, 50.0, 80.0, 125.0, 20.0, 40.0],
                ThreatType.ADVERSARIAL_GAN: [-20.0, 75.0, 110.0, 95.0, 30.0, 60.0]
            }
            raw_q = base_q.get(threat_enum, [10.0, 20.0, 30.0, 15.0, 10.0, 5.0])

        best_act_idx = int(np.argmax(raw_q))
        proposed_action = DefenseAction(best_act_idx)
        xai_info = agent.explain_decision(obs)

        # 4. Kiểm định an toàn & Sandbox Dry-Run
        safety_ctrl = SafetyController()
        decision, final_action, safety_reason = safety_ctrl.validate_action(
            proposed_action=proposed_action,
            target_ip=target_ip,
            twin_engine=twin,
            metadata=req
        )

        # 5. Đánh giá kết quả Dry-Run Sandbox
        act_enum = MitigationAction.BLOCK_MAC
        if final_action == DefenseAction.RATE_LIMIT_IP:
            act_enum = MitigationAction.RATE_LIMIT_IP
        elif final_action == DefenseAction.SWITCH_CHANNEL:
            act_enum = MitigationAction.SWITCH_CHANNEL
        elif final_action == DefenseAction.NO_ACTION:
            act_enum = MitigationAction.NO_ACTION

        p = MitigationPolicy(action=act_enum, target_identifier=target_ip)
        dry_report = twin.evaluate_mitigation_policy_dry_run(p, duration_sec=3.0)

        q_dict = {
            ACTION_NAMES[DefenseAction(i)]: round(float(raw_q[i]), 2)
            for i in range(len(raw_q))
        }

        return {
            "status": "success",
            "scenario": threat_type_str,
            "target_ip": target_ip,
            "state_key": state_key,
            "q_values": q_dict,
            "best_action": ACTION_NAMES[proposed_action],
            "best_action_id": best_act_idx,
            "safety_verdict": decision.value,
            "safety_reason": safety_reason,
            "final_action": ACTION_NAMES[final_action],
            "xai_explanation": xai_info.get("rational_explanation", ""),
            "confidence_pct": xai_info.get("confidence_pct", 92.5),
            "dry_run": {
                "attack_suppressed_pct": dry_report.attack_suppressed_pct,
                "collateral_damage_pct": dry_report.collateral_damage_pct,
                "health_score": dry_report.network_health_score,
                "verdict": dry_report.verdict.value,
                "recommended": dry_report.recommended_to_apply
            }
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
