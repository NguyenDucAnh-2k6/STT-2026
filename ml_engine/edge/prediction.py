"""Validate/display ESP32 decisions without re-running or relabeling them on host."""
import math
import re
from typing import Any
from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, ESP32_PACKET_PROFILE
from ml_engine.config.schema import LABEL_NAMES, EDGE_IIOTSET_FEATURES


def radio_prediction_input(sample: Any) -> dict[str, Any]:
    """Preserve the chip's measured profile, independently of optional host dissection."""
    edge = sample.edge_result or {}
    measured = edge.get("edge_raw_features", {})
    if not isinstance(measured, dict) or any(name not in ESP32_PACKET_FEATURES for name in measured):
        raise ValueError("Invalid on-device feature names")
    if any(type(value) not in (float, int) or not math.isfinite(value) or value < 0 for value in measured.values()):
        raise ValueError("Invalid on-device raw feature values")
    if edge.get("edge_inference_status") == "ok" and set(measured) != set(ESP32_PACKET_FEATURES):
        raise ValueError("Incomplete on-device feature vector")
    packet = {name: measured.get(name) for name in EDGE_IIOTSET_FEATURES}
    packet.update(edge)
    packet.update(schema_version=3, record_kind="packet", probe_type="esp32",
        feature_semantics=ESP32_PACKET_PROFILE, capture_backend="esp32_native", data_provenance="esp32-radio",
        device_id=sample.device_id, boot_id=sample.boot_id, sequence=sample.sequence,
        capture_id=f"{sample.device_id}:{sample.boot_id}", packet_id=f"{sample.device_id}:{sample.boot_id}:native:{sample.sequence}",
        timestamp=sample.received_at_ms, timestamp_kind="receipt_epoch_ms", source_timestamp=sample.uptime_ms,
        frame_length=sample.original_length, captured_length=len(sample.payload), radio_protected=bool(sample.payload[1] & 0x40),
        channel=sample.channel, rssi=sample.rssi, missing_features=[name for name in EDGE_IIOTSET_FEATURES if name not in measured],
        label_source="unverified", ground_truth_scenario="Unknown", supervised_training_eligible=False)
    return packet


def edge_prediction(telemetry: dict[str, Any]) -> dict[str, Any]:
    result = {"device_id": telemetry.get("device_id", "unknown"), "timestamp": telemetry.get("timestamp"),
        "packet_id": telemetry.get("packet_id"), "capture_id": telemetry.get("capture_id"),
        "inference_source": "esp32", "inference_status": "unavailable", "is_anomaly": None,
        "anomaly_score": None, "confidence": 0.0, "threat_type": "Unknown", "severity": "UNKNOWN",
        "class_probabilities": {}, "top_probabilities": {}, "edge_prediction": "Unknown", "edge_flag": None,
        "edge_model": telemetry.get("edge_model", "unavailable"), "edge_features_count": telemetry.get("edge_features_count", 0),
        "edge_inference_status": "unavailable", "edge_model_version": telemetry.get("edge_model_version"),
        "edge_input_profile": telemetry.get("edge_input_profile"), "host_classifier": "not_used",
        "host_anomaly_detector": "not_used", "host_features_count": 0, "latency_ms": 0, "raw_telemetry": telemetry}
    try:
        if telemetry.get("edge_input_profile") != ESP32_PACKET_PROFILE:
            raise ValueError("No compatible on-device packet inference result")
        if telemetry.get("edge_inference_status") != "ok":
            raise ValueError(str(telemetry.get("edge_error", "On-device inference unavailable")))
        if telemetry.get("radio_protected"):
            raise ValueError("Encrypted radio payload cannot supply the plaintext edge profile")
        if telemetry.get("capture_backend") == "esp32_native" and any(telemetry.get(name) is None for name in ESP32_PACKET_FEATURES):
            raise ValueError("Incomplete on-device feature measurements")
        if telemetry.get("edge_features_count") != len(ESP32_PACKET_FEATURES):
            raise ValueError("Edge feature profile mismatch")
        if not re.fullmatch(r"[a-f0-9]{32}", str(telemetry.get("edge_model_version", ""))):
            raise ValueError("Missing edge artifact identity")
        numbers = {}
        for name in ("edge_anomaly_score", "edge_confidence", "edge_threshold", "edge_latency_ms"):
            value = telemetry.get(name)
            if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
                raise ValueError(f"Invalid {name}")
            if name != "edge_latency_ms" and value > 1:
                raise ValueError(f"Invalid {name}")
            numbers[name] = value
        probabilities = telemetry.get("edge_class_probabilities")
        if not isinstance(probabilities, dict) or not probabilities:
            raise ValueError("Invalid edge probability labels")
        valid_label_sets = [
            set(LABEL_NAMES),
            {"Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Normal", "Nsis-ay", "Shifu", "Virut", "Zeus"},
            {"Cridex", "Geodo", "Htbot", "Miuref", "Neris", "Normal", "Nsis-ay", "Shifu", "Tinba", "Virut", "Zeus"},
        ]
        prob_labels = list(probabilities.keys())
        if not any(set(prob_labels) == s for s in valid_label_sets):
            raise ValueError("Invalid edge probability labels")
        if any(type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities.values()):
            raise ValueError("Invalid edge probabilities")
        if abs(sum(probabilities.values()) - 1) > 1e-4 or abs(max(probabilities.values()) - numbers["edge_confidence"]) > 1e-4:
            raise ValueError("Inconsistent edge probability distribution")
        flag = telemetry.get("edge_flag")
        if type(flag) is not bool:
            raise ValueError("Missing edge decision")
        difference = numbers["edge_anomaly_score"] - numbers["edge_threshold"]
        if abs(difference) > 1e-5 and flag != (difference >= 0):
            raise ValueError("Edge decision conflicts with device threshold")
        classified = max(prob_labels, key=lambda label: probabilities[label])
        expected_threat = ("ZeroDay_Anomaly" if classified == "Normal" else classified) if flag else "Normal"
        if telemetry.get("edge_prediction") != expected_threat:
            raise ValueError("Edge threat conflicts with device decision/probabilities")
        critical_threats = ("DDoS_TCP", "DDoS_UDP", "Port_Scanning", "Zeus", "Cridex", "Virut")
        severity = "NORMAL" if not flag else ("CRITICAL" if numbers["edge_anomaly_score"] > .85 or
            expected_threat in critical_threats else "HIGH" if numbers["edge_anomaly_score"] > .65 else "MEDIUM")
        result.update(inference_status="ok", is_anomaly=flag, anomaly_score=numbers["edge_anomaly_score"],
            confidence=numbers["edge_confidence"], threat_type=expected_threat, severity=severity,
            class_probabilities=probabilities, top_probabilities={name: round(value * 100, 1) for name, value in
                sorted(probabilities.items(), key=lambda item: item[1], reverse=True)[:5]},
            edge_prediction=expected_threat, edge_flag=flag, edge_inference_status="ok",
            edge_threshold=numbers["edge_threshold"], latency_ms=numbers["edge_latency_ms"])
    except ValueError as exc:
        result["error"] = str(exc)
    return result
