"""UI experiment context is persisted separately from verified packet labels."""
import math
from typing import Any

from ml_engine.config.schema import LABEL_NAMES


class ScenarioContext:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def update(self, event: dict[str, Any]) -> None:
        timestamp = event.get("timestamp")
        if (not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool)
                or not math.isfinite(timestamp) or timestamp < 1_000_000_000_000):
            raise ValueError("Invalid scenario epoch timestamp")
        if event.get("status") not in ("ATTACKING", "IDLE", "UNSUPPORTED", "ERROR"):
            raise ValueError("Invalid scenario status")
        end = event.get("expires_at_ms", timestamp + 60_000)
        if (not isinstance(end, (int, float)) or not math.isfinite(end)
                or end < timestamp or end > timestamp + 60_000):
            raise ValueError("Invalid scenario expiry")
        self.events.append({"timestamp": timestamp, "expires_at_ms": end,
                            "status": event["status"], "scenario": event.get("scenario"),
                            "experiment_id": event.get("experiment_id"),
                            "target_ip": event.get("target_ip"),
                            "implementation_status": event.get("implementation_status", "legacy_unverified")})
        self.events.sort(key=lambda item: item["timestamp"])
        self.events = self.events[-128:]

    def annotate(self, packet: dict[str, Any]) -> dict[str, Any]:
        context: dict[str, Any] = {"requested_attack_label": "Unknown",
            "experiment_id": None, "scenario_status": "UNKNOWN",
            "scenario_target_ip": None, "scenario_target_match": False,
            "scenario_label_source": "ui_scenario", "scenario_label_verified": False,
            "scenario_label_scope": "time_interval_context",
            "scenario_implementation_status": "unknown"}
        timestamp = packet.get("timestamp")
        if packet.get("timestamp_kind") != "epoch_ms" or not isinstance(timestamp, (int, float)):
            return context
        before = [event for event in self.events if event["timestamp"] <= timestamp]
        if not before:
            return context
        event = before[-1]
        if timestamp > event["expires_at_ms"]:
            return context
        context.update(experiment_id=event["experiment_id"], scenario_status=event["status"],
                       scenario_target_ip=event["target_ip"],
                       scenario_implementation_status=event["implementation_status"])
        if event["status"] == "ATTACKING" and event["scenario"] in LABEL_NAMES:
            context["requested_attack_label"] = event["scenario"]
            context["scenario_target_match"] = bool(event["target_ip"] and event["target_ip"] in
                                                   (packet.get("src_ip"), packet.get("dst_ip")))
        return context
