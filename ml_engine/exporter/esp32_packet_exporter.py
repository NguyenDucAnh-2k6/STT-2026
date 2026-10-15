"""Compatibility facade for the firmware's canonical numeric packet profile."""
from pathlib import Path
from typing import Any
from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, ESP32_PACKET_PROFILE
from .esp32_model_exporter import export_model_header


def export_packet_model(classifier: Any, anomaly: Any, scaler: Any,
                        labels: list[str], metadata: dict[str, Any], path: Path) -> None:
    metadata = {**metadata, "profile": ESP32_PACKET_PROFILE}
    report = export_model_header(classifier, anomaly, scaler, ESP32_PACKET_FEATURES, labels, metadata, path)
    import json
    (path.parent / "export_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
