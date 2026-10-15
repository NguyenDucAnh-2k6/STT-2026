"""Resolve loopback by stable device name; NIC indices change after installation."""
import os
from firmware.host_probe.tshark_engine import get_available_interfaces


def loopback_interface(tshark: str, configured: str | None = None) -> str:
    configured = (configured if configured is not None else os.getenv("TWIN_CAPTURE_INTERFACE", "auto-loopback")).strip() or "auto-loopback"
    available = get_available_interfaces(tshark, strict=True)
    if not available:
        raise ValueError("TShark returned no capture interfaces; check tshark -D and the Npcap installation")
    selected = next((entry for entry in available if (
        configured == "auto-loopback" and ("loopback" in (entry["name"] + entry["device"]).lower() or entry["device"] == "lo")
        or configured in (entry["index"], entry["device"]))), None)
    if not selected or ("loopback" not in (selected["name"] + selected["device"]).lower() and selected["device"] != "lo"):
        raise ValueError(f"Twin local lab cannot select loopback for TWIN_CAPTURE_INTERFACE={configured!r}; "
                         "set auto-loopback or a loopback device from tshark -D (Npcap required on Windows)")
    return selected["device"]
