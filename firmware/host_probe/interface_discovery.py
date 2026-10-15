"""Read-only OS adapter discovery; no connection or credential changes."""
import json
import logging
import re
import subprocess
import sys
from typing import Optional

import psutil

LOG = logging.getLogger(__name__)


def interface_guid(value: str) -> Optional[str]:
    match = re.search(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value)
    return match.group(0).lower() if match else None


def active_adapter_ids() -> Optional[set[str]]:
    """Return active names/GUIDs, or None if OS state cannot be obtained."""
    try:
        stats = psutil.net_if_stats()
        active = {name.casefold() for name, status in stats.items() if status.isup}
    except (OSError, RuntimeError) as error:
        LOG.warning("Cannot query adapter link state: %s", type(error).__name__)
        return None
    if sys.platform == "win32":
        # GUID connects Windows adapter state to Npcap's stable device path.
        command = "Get-NetAdapter | Select-Object Name,InterfaceGuid,Status | ConvertTo-Json -Compress"
        try:
            output = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                text=True, encoding="utf-8", errors="replace", stderr=subprocess.PIPE,
                timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            adapters = json.loads(output) if output.strip() else []
            if isinstance(adapters, dict):
                adapters = [adapters]
            for adapter in adapters:
                if str(adapter.get("Status", "")).casefold() == "up":
                    active.add(str(adapter.get("Name", "")).casefold())
                    guid = interface_guid(str(adapter.get("InterfaceGuid", "")))
                    if guid:
                        active.add(guid)
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
            LOG.warning("Windows adapter GUID query unavailable (%s); using link names", type(error).__name__)
    return active


def physical_capture_interface(entry: dict[str, str]) -> bool:
    text = (entry["name"] + " " + entry["device"]).casefold()
    return entry["device"] != "lo" and not any(token in text for token in
        ("loopback", "vethernet", "virtual", "docker", "vmware", "vbox", "bluetooth", "etw", "sshdump", "ciscodump"))
