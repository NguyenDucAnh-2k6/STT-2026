"""Refresh ordinary host capture at startup, preserving unrelated .env settings."""
import json
import os
import re
import tempfile
from pathlib import Path

from firmware.host_probe.tshark_engine import find_tshark_path, get_available_interfaces, select_best_interfaces


def prepare_host_capture(root_dir: str) -> list[str]:
    """Discover current physical NICs and atomically persist their stable IDs.

    Called before workers start, only for ordinary live host capture. Discovery
    failure preserves the original .env and refuses a stale capture selection.
    """
    executable = find_tshark_path()
    if not executable:
        raise ValueError("TShark not found; install Wireshark/Npcap for host packet capture")
    selected = select_best_interfaces(get_available_interfaces(executable, strict=True), configured_value="auto")
    if not selected:
        raise ValueError("No active physical capture interface found")
    persist_env_setting(root_dir, "HOST_CAPTURE_INTERFACES", ",".join(selected))
    return selected


def persist_env_setting(root_dir: str, key: str, value: str) -> None:
    """Update one explicit configuration key, without printing unrelated secrets."""
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
        raise ValueError("Invalid environment setting name")
    path = Path(root_dir) / ".env"
    original = path.read_bytes() if path.exists() else b""
    text = original.decode("utf-8-sig")
    newline = "\r\n" if "\r\n" in text else "\n"
    setting = key + "=" + json.dumps(value, ensure_ascii=False) + newline
    pattern = rf"(?m)^[ \t]*(?:export[ \t]+)?{re.escape(key)}[ \t]*=[^\r\n]*(?:\r?\n|$)"
    updated, count = re.subn(pattern, lambda match: setting, text)
    if not count:
        updated = text + (newline if text and not text.endswith("\n") else "") + setting
    payload = (b"\xef\xbb\xbf" if original.startswith(b"\xef\xbb\xbf") else b"") + updated.encode("utf-8")
    if payload != original:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".env.capture.", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
            if (path.read_bytes() if path.exists() else b"") != original:
                raise RuntimeError(".env changed during capture discovery; restart to avoid overwriting concurrent edits")
            os.replace(temporary, path)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
    os.environ[key] = value
