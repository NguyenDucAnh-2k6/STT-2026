"""Explicit lab targets; discovery never selects a home gateway or public host."""
import ipaddress
import os


def validate_lab_target(value: str) -> str:
    cleaned = (value or "").strip()
    address = ipaddress.ip_address(cleaned)
    allowed = [ipaddress.ip_network(item.strip(), strict=False) for item in
               os.getenv("LAB_ALLOWED_TARGETS", "127.0.0.1/32").split(",") if item.strip()]
    if not any(address in network for network in allowed):
        raise ValueError("Target is outside LAB_ALLOWED_TARGETS")
    return str(address)


def configured_target() -> str:
    target = os.getenv("LAB_TARGET_IP") or os.getenv("ATTACK_TARGET_IP")
    if not target:
        raise ValueError("Configure LAB_TARGET_IP and LAB_ALLOWED_TARGETS; automatic attack target discovery is disabled")
    return validate_lab_target(target)


def http_port() -> int:
    port = int(os.getenv("LAB_HTTP_PORT", "8088"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid LAB_HTTP_PORT")
    return port


def allow_twin_loopback() -> str:
    """An owned Twin target is always localhost; never widen access to a LAN."""
    value = os.getenv("LAB_ALLOWED_TARGETS", "127.0.0.1/32")
    networks = [ipaddress.ip_network(item.strip(), strict=False) for item in value.split(",") if item.strip()]
    if not any(ipaddress.ip_address("127.0.0.1") in network for network in networks):
        value = value.rstrip(", ") + ("," if value.strip() else "") + "127.0.0.1/32"
    os.environ["LAB_ALLOWED_TARGETS"] = value
    return value
