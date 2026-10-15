"""Start shared Docker Desktop when needed; wait for a usable Linux engine."""
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable


def desktop_executable() -> Path | None:
    candidates = [shutil.which("Docker Desktop.exe")]
    cli = shutil.which("docker.exe")
    if cli and len(Path(cli).parents) >= 3:
        candidates.append(str(Path(cli).parents[2] / "Docker Desktop.exe"))
    for variable in ("ProgramFiles", "LOCALAPPDATA"):
        base = os.getenv(variable)
        if base:
            candidates.append(str(Path(base) / "Docker" / "Docker" / "Docker Desktop.exe"))
    local = os.getenv("LOCALAPPDATA")
    if local:
        candidates.append(str(Path(local) / "Programs" / "DockerDesktop" / "Docker Desktop.exe"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def docker_executable() -> str:
    executable = shutil.which("docker.exe" if sys.platform == "win32" else "docker")
    if not executable and sys.platform == "win32":
        desktop = desktop_executable()
        candidate = desktop.parent / "resources" / "bin" / "docker.exe" if desktop else None
        if candidate and candidate.is_file():
            executable = str(candidate)
    if not executable:
        raise RuntimeError("Docker CLI not found; install Docker Desktop with its Linux/WSL2 backend for Twin experiments")
    return executable


def linux_engine_ready(executable: str, timeout_sec: float) -> bool:
    try:
        result = subprocess.run([executable, "info", "--format", "{{.OSType}}"],
                                capture_output=True, text=True, timeout=timeout_sec,
                                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode:
        return False
    kind = result.stdout.strip()
    if kind == "windows":
        raise RuntimeError("Docker is using Windows containers; select Linux containers in Docker Desktop and retry")
    return kind == "linux"


def launch_desktop(executable: Path) -> None:
    # Shared application: let Desktop outlive this launcher and never kill it
    # during AERO cleanup. Owned experiment containers have separate cleanup.
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    subprocess.Popen([str(executable)], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     startupinfo=startup,
                     creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)


def ensure_docker_linux(timeout_sec: float = 120, cancel: threading.Event | None = None,
                        report: Callable[[str], None] | None = None) -> str:
    """Return CLI path only after readiness; bounded, cancellable and import-safe."""
    if timeout_sec <= 0:
        raise ValueError("Docker startup timeout must be positive")
    executable = docker_executable()
    deadline = time.monotonic() + timeout_sec
    stop = cancel or threading.Event()
    def check_cancel() -> None:
        if stop.is_set():
            raise InterruptedError("Docker startup cancelled")
    def emit(message: str) -> None:
        if report:
            report(message)
    check_cancel()
    if linux_engine_ready(executable, min(3, timeout_sec)):
        emit("[Docker] Linux engine đã sẵn sàng.")
        return executable
    check_cancel()
    if sys.platform != "win32":
        raise RuntimeError("Docker Linux engine unavailable; start your Docker service and retry")
    desktop = desktop_executable()
    if not desktop:
        raise RuntimeError("Docker Desktop executable not found in PATH or its standard install location")
    emit("[Docker] Đang mở Docker Desktop ngầm và chờ Linux engine...")
    try:
        launch_desktop(desktop)
    except OSError as error:
        raise RuntimeError("Could not launch Docker Desktop; check installation and executable permissions") from error
    next_report = time.monotonic() + 15
    while time.monotonic() < deadline:
        check_cancel()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if linux_engine_ready(executable, min(3, remaining)):
            emit("[Docker] Linux engine đã sẵn sàng.")
            return executable
        if time.monotonic() >= next_report:
            emit("[Docker] Vẫn đang chờ Linux engine khởi động...")
            next_report = time.monotonic() + 15
        stop.wait(min(1, max(0, deadline - time.monotonic())))
    check_cancel()
    raise RuntimeError(f"Docker Linux engine not ready after {timeout_sec:g}s; check Docker Desktop WSL2/virtualization/setup errors and retry")
