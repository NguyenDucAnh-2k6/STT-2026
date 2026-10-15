"""Own one isolated container; return its PCAP/manifest to the host importer."""
import json
import logging
import subprocess
import time
import os
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)
IMAGE = "aero-twin-raw:v6"
ROOT = Path(__file__).resolve().parents[2]


def collect_in_container(directory: Path, scenario: str, duration: int, seed: int,
                         cancel: Any, notify: Any) -> tuple[Path, dict]:
    from launcher.docker_setup import ensure_docker_linux
    docker = ensure_docker_linux(cancel=cancel,
        report=lambda message: notify(phase="STARTING", backend="docker-raw", detail=message))
    container = "aero-twin-" + directory.name
    process = None
    log = (directory/"container.log").open("w", encoding="utf-8")
    created = False
    try:
        exists = subprocess.run([docker, "image", "inspect", IMAGE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        if not exists:
            notify(phase="STARTING", backend="docker-raw", detail="Building isolated Linux raw lab image")
            process = subprocess.Popen([docker, "build", "-t", IMAGE, "-f", str(Path(__file__).with_name("raw_lab.Dockerfile")), str(ROOT)], stdout=log, stderr=log)
            deadline = time.monotonic()+600
            while process.poll() is None:
                if cancel.wait(.2) or time.monotonic() > deadline:
                    raise TimeoutError("Raw lab image build cancelled/timed out; inspect container.log")
            if process.returncode:
                raise RuntimeError("Raw lab image build failed; inspect container.log")
        command = [docker, "run", "--rm", "--name", container, "--network", "none", "--read-only",
                   "--label", f"aero.twin.experiment_id={directory.name}",
                   "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
                   "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,size=64m",
                   "--mount", f"type=bind,source={directory.resolve()},target=/results",
                   "--env", f"LAB_HTTP_PORT={os.getenv('LAB_HTTP_PORT', '8088')}",
                   "--env", f"TWIN_SCAN_PORT_COUNT={os.getenv('TWIN_SCAN_PORT_COUNT', '12')}",
                   IMAGE, scenario, str(duration), str(seed)]
        process = subprocess.Popen(command, stdout=log, stderr=log)
        created = True
        deadline = time.monotonic()+240
        emitted_running = False
        stop_requested = False
        while process.poll() is None:
            time.sleep(.2)
            if cancel.is_set() and not stop_requested:
                (directory/"stop.request").write_text("stop-and-save", encoding="utf-8")
                stop_requested = True
                deadline = min(deadline, time.monotonic()+30)
            if time.monotonic() > deadline:
                raise TimeoutError("Raw lab container stop/import timed out; capture retained")
            child_manifests = list((directory/"experiments").glob("*/manifest.json"))
            if child_manifests and not emitted_running:
                # Child manifest STARTING appears before dumpcap. Its actual
                # RUNNING phase is streamed as JSON in container.log.
                log.flush()
                if '"phase": "RUNNING"' in (directory/"container.log").read_text(encoding="utf-8", errors="replace"):
                    notify(phase="RUNNING", backend="docker-raw", capture_interface="container:lo")
                    emitted_running = True
        if process.returncode:
            raise RuntimeError("Raw lab container failed; inspect container.log and child manifest")
        manifests = list((directory/"experiments").glob("*/manifest.json"))
        if len(manifests) != 1:
            raise RuntimeError("Missing/ambiguous raw container manifest")
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        if manifest.get("phase") != "COMPLETED":
            raise RuntimeError(manifest.get("error", "Raw container incomplete"))
        return manifests[0].with_name("capture.pcapng"), manifest
    finally:
        if created and process and process.poll() is None:
            try:
                stopped = subprocess.run([docker, "stop", "--time", "3", container], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
                if stopped.returncode:
                    raise RuntimeError("docker stop failed")
            except (OSError, subprocess.SubprocessError, RuntimeError):
                LOG.error("Owned Twin container cleanup pending: %s", container)
                (directory/"cleanup_pending.json").write_text(json.dumps({"container": container, "experiment_id": directory.name}), encoding="utf-8")
        try:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            log.close()
