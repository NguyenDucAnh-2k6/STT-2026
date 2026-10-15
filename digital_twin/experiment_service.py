"""Bounded Twin experiments: persist PCAP first, import measured packets in batches."""
import hashlib
import http.client
import json
import logging
import os
import random
import shutil
import signal
import subprocess
import threading
import time
import uuid
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from data_lake.lakehouse import DataLakeManager
from firmware.host_probe.packet_capture import PacketTSharkEngine
from firmware.host_probe.tshark_engine import find_tshark_path
from firmware.simulator.lab_config import http_port, allow_twin_loopback
from firmware.simulator.scenarios import require_twin_scenario
from digital_twin.lab.flows import FlowRecorder, packet_label
from digital_twin.lab.http_target import LabRequestHandler
from digital_twin.lab.capture_config import loopback_interface
from firmware.simulator.http_variants import HttpVariantGenerator, USER_AGENTS
from digital_twin.lab.services import LabServices
from digital_twin.lab.workloads import TwinWorkloads
from digital_twin.lab.profile import capture_filter, scenario_metadata
from digital_twin.lab.raw_packets import require_raw_capability
from digital_twin.lab.controlled_channel import CONTRACTS

LOG = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]


def write_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    temporary = directory / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    temporary.replace(directory / "manifest.json")


class NullStats:
    def add_packet(self, **kwargs: Any) -> None:
        pass


class TwinExperimentService:
    def __init__(self, notify: Callable[[dict[str, Any]], None], base_dir: Path | None = None,
                 live_inference: bool = True) -> None:
        self.notify = notify
        self.live_inference = live_inference
        self.base_dir = base_dir or ROOT / "data_lake"
        self.lock = threading.RLock()
        self.worker: threading.Thread | None = None
        self.cancel = threading.Event()
        self.shutdown = threading.Event()
        self.status: dict[str, Any] = {"phase": "IDLE", "scenario": None}
        self.variant_generator: HttpVariantGenerator | None = None

    def start(self, scenario: str, duration_sec: int = 15) -> dict[str, Any]:
        scenario = require_twin_scenario(scenario)
        if not 1 <= duration_sec <= 60:
            raise ValueError("Experiment duration must be 1..60 seconds")
        if scenario == "Adversarial":
            raise ValueError("Adversarial is not a benchmark label")
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise RuntimeError("Experiment is still running/importing; stop and wait before selecting another class")
            self.cancel = threading.Event()
            self.variant_generator = None
            experiment_id = uuid.uuid4().hex
            base_seed = int(os.getenv("TWIN_VARIATION_SEED", "42"))
            generator_seed = int(hashlib.sha256(f"{base_seed}:{experiment_id}".encode()).hexdigest()[:8], 16)
            self.status = {"phase": "STARTING", "scenario": scenario, "command_id": uuid.uuid4().hex,
                "experiment_id": experiment_id, "duration_sec": duration_sec, "generator_seed": generator_seed,
                "target_ip": "127.0.0.1", "backend": os.getenv("TWIN_LAB_BACKEND", "native"),
                "saved_rows": 0, "labeled_rows": 0, "unknown_rows": 0,
                "schema_version": 2, "timestamp": int(time.time() * 1000)}
            self.status.update(scenario_metadata(scenario))
            result = dict(self.status)
            self.worker = threading.Thread(target=self._run, name="twin-experiment")
            self.worker.start()
            return {"status": "accepted", **result}

    def _emit(self, **updates: Any) -> None:
        with self.lock:
            self.status.update(updates, timestamp=int(time.time() * 1000))
            snapshot = dict(self.status)
        self.notify(snapshot)

    def stop(self) -> dict[str, Any]:
        self.cancel.set()
        return {"status": "accepted", "command_id": self.status.get("command_id")}

    def close(self) -> None:
        self.shutdown.set()
        self.cancel.set()
        if self.worker:
            self.worker.join(timeout=30)
            if self.worker.is_alive():
                LOG.error("Experiment cleanup exceeded shutdown timeout")

    def _normal(self, recorder: FlowRecorder, duration: int, port: int) -> None:
        rng = random.Random(self.status.get("generator_seed", 42))
        end = time.monotonic() + duration
        while not self.cancel.is_set() and time.monotonic() < end:
            size = rng.choice([64, 512, 4096, 16384])
            method = rng.choice(["GET", "POST"])
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            start = int(time.time() * 1000)
            local = None
            try:
                connection.connect()
                local = connection.sock.getsockname()
                recorder.record(local, ("127.0.0.1", port), "tcp", start)
                connection.request(method, f"/bytes/{size}", body=b"N" * size if method == "POST" else None,
                                   headers={"User-Agent": rng.choice(USER_AGENTS)})
                response = connection.getresponse()
                body = response.read(65537)
                response_ok = response.status == 200 and response.getheader("X-AERO-Lab") == "normal-http-v1" and body == b"N" * size
                if not response_ok:
                    raise RuntimeError("Lab response failed Normal verification")
                recorder.record(local, ("127.0.0.1", port), "tcp", start, response_ok=True)
            finally:
                connection.close()
                if local:
                    recorder.record(local, ("127.0.0.1", port), "tcp", start)
            self.cancel.wait(rng.uniform(0.05, 0.2))

    def _attack(self, recorder: FlowRecorder, scenario: str, duration: int, port: int) -> None:
        workload = TwinWorkloads(port, recorder, self.cancel, self.status["generator_seed"])
        self.variant_generator = workload.variants if scenario in ("SQL_injection", "XSS") else None
        end = time.monotonic() + duration
        while not self.cancel.is_set() and time.monotonic() < end:
            workload.burst(scenario)
            if workload.failed and not workload.completed:
                raise RuntimeError("Lab workload has no completed HTTP exchanges; inspect service health")
            self.cancel.wait(.2)
        self.status["workload_completed_exchanges"] = workload.completed
        self.status["workload_failed_exchanges"] = workload.failed

    @staticmethod
    def _stop_capture(process: subprocess.Popen | None) -> None:
        if not process or process.poll() is not None:
            return
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def import_capture(self, path: Path, manifest: dict[str, Any], tshark: str) -> dict[str, int]:
        lake = DataLakeManager(str(self.base_dir))
        lake.start_session("host", "twin-experiment-pcap")
        counts = {"saved_rows": 0, "labeled_rows": 0, "unknown_rows": 0}
        def ingest(packet: dict[str, Any]) -> None:
            label = packet_label(packet, manifest["flows"], manifest["scenario"])
            packet.pop("label_verified", None)  # Legacy probe flag is no longer a label gate.
            packet.update(label, experiment_id=manifest["experiment_id"],
                requested_experiment_class=manifest["scenario"], data_provenance="twin-controlled-lab",
                experiment_manifest_version=manifest.get("experiment_manifest_version", 3),
                capture_environment=manifest.get("backend", "native"),
                **{key: manifest[key] for key in ("scenario_version", "scenario_fidelity", "supervised_training_eligible", "distributed_attack", "training_domain") if key in manifest})
            if manifest["scenario"] in CONTRACTS:
                packet["supervised_training_eligible"] = (packet.get("evidence_contract") == CONTRACTS[manifest["scenario"]]
                    and packet.get("fixture_effect_ok") is True and manifest.get("experiment_manifest_version") == 4)
            lake.record_telemetry(packet, ground_truth=label["ground_truth_scenario"])
            counts["saved_rows"] += 1
            counts["labeled_rows"] += int(label["ground_truth_scenario"] != "Unknown")
            counts["unknown_rows"] += int(label["ground_truth_scenario"] == "Unknown")
        engine = PacketTSharkEngine(NullStats(), ingest, pcap_path=str(path), tshark_path=tshark)
        engine.capture_id = manifest["experiment_id"]
        try:
            engine.start()
            deadline = time.monotonic() + 120
            while not engine.completed.wait(.2):
                if self.shutdown.is_set() or time.monotonic() > deadline:
                    raise TimeoutError("PCAP import interrupted; raw capture retained")
            if engine.error:
                raise RuntimeError(engine.error)
            lake.flush()
            counts.update(parsed_packets=engine.captured_packets, rejected_packets=engine.rejected_packets)
            capinfos = Path(tshark).with_name("capinfos.exe" if os.name == "nt" else "capinfos")
            if capinfos.exists():
                table = subprocess.check_output([str(capinfos), "-T", "-r", "-c", str(path)],
                    text=True, encoding="utf-8", timeout=10)
                counts["pcap_packets"] = int(table.strip().splitlines()[-1].split("\t")[-1].strip('"'))
                if counts["pcap_packets"] != counts["parsed_packets"] + counts["rejected_packets"]:
                    raise RuntimeError("PCAP/import frame counts do not reconcile; capture retained")
        finally:
            engine.stop()
            lake.close_session()
        if not counts["saved_rows"]:
            raise RuntimeError("Capture had no readable packets; verify loopback interface")
        return counts

    def _run(self) -> None:
        server = None
        lab = None
        http_worker = None
        capture = None
        log_file = None
        live_capture = None
        live_bridge = None
        directory = self.base_dir / "experiments" / self.status["experiment_id"]
        manifest = dict(self.status)
        recorder = FlowRecorder()
        try:
            directory.mkdir(parents=True, exist_ok=False)
            write_manifest(directory, manifest)
            self._emit(phase="STARTING")
            if os.getenv("AERO_ISOLATED_TWIN") != "1":
                from digital_twin.lab.docker_runner import collect_in_container
                if self.live_inference:
                    from digital_twin.lab.live_bridge import LiveBridge
                    live_bridge = LiveBridge(directory, manifest["experiment_id"], self._emit)
                    live_bridge.start()
                path, child = collect_in_container(directory, manifest["scenario"], manifest["duration_sec"],
                    manifest["generator_seed"], self.cancel, self._emit)
                child.update(experiment_id=manifest["experiment_id"], command_id=manifest["command_id"],
                             backend="docker-raw", container_experiment_id=child["experiment_id"])
                manifest.update(child)
                if live_bridge:
                    live_bridge.close()
                    manifest.update(live_bridge.health())
                    self._emit(**live_bridge.health(), live_inference_status="STOPPED")
                    live_bridge = None
                tshark = find_tshark_path()
                if not tshark:
                    raise RuntimeError("Host TShark required to import container capture")
                write_manifest(directory, manifest)
                self._emit(phase="IMPORTING", backend="docker-raw", generator_seed=manifest["generator_seed"])
                results = self.import_capture(path, manifest, tshark)
                manifest.update(results, phase="COMPLETED", capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                write_manifest(directory, manifest)
                self._emit(phase="COMPLETED", supervised_training_eligible=manifest.get("supervised_training_eligible", False), **results)
                return
            port = http_port()
            allow_twin_loopback()
            if manifest["scenario"] in ("DDoS_TCP", "DDoS_ICMP", "Fingerprinting"):
                require_raw_capability(manifest["scenario"])
            if manifest["backend"] not in ("native", "docker"):
                raise ValueError("TWIN_LAB_BACKEND must be native or docker")
            if port in (int(os.getenv("PORT", "8000")), int(os.getenv("MQTT_BROKER_PORT", "1883"))):
                raise ValueError("Lab HTTP port must differ from AERO dashboard/broker")
            if manifest["backend"] == "native":
                lab = LabServices(port, {int(os.getenv("PORT", "8000")), int(os.getenv("MQTT_BROKER_PORT", "1883"))},
                                  recorder, dns_proxy=manifest["scenario"] == "MITM",
                                  reverse_channel=manifest["scenario"] in ("Backdoor", "Ransomware"))
                lab.start()
            else:
                if manifest["scenario"] in ("Port_Scanning", "DDoS_UDP", "DDoS_TCP", "DDoS_ICMP", "MITM"):
                    raise ValueError("This scenario requires the native owned port/raw lab; the HTTP-only Docker target cannot provide it")
                check = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    check.request("GET", "/health")
                    response = check.getresponse()
                    if response.getheader("X-AERO-Lab") != "normal-http-v1":
                        raise RuntimeError("Docker lab target not ready; run compose up first")
                    response.read(4096)
                finally:
                    check.close()
            tshark = find_tshark_path()
            if not tshark:
                raise RuntimeError("Wireshark/TShark required for measured experiments")
            dumpcap = shutil.which("dumpcap") or str(Path(tshark).with_name("dumpcap.exe" if os.name == "nt" else "dumpcap"))
            if not Path(dumpcap).is_file():
                raise RuntimeError("dumpcap executable not found")
            configured = loopback_interface(tshark)
            path = directory / "capture.pcapng"
            log_file = (directory / "capture.log").open("w", encoding="utf-8")
            # Every implemented workload targets this service. Broad scan capture
            # previously included unrelated host sockets and overwhelmed the lab data.
            icmp_id = (manifest["generator_seed"] % 65534) + 1
            current_filter = capture_filter(port, manifest["scenario"], icmp_id)
            manifest["capture_filter"] = current_filter
            manifest["labeling_policy"] = "automatic-flow-v2"
            command = [dumpcap, "-i", configured, "-f", current_filter, "-B", "16",
                       "-a", "duration:65", "-a", "filesize:65536", "-w", str(path)]
            capture = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log_file,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            deadline = time.monotonic() + 5
            while not path.exists() or path.stat().st_size == 0:
                if capture.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("dumpcap did not start; inspect experiment capture.log")
                time.sleep(.05)
            self.cancel.wait(.2)
            from digital_twin.lab.live_capture import LiveCapture
            live_capture = LiveCapture(directory, tshark, configured, current_filter)
            live_capture.start()
            self._emit(phase="RUNNING", capture_interface=configured, label_method="automatic_flow")
            if manifest["scenario"] == "Normal":
                self._normal(recorder, manifest["duration_sec"], port)
            else:
                self._attack(recorder, manifest["scenario"], manifest["duration_sec"], port)
            self.cancel.wait(.5)
            live_capture.close()
            manifest.update(live_capture.health())
            if live_capture.engine.error or live_capture.engine.captured_packets == 0:
                raise RuntimeError(live_capture.engine.error or "Live capture had no packets")
            live_capture = None
            if capture.poll() is not None:
                raise RuntimeError("Capture stopped before workload ended; raw PCAP retained")
            self._stop_capture(capture)
            log_file.close()
            log_file = None
            manifest.update(flows=recorder.snapshot(), ended_ms=int(time.time() * 1000),
                lab_http_port=port, seed=manifest["generator_seed"], capture_interface=configured, stopped_by_user=self.cancel.is_set())
            manifest["experiment_manifest_version"] = 4
            if manifest["scenario"] in CONTRACTS:
                supported = [flow for flow in manifest["flows"] if flow.get("evidence_contract") == CONTRACTS[manifest["scenario"]] and flow.get("fixture_effect_ok") is True]
                if not supported:
                    raise RuntimeError("No successful controlled effect; refusing training labels")
                manifest.update(supervised_training_eligible=True, evidence_contract=CONTRACTS[manifest["scenario"]],
                                evidenced_flow_count=len(supported), training_domain="controlled-surrogate-lab")
            if lab:
                manifest["service_evidence"] = lab.evidence()
            manifest.update({key: self.status[key] for key in ("workload_completed_exchanges", "workload_failed_exchanges") if key in self.status})
            if self.variant_generator:
                manifest["request_generator"] = self.variant_generator.metadata()
            write_manifest(directory, manifest)
            self._emit(phase="IMPORTING", flow_count=len(manifest["flows"]))
            results = self.import_capture(path, manifest, tshark)
            manifest.update(results, capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), phase="COMPLETED")
            write_manifest(directory, manifest)
            self._emit(phase="COMPLETED", supervised_training_eligible=manifest.get("supervised_training_eligible", False), **results, flow_count=len(manifest["flows"]))
        except Exception as error:
            manifest.update(flows=recorder.snapshot(), phase="ERROR", error=str(error))
            if self.variant_generator:
                manifest["request_generator"] = self.variant_generator.metadata()
            if directory.exists():
                write_manifest(directory, manifest)
            LOG.exception("Twin experiment failed; capture retained")
            self._emit(phase="ERROR", error=str(error))
        finally:
            if live_bridge:
                try:
                    live_bridge.close()
                except Exception:
                    LOG.exception("Live bridge cleanup failed")
            if live_capture:
                try:
                    live_capture.close()
                except Exception:
                    LOG.exception("Live capture cleanup failed")
            self._stop_capture(capture)
            if log_file:
                log_file.close()
            if server:
                server.shutdown()
                server.server_close()
            if http_worker:
                http_worker.join(timeout=2)
            if lab:
                lab.close()
