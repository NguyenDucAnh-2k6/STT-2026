"""All modes, real Docker/TShark/MQTT/model artifacts; disposable isolated broker/lake."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from broker.manager import find_mosquitto_executable, check_mqtt_ready
from digital_twin.experiment_service import TwinExperimentService
from ml_engine.config.schema import LABEL_NAMES
import paho.mqtt.client as mqtt


def main() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT/"scratch", prefix="all-live-validation-") as directory:
        root = Path(directory)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root/"mosquitto.conf"
        config.write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\n")
        executable = find_mosquitto_executable()
        if not executable:
            raise RuntimeError("Native Mosquitto required for isolated validation")
        log = (root/"inference.log").open("w", encoding="utf-8")
        broker = subprocess.Popen([executable, "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        inference = None
        observer = None
        service = None
        results = []
        windows = []
        try:
            deadline = time.monotonic()+10
            while not check_mqtt_ready(port):
                if time.monotonic() > deadline:
                    raise TimeoutError("Validation broker not ready")
                time.sleep(.1)
            env = dict(os.environ, MQTT_HOST="127.0.0.1", MQTT_BROKER_HOST="127.0.0.1", MQTT_PORT=str(port), MQTT_BROKER_PORT=str(port),
                       MODELS_DIR=str(ROOT/"ml_engine/models/random_forest_isolation_forest"), PYTHONUNBUFFERED="1", PYTHONUTF8="1")
            os.environ.update({key: env[key] for key in ("MQTT_HOST", "MQTT_PORT", "MQTT_BROKER_HOST", "MQTT_BROKER_PORT")})
            inference = subprocess.Popen([sys.executable, "ml_engine/inference_service.py"], env=env, cwd=ROOT, stdout=log, stderr=log)
            deadline = time.monotonic()+60
            while "Da subscribe topic" not in (root/"inference.log").read_text(encoding="utf-8", errors="replace"):
                if inference.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Validation model service unavailable")
                time.sleep(.2)
            observer = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="twin-validation-windows")
            observer.on_connect = lambda c,u,f,r,p: c.subscribe("edge/telemetry/window")
            observer.on_message = lambda c,u,m: windows.append(json.loads(m.payload))
            observer.connect("127.0.0.1", port)
            observer.loop_start()
            events = []
            service = TwinExperimentService(events.append, root/"lake")
            for scenario in LABEL_NAMES:
                events.clear()
                service.start(scenario, 1)
                service.worker.join(120)
                if service.worker.is_alive() or service.status["phase"] != "COMPLETED":
                    for error_log in (root/"lake/experiments").glob("*/container.log"):
                        tail = error_log.read_text(encoding="utf-8", errors="replace")[-2500:]
                        if "Traceback" in tail:
                            print(tail)
                    raise RuntimeError(service.status)
                status = dict(service.status)
                capture_windows = [w for w in windows if w.get("capture_id") == status["experiment_id"]]
                result = {key: status.get(key) for key in ("scenario", "saved_rows", "labeled_rows", "unknown_rows", "live_received", "live_published", "live_predictions", "live_inference_failed", "live_preview_dropped")}
                result["prediction_while_running"] = any(e.get("phase") == "RUNNING" and (e.get("live_predictions") or 0) > 0 for e in events)
                result["nonzero_window"] = any(w.get("packet_rate", 0) > 0 for w in capture_windows)
                result["idle_window"] = bool(capture_windows and capture_windows[-1]["packet_rate"] == 0)
                assert result["live_predictions"] > 0 and result["prediction_while_running"] and result["nonzero_window"] and result["idle_window"], result
                assert result["saved_rows"] > 0 and result["live_inference_failed"] == 0, result
                results.append(result)
                print(json.dumps(result), flush=True)
            (ROOT/"scratch/twin_all_live_validation_20261012.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        finally:
            if service:
                service.close()
            if observer:
                observer.disconnect()
                observer.loop_stop()
            for process in (inference, broker):
                if process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    main()
