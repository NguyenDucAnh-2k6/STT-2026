"""Raw loopback experiments inside an isolated Linux container."""
import argparse
import json
import os
import time
from pathlib import Path

from digital_twin.experiment_service import TwinExperimentService
from ml_engine.config.schema import LABEL_NAMES


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=LABEL_NAMES)
    parser.add_argument("duration", type=int)
    parser.add_argument("seed", type=int)
    args = parser.parse_args()
    os.environ.update(TWIN_LAB_BACKEND="native", TWIN_CAPTURE_INTERFACE="auto-loopback", TWIN_VARIATION_SEED=str(args.seed), AERO_ISOLATED_TWIN="1")
    service = TwinExperimentService(lambda status: print(json.dumps(status), flush=True), Path("/results"), live_inference=False)
    try:
        service.start(args.scenario, args.duration)
        deadline = time.monotonic() + 180
        while service.worker.is_alive() and time.monotonic() < deadline:
            service.worker.join(timeout=.2)
            if Path("/results/stop.request").exists():
                service.stop()  # Finish dumpcap/import cooperatively before exit.
        if service.worker.is_alive() or service.status["phase"] != "COMPLETED":
            raise RuntimeError(service.status.get("error", "Container experiment did not finish"))
    finally:
        service.close()


if __name__ == "__main__":
    main()
