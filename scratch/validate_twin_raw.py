"""Bounded container SYN/ICMP validation, only temporary local experiment files."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from digital_twin.experiment_service import TwinExperimentService
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records


def main() -> None:
    results = []
    with tempfile.TemporaryDirectory(dir=ROOT/"scratch", prefix="raw_validation_") as directory:
        service = TwinExperimentService(lambda status: None, Path(directory))
        try:
            for scenario in ["DDoS_TCP", "DDoS_ICMP"]:
                service.start(scenario, 1)
                service.worker.join(timeout=180)
                if service.worker.is_alive() or service.status["phase"] != "COMPLETED":
                    for log in Path(directory).glob("experiments/*/container.log"):
                        print(log.read_text(encoding="utf-8", errors="replace")[-6000:])
                    raise RuntimeError(service.status)
                results.append({key: service.status.get(key) for key in ["scenario", "phase", "backend", "saved_rows", "labeled_rows", "unknown_rows"]})
                print(json.dumps(results[-1]), flush=True)
            frame = DataLakeManager(directory).load_all_training_data()
            accepted, report = select_training_records(frame)
            flags = frame[frame.ground_truth_scenario.eq("DDoS_TCP")]["tcp.flags"].value_counts().to_dict()
            raw_counts = {"tcp_flags": flags, "icmp_types": frame[frame.ground_truth_scenario.eq("DDoS_ICMP")].icmp_type.value_counts().to_dict()}
            output = {"experiments": results, "eligibility": report, "measurements": raw_counts,
                      "labels": accepted.ground_truth_scenario.value_counts().to_dict()}
            (ROOT/"scratch/twin_v3_raw_validation_20261012.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
            print(json.dumps(output))
        finally:
            service.close()


if __name__ == "__main__":
    main()
