"""Short isolated capture/import validation; does not modify the user's data lake."""
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
    with tempfile.TemporaryDirectory(dir=ROOT / "scratch", prefix="surrogate-validation-") as directory:
        service = TwinExperimentService(lambda status: None, Path(directory))
        try:
            for scenario in ("Fingerprinting", "MITM", "Backdoor", "Ransomware"):
                service.start(scenario, 1)
                service.worker.join(timeout=180)
                if service.worker.is_alive() or service.status["phase"] != "COMPLETED":
                    for log in Path(directory).glob("experiments/*/container.log"):
                        print(log.read_text(encoding="utf-8", errors="replace")[-4000:])
                    raise RuntimeError(service.status)
                results.append({key: service.status.get(key) for key in ("scenario", "phase", "saved_rows", "labeled_rows", "unknown_rows", "supervised_training_eligible")})
                print(json.dumps(results[-1]), flush=True)
            frame = DataLakeManager(directory).load_all_training_data()
            accepted, report = select_training_records(frame)
            output = {"experiments": results, "training_quality": report,
                      "accepted_labels": accepted.ground_truth_scenario.value_counts().to_dict(),
                      "evidence": frame.evidence_contract.value_counts().to_dict()}
            assert set(output["accepted_labels"]) == {"Fingerprinting", "MITM", "Backdoor", "Ransomware"}, output
            assert report["rejected"] == 0, report
            (ROOT / "scratch/twin_v4_surrogate_validation_20261012.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
            print(json.dumps(output), flush=True)
        finally:
            service.close()


if __name__ == "__main__":
    main()
