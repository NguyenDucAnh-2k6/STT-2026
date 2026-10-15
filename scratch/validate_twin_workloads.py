"""Explicit bounded native lab validation; writes only temporary experiment data."""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from digital_twin.experiment_service import TwinExperimentService
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import select_training_records


def main() -> None:
    os.environ.update(LAB_HTTP_PORT="23088", TWIN_SCAN_PORT_COUNT="3", TWIN_CAPTURE_INTERFACE="auto-loopback", TWIN_LAB_BACKEND="native")
    results = []
    with tempfile.TemporaryDirectory() as directory:
        service = TwinExperimentService(lambda status: None, Path(directory))
        for scenario in ["Normal", "Port_Scanning", "Vulnerability_scanner", "DDoS_UDP", "DDoS_HTTP", "SQL_injection", "XSS", "Uploading", "Password", "Fingerprinting", "MITM", "Backdoor", "Ransomware"]:
            service.start(scenario, 1)
            service.worker.join(timeout=45)
            if service.worker.is_alive() or service.status["phase"] != "COMPLETED":
                service.close()
                raise RuntimeError(service.status)
            result = {key: service.status.get(key) for key in ["scenario", "phase", "saved_rows", "labeled_rows", "unknown_rows", "supervised_training_eligible"]}
            results.append(result)
            print(json.dumps(result), flush=True)
        service.close()
        frame = DataLakeManager(directory).load_all_training_data()
        accepted, gate = select_training_records(frame)
        report = {"experiments": results, "eligibility": gate,
                  "accepted_labels": accepted.ground_truth_scenario.value_counts().to_dict()}
    (ROOT/"scratch/twin_v3_native_validation_20261012.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
