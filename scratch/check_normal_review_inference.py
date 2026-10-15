"""Read-only eligibility audit and inference on one persisted Twin UDP packet."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from data_lake.lakehouse import DataLakeManager
from data_lake.quality import TRAINING_REQUIRED_COLUMNS
from ml_engine.inference_service import AnomalyInferenceEngine


def main() -> None:
    lake = DataLakeManager(str(ROOT / "data_lake"))
    frame = lake.load_labeled_dataset(columns=TRAINING_REQUIRED_COLUMNS)
    summary = {"eligibility": lake.last_training_report,
               "labels": frame.ground_truth_scenario.value_counts().to_dict()}
    rows = frame[frame.ground_truth_scenario.eq("DDoS_UDP")]
    if not rows.empty:
        sample = rows.iloc[-1].to_dict()
        # Arrow list columns arrive as NumPy arrays; the MQTT contract uses JSON lists.
        sample["missing_features"] = list(sample["missing_features"])
        engine = AnomalyInferenceEngine(models_dir=str(ROOT / "ml_engine/models/random_forest_isolation_forest"))
        prediction = engine.predict(sample)
        summary["one_udp_packet_prediction"] = {key: prediction.get(key) for key in
            ["inference_status", "error", "anomaly_score", "is_anomaly", "threat_type", "class_probabilities"]}
    (ROOT / "scratch/operator_normal_inference_audit.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
