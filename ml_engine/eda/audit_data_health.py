"""Read-only schema/eligibility audit; writes aggregate counts, never payloads."""
import argparse
import json
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

from data_lake.quality import select_training_records
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES
from ml_engine.preprocessing.validation import invalid_feature_counts, invalid_record_mask


def audit(root: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {"benchmark": {}, "lake": {}}
    dataset_dir = root / "ml_engine/datasets/Edge-IIoTset dataset/Selected dataset for ML and DL"
    for path in sorted(dataset_dir.glob("*.csv")):
        header = pd.read_csv(path, nrows=0)
        columns = [c for c in EDGE_IIOTSET_FEATURES + ["Attack_type"] if c in header]
        counts: Dict[str, int] = {}
        labels: Dict[str, int] = {}
        rows = 0
        malformed_rows = 0
        for chunk in pd.read_csv(path, usecols=columns, chunksize=50_000, low_memory=False):
            rows += len(chunk)
            malformed_rows += int(invalid_record_mask(chunk).sum())
            for key, value in invalid_feature_counts(chunk).items():
                counts[key] = counts.get(key, 0) + value
            if "Attack_type" in chunk:
                for key, value in chunk.Attack_type.value_counts().items():
                    labels[str(key)] = labels.get(str(key), 0) + int(value)
        result["benchmark"][path.name] = {"rows": rows, "columns": len(header.columns),
            "canonical_features": sum(c in header for c in EDGE_IIOTSET_FEATURES),
            "malformed_numeric_rows": malformed_rows,
            "invalid_numeric_fields": counts, "labels": labels}
    files = sorted((root / "data_lake/raw").rglob("*.parquet"))
    frames = [pd.read_parquet(path) for path in files]
    if frames:
        frame = pd.concat(frames, ignore_index=True)
        _, quality = select_training_records(frame)
        identity = [c for c in ("session_id", "timestamp") if c in frame]
        numeric = frame.select_dtypes(include=["number"])
        result["lake"] = {"files": len(files), "rows": len(frame), "columns": len(frame.columns),
            "canonical_features": sum(c in frame for c in EDGE_IIOTSET_FEATURES),
            "labels": frame.ground_truth_scenario.value_counts(dropna=False).to_dict(),
            "probe_types": frame.probe_type.value_counts(dropna=False).to_dict(),
            "duplicate_session_timestamp": int(frame.duplicated(identity).sum()) if identity else None,
            "numeric_nulls": int(numeric.isna().sum().sum()),
            "numeric_infinities": int(np.isinf(numeric.to_numpy(dtype=float)).sum()),
            "training_eligibility": quality}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Aggregate audit saved to {args.output}")


if __name__ == "__main__":
    main()
