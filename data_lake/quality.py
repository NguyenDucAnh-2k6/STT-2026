"""Packet quality and attributable labels; automatic flow labels need no verified flag."""
import pandas as pd
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES, LABEL_NAMES
from ml_engine.preprocessing.validation import invalid_record_mask

TRAINING_REQUIRED_COLUMNS = EDGE_IIOTSET_FEATURES + ["record_kind", "feature_semantics", "schema_version",
    "device_id", "packet_id", "timestamp", "capture_backend", "label_source", "ground_truth_scenario", "missing_features"]
TRAINING_OPTIONAL_COLUMNS = ["supervised_training_eligible", "scenario_fidelity", "scenario_version", "data_provenance", "experiment_manifest_version", "evidence_contract", "fixture_effect_ok", "training_domain"]


def select_training_records(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    required = TRAINING_REQUIRED_COLUMNS
    if frame.empty or any(name not in frame for name in required):
        return frame.iloc[:0].copy(), {"accepted": 0, "rejected": len(frame), "reasons": {"incomplete_schema": len(frame)}}
    mask = (frame.record_kind.eq("packet") & frame.feature_semantics.eq("edgeiiot-packet-v1")
            & pd.to_numeric(frame.schema_version, errors="coerce").ge(2)
            & frame.capture_backend.isin(["tshark", "pcap"])
            & frame.label_source.isin(["manual_review", "controlled_flow"])
            & frame.ground_truth_scenario.isin(LABEL_NAMES)
            & pd.to_numeric(frame.timestamp, errors="coerce").ge(1_000_000_000_000)
            & frame.device_id.notna() & frame.device_id.astype(str).ne("")
            & frame.packet_id.notna() & frame.packet_id.astype(str).ne("")
            & frame.missing_features.map(lambda value: hasattr(value, "__len__") and not isinstance(value, str) and len(value) == 0)
            & frame[EDGE_IIOTSET_FEATURES].notna().all(axis=1)
            & ~invalid_record_mask(frame))
    surrogate = frame.supervised_training_eligible.eq(False).fillna(False) if "supervised_training_eligible" in frame else pd.Series(False, index=frame.index)
    legacy_twin = pd.Series(False, index=frame.index)
    if "data_provenance" in frame:
        version = pd.to_numeric(frame.get("experiment_manifest_version", pd.Series(None, index=frame.index, dtype=object)), errors="coerce")
        legacy_twin = (frame.data_provenance.eq("twin-controlled-lab").fillna(False) & ~version.ge(3)
                       & ~frame.ground_truth_scenario.isin(["Normal", "Unknown"]))
    from digital_twin.lab.controlled_channel import CONTRACTS
    needs_evidence = (frame.get("data_provenance", pd.Series(None, index=frame.index, dtype=object)).eq("twin-controlled-lab").fillna(False)
                      & frame.ground_truth_scenario.isin(CONTRACTS))
    effect = frame.get("fixture_effect_ok", pd.Series(False, index=frame.index)).eq(True).fillna(False)
    contract = frame.get("evidence_contract", pd.Series(None, index=frame.index, dtype=object))
    evidence_ok = effect & contract.eq(frame.ground_truth_scenario.map(CONTRACTS)).fillna(False)
    evidence_ok &= pd.to_numeric(frame.get("experiment_manifest_version", pd.Series(0, index=frame.index)), errors="coerce").ge(4)
    missing_evidence = needs_evidence & ~evidence_ok
    mask &= ~surrogate & ~legacy_twin & ~missing_evidence
    valid = frame.loc[mask]
    accepted = valid.drop_duplicates(["device_id", "packet_id"]).copy()
    return accepted, {"accepted": len(accepted), "rejected": len(frame) - len(accepted),
        "reasons": {"duplicate_identity": len(valid) - len(accepted),
                    "scenario_not_training_eligible": int(surrogate.sum()),
                    "legacy_twin_attack_requires_recollection": int(legacy_twin.sum()),
                    "controlled_effect_evidence_missing": int(missing_evidence.sum()),
                    "malformed_numeric_features": int(invalid_record_mask(frame).sum()),
                    "unlabeled_or_incompatible": int((~mask).sum())}}
