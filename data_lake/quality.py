"""Packet quality and attributable labels; automatic flow labels need no verified flag."""
from typing import Tuple, Dict, Any, Optional
import pandas as pd
from ml_engine.config.schema import EDGE_IIOTSET_FEATURES, LABEL_NAMES, AWID3_LABELS
from ml_engine.config.edge_profiles import (
    ESP32_PACKET_FEATURES,
    ESP32_PACKET_PROFILE,
    HOST_DPI_PROFILE,
    AWID3_WIFI_FEATURES,
    AWID3_WIFI_PROFILE
)
from ml_engine.preprocessing.validation import invalid_record_mask
from ml_engine.preprocessing.ustc_tfc2016_preprocessor import USTC_TFC2016_LABELS

COMMON_METADATA_COLUMNS = [
    "record_kind", "feature_semantics", "schema_version",
    "device_id", "packet_id", "timestamp", "capture_backend",
    "label_source", "ground_truth_scenario", "missing_features"
]

TRAINING_REQUIRED_COLUMNS = EDGE_IIOTSET_FEATURES + COMMON_METADATA_COLUMNS
TRAINING_REQUIRED_COLUMNS_DECRYPTED = TRAINING_REQUIRED_COLUMNS
TRAINING_REQUIRED_COLUMNS_ENCRYPTED = ESP32_PACKET_FEATURES + COMMON_METADATA_COLUMNS
TRAINING_REQUIRED_COLUMNS_WIRELESS = AWID3_WIFI_FEATURES + COMMON_METADATA_COLUMNS

TRAINING_OPTIONAL_COLUMNS = [
    "supervised_training_eligible", "scenario_fidelity", "scenario_version",
    "data_provenance", "experiment_manifest_version", "evidence_contract",
    "fixture_effect_ok", "training_domain", "traffic_mode"
]


def select_training_records(frame: pd.DataFrame, traffic_mode: str = "decrypted") -> Tuple[pd.DataFrame, dict]:
    if traffic_mode == "encrypted":
        required_features = ESP32_PACKET_FEATURES
        expected_semantics = ESP32_PACKET_PROFILE
        valid_labels = set(USTC_TFC2016_LABELS) | {"Normal", "Unknown"}
        required_cols = TRAINING_REQUIRED_COLUMNS_ENCRYPTED
    elif traffic_mode == "wireless":
        required_features = AWID3_WIFI_FEATURES
        expected_semantics = AWID3_WIFI_PROFILE
        valid_labels = set(AWID3_LABELS) | {"Normal", "Unknown"}
        required_cols = TRAINING_REQUIRED_COLUMNS_WIRELESS
    else:  # decrypted (default)
        required_features = EDGE_IIOTSET_FEATURES
        expected_semantics = HOST_DPI_PROFILE
        valid_labels = set(LABEL_NAMES)
        required_cols = TRAINING_REQUIRED_COLUMNS_DECRYPTED

    if frame.empty or any(name not in frame for name in required_cols):
        return frame.iloc[:0].copy(), {"accepted": 0, "rejected": len(frame), "reasons": {"incomplete_schema": len(frame)}}

    mask = (frame.record_kind.eq("packet") & frame.feature_semantics.eq(expected_semantics)
            & pd.to_numeric(frame.schema_version, errors="coerce").ge(2)
            & frame.capture_backend.isin(["tshark", "pcap", "esp32_pcap", "esp32_sniffer", "wifi_sniffer"])
            & frame.label_source.isin(["manual_review", "controlled_flow"])
            & frame.ground_truth_scenario.isin(valid_labels)
            & pd.to_numeric(frame.timestamp, errors="coerce").ge(1_000_000_000_000)
            & frame.device_id.notna() & frame.device_id.astype(str).ne("")
            & frame.packet_id.notna() & frame.packet_id.astype(str).ne("")
            & frame.missing_features.map(lambda value: hasattr(value, "__len__") and not isinstance(value, str) and len(value) == 0)
            & frame[required_features].notna().all(axis=1))

    if traffic_mode == "decrypted":
        mask &= ~invalid_record_mask(frame)

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
                    "malformed_numeric_features": int(invalid_record_mask(frame).sum()) if traffic_mode == "decrypted" else 0,
                    "unlabeled_or_incompatible": int((~mask).sum())}}
