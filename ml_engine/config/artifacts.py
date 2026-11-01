"""
AERO ML Engine Artifact Registry and Routing Manager
=====================================================
Provides centralized, deterministic discovery, validation, and resolution of ML
model artifacts across diverse datasets and execution environments:
  - Host DPI (Edge-IIoTset, 56 features) -> profile 'edgeiiot-packet-v1', mode 'decrypted'
  - Promiscuous Sniffer (USTC-TFC2016, 10 features) -> profile 'esp32-l234-packet-v1', mode 'encrypted'
  - Wireless 802.11 WIDS (AWID3, 14 features) -> profile 'awid3-wifi-v1', mode 'wireless'

Eliminates fragile filesystem heuristics, blind mixing of incompatible model files,
and unintentional fallback to synthetic/simulated demo artifacts.
"""

import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from ml_engine.config.edge_profiles import (
    ESP32_PACKET_PROFILE,
    ESP32_PACKET_FEATURES,
    HOST_DPI_PROFILE,
    AWID3_WIFI_PROFILE,
    AWID3_WIFI_FEATURES
)
from ml_engine.config.schema import (
    EDGE_IIOTSET_FEATURES,
    EDGE_IIOTSET_LABELS,
    AWID3_LABELS
)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_MODELS_ROOT = os.path.join(ROOT_DIR, "ml_engine", "models")

# Known synthetic or prepared-vector demo directories that must NOT be selected
# for real live inference unless explicitly requested.
DEMO_DIRECTORY_NAMES = {
    "esp32_rf_if_56_demo",
    "esp32_rf_if_packet_demo",
    "esp32_edgeiiot_rf16",
}


@dataclass
class ArtifactDescriptor:
    """Detailed metadata and verification status of a trained model bundle."""
    models_dir: str
    artifact_id: str
    profile: str
    dataset_name: str
    traffic_mode: str
    classifier_type: str
    anomaly_detector_type: str
    features: List[str]
    features_count: int
    labels: List[str]
    labels_count: int
    preprocessing_version: int
    is_demo: bool = False
    has_tinyml_header: bool = False
    has_packet_model_header: bool = False
    has_tflite: bool = False
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


def normalize_traffic_mode(mode_or_dataset: Optional[str]) -> str:
    """Normalizes dataset names and aliases into canonical traffic_mode."""
    if not mode_or_dataset:
        return "decrypted"
    clean = str(mode_or_dataset).lower().strip()
    if clean in ("wireless", "wifi", "wids", "awid", "awid3", "awid3_dataset", "awid3-wifi-v1"):
        return "wireless"
    if clean in ("encrypted", "ustc", "ustc-tfc2016", "ustc_tfc2016", "esp32", "esp32-packet", "esp32-l234-packet-v1"):
        return "encrypted"
    return "decrypted"


def normalize_profile(profile_or_mode: Optional[str]) -> str:
    """Normalizes profile identifiers."""
    mode = normalize_traffic_mode(profile_or_mode)
    if mode == "wireless":
        return AWID3_WIFI_PROFILE
    if mode == "encrypted":
        return ESP32_PACKET_PROFILE
    return HOST_DPI_PROFILE


def inspect_artifact_dir(models_dir: str) -> Optional[ArtifactDescriptor]:
    """
    Inspects and validates an artifact directory.
    Returns None if essential model files (classifier, anomaly detector, scaler/preprocessor) are missing.
    """
    if not models_dir or not os.path.isdir(models_dir):
        return None

    clf_path = os.path.join(models_dir, "attack_classifier.joblib")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    prep_path = os.path.join(models_dir, "preprocessor.joblib")

    has_joblib = (os.path.exists(clf_path) and os.path.exists(iso_path) and (os.path.exists(scaler_path) or os.path.exists(prep_path)))
    has_header = (os.path.exists(os.path.join(models_dir, "tinyml_model.h")) or os.path.exists(os.path.join(models_dir, "esp32_packet_model.h")))
    has_meta = os.path.exists(os.path.join(models_dir, "model_metadata.json"))

    if not (has_joblib or (has_header and has_meta)):
        return None

    meta_path = os.path.join(models_dir, "model_metadata.json")
    meta: Dict[str, Any] = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

    dir_basename = os.path.basename(os.path.normpath(models_dir))
    parent_basename = os.path.basename(os.path.dirname(os.path.normpath(models_dir)))

    # Determine demo status
    is_demo = (
        dir_basename in DEMO_DIRECTORY_NAMES
        or "_demo" in dir_basename.lower()
        or bool(meta.get("demo_scope"))
        or "simulated" in str(meta.get("demo_scope", "")).lower()
    )

    # Resolve features & profile
    features = meta.get("features", [])
    features_count = meta.get("features_count", len(features))
    if not features:
        if features_count == 10:
            features = list(ESP32_PACKET_FEATURES)
        elif features_count == 14:
            features = list(AWID3_WIFI_FEATURES)
        else:
            features = list(EDGE_IIOTSET_FEATURES)
        features_count = len(features)

    profile = meta.get("profile") or meta.get("feature_semantics")
    if not profile:
        if features_count == 10:
            profile = ESP32_PACKET_PROFILE
        elif features_count == 14:
            profile = AWID3_WIFI_PROFILE
        else:
            profile = HOST_DPI_PROFILE

    # Resolve traffic mode
    traffic_mode = meta.get("traffic_mode")
    if not traffic_mode:
        if parent_basename in ("decrypted", "encrypted", "wireless"):
            traffic_mode = parent_basename
        elif profile == ESP32_PACKET_PROFILE or features_count == 10:
            traffic_mode = "encrypted"
        elif profile == AWID3_WIFI_PROFILE or features_count == 14:
            traffic_mode = "wireless"
        else:
            traffic_mode = "decrypted"
    traffic_mode = normalize_traffic_mode(traffic_mode)

    dataset_name = (
        meta.get("dataset_quality", {}).get("dataset_name")
        or meta.get("data_source")
        or ("AWID3" if traffic_mode == "wireless" else "USTC-TFC2016" if traffic_mode == "encrypted" else "Edge-IIoTset")
    )

    labels = meta.get("labels", [])
    if not labels:
        labels = AWID3_LABELS if traffic_mode == "wireless" else EDGE_IIOTSET_LABELS

    tinyml_h = os.path.exists(os.path.join(models_dir, "tinyml_model.h"))
    packet_h = os.path.exists(os.path.join(models_dir, "esp32_packet_model.h"))
    has_tflite = (
        os.path.exists(os.path.join(models_dir, "classifier_dnn.tflite"))
        or os.path.exists(os.path.join(models_dir, "anomaly_autoencoder.tflite"))
    )

    return ArtifactDescriptor(
        models_dir=models_dir,
        artifact_id=meta.get("artifact_id", dir_basename),
        profile=profile,
        dataset_name=dataset_name,
        traffic_mode=traffic_mode,
        classifier_type=meta.get("classifier_type", "unknown"),
        anomaly_detector_type=meta.get("anomaly_detector_type", "unknown"),
        features=features,
        features_count=features_count,
        labels=labels,
        labels_count=len(labels),
        preprocessing_version=meta.get("preprocessing_version", 2 if profile == HOST_DPI_PROFILE else 1),
        is_demo=is_demo,
        has_tinyml_header=tinyml_h,
        has_packet_model_header=packet_h,
        has_tflite=has_tflite,
        raw_metadata=meta
    )


def list_available_artifacts(base_models_dir: Optional[str] = None) -> List[ArtifactDescriptor]:
    """Enumerates all valid model artifact bundles under base_models_dir."""
    base_dir = base_models_dir or DEFAULT_MODELS_ROOT
    if not os.path.isdir(base_dir):
        return []

    descriptors: List[ArtifactDescriptor] = []

    # 1. Check partitioned subdirectories: decrypted, encrypted, wireless
    for mode in ("decrypted", "encrypted", "wireless"):
        mode_dir = os.path.join(base_dir, mode)
        if os.path.isdir(mode_dir):
            for sub in sorted(os.listdir(mode_dir)):
                sub_path = os.path.join(mode_dir, sub)
                desc = inspect_artifact_dir(sub_path)
                if desc:
                    descriptors.append(desc)

    # 2. Check top-level directories (legacy / flat)
    for entry in sorted(os.listdir(base_dir)):
        top_path = os.path.join(base_dir, entry)
        if entry in ("decrypted", "encrypted", "wireless"):
            continue
        desc = inspect_artifact_dir(top_path)
        if desc:
            descriptors.append(desc)

    return descriptors


def resolve_artifact_dir(
    traffic_mode: Optional[str] = None,
    dataset_name: Optional[str] = None,
    profile: Optional[str] = None,
    classifier: Optional[str] = None,
    anomaly_model: Optional[str] = None,
    custom_dir: Optional[str] = None,
    prefer_demo: bool = False,
    base_models_dir: Optional[str] = None
) -> Tuple[str, ArtifactDescriptor]:
    """
    Deterministic resolution of model artifact directory.

    Rules:
      1. If custom_dir is provided and valid, return it immediately.
      2. Match against normalized traffic_mode / profile.
      3. Filter out demo directories unless prefer_demo is explicitly True.
      4. Never fabricate an incompatible composite model by copying disparate files.
      5. Raise ValueError with actionable guidance if no valid model exists.
    """
    base_dir = base_models_dir or DEFAULT_MODELS_ROOT

    # 1. Custom directory override
    if custom_dir:
        desc = inspect_artifact_dir(custom_dir)
        if desc:
            return custom_dir, desc
        raise ValueError(
            f"Specified --models-dir '{custom_dir}' does not contain valid model artifacts "
            "(attack_classifier.joblib, isolation_forest.joblib, scaler.joblib/preprocessor.joblib)."
        )

    canonical_mode = normalize_traffic_mode(traffic_mode or dataset_name or profile)
    target_profile = normalize_profile(profile or canonical_mode)
    clf_clean = (classifier or "").lower().strip()
    ano_clean = (anomaly_model or "").lower().strip()

    # 2. Check direct partitioned directory if classifier and anomaly detector specified
    if clf_clean and ano_clean:
        direct_candidate = os.path.join(base_dir, canonical_mode, f"{clf_clean}_{ano_clean}")
        desc = inspect_artifact_dir(direct_candidate)
        if desc and (prefer_demo or not desc.is_demo):
            return direct_candidate, desc

        # Check legacy unpartitioned path for decrypted
        if canonical_mode == "decrypted":
            legacy_candidate = os.path.join(base_dir, f"{clf_clean}_{ano_clean}")
            desc = inspect_artifact_dir(legacy_candidate)
            if desc and desc.traffic_mode == "decrypted" and (prefer_demo or not desc.is_demo):
                return legacy_candidate, desc

    # 3. Scan available artifacts and match by mode/profile
    all_artifacts = list_available_artifacts(base_dir)

    # Filter by mode/profile
    matched = [
        d for d in all_artifacts
        if (d.traffic_mode == canonical_mode or d.profile == target_profile)
        and (prefer_demo or not d.is_demo)
    ]

    # If algorithm specified, prioritize matching algorithm
    if clf_clean:
        clf_matched = [d for d in matched if clf_clean in d.classifier_type.lower() or clf_clean in os.path.basename(d.models_dir).lower()]
        if clf_matched:
            matched = clf_matched

    if ano_clean:
        ano_matched = [d for d in matched if ano_clean in d.anomaly_detector_type.lower() or ano_clean in os.path.basename(d.models_dir).lower()]
        if ano_matched:
            matched = ano_matched

    if matched:
        # Sort by modification time of model_metadata.json (most recently trained first)
        matched.sort(
            key=lambda d: os.path.getmtime(os.path.join(d.models_dir, "model_metadata.json"))
            if os.path.exists(os.path.join(d.models_dir, "model_metadata.json")) else 0,
            reverse=True
        )
        selected = matched[0]
        return selected.models_dir, selected

    # If demo is allowed as last resort when no production models exist
    if not prefer_demo:
        demo_candidates = [
            d for d in all_artifacts
            if (d.traffic_mode == canonical_mode or d.profile == target_profile)
            and d.is_demo
        ]
        if demo_candidates:
            # Inform user demo exists but wasn't auto-selected
            demo_paths = [d.models_dir for d in demo_candidates]
            raise ValueError(
                f"No production model artifacts found for mode '{canonical_mode}' (profile '{target_profile}'). "
                f"Found demo artifacts at {demo_paths}, but demo models are blocked for production inference. "
                f"To train a production model, run: python ml_engine/train.py --traffic-mode {canonical_mode} "
                f"--classifier {classifier or 'decision_tree'}"
            )

    raise ValueError(
        f"No model artifacts found for mode '{canonical_mode}' (profile '{target_profile}'). "
        f"Searched base directory: '{base_dir}'. "
        f"Please train a model first using: python ml_engine/train.py --traffic-mode {canonical_mode} "
        f"--classifier {classifier or 'decision_tree'}"
    )
