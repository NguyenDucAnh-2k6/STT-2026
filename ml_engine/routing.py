"""
AERO ML Engine Multi-Stream Routing & Pipeline Orchestration Module
===================================================================
Provides centralized, deterministic routing across the 3 independent data streams:
  1. 'decrypted' : Host DPI (Edge-IIoTset 56 features) -> profile 'edgeiiot-packet-v1'
  2. 'encrypted' : Promiscuous Sniffer L2-L4 (USTC-TFC2016 10 features) -> profile 'esp32-l234-packet-v1'
  3. 'wireless'  : 802.11 Layer 2 WIDS (AWID3 14 features) -> profile 'awid3-wifi-v1'

Each stream maintains independent:
  - Dataset source & preprocessor
  - Feature spaces & labels
  - Partitioned model storage: ml_engine/models/<stream>/<classifier>_<anomaly>/
  - Firmware header exports: esp32_packet_model.h vs tinyml_model.h
"""

from __future__ import annotations

import os
import shutil
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Literal

from ml_engine.config.edge_profiles import (
    ESP32_PACKET_PROFILE,
    ESP32_PACKET_FEATURES,
    HOST_DPI_PROFILE,
    AWID3_WIFI_PROFILE,
    AWID3_WIFI_FEATURES,
)
from ml_engine.config.schema import (
    EDGE_IIOTSET_FEATURES,
    EDGE_IIOTSET_LABELS,
    AWID3_LABELS,
)

LOG = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODELS_ROOT = ROOT_DIR / "ml_engine" / "models"
DEFAULT_FIRMWARE_DIR = ROOT_DIR / "firmware" / "esp32_probe"

STREAM_DECRYPTED = "decrypted"
STREAM_ENCRYPTED = "encrypted"
STREAM_WIRELESS = "wireless"
ALL_STREAMS = (STREAM_DECRYPTED, STREAM_ENCRYPTED, STREAM_WIRELESS)
StreamType = Literal["decrypted", "encrypted", "wireless"]


@dataclass(frozen=True)
class StreamSpec:
    """Specification of an independent data & model stream."""
    stream_id: StreamType
    display_name: str
    profile: str
    features: List[str]
    features_count: int
    labels: List[str]
    labels_count: int
    default_dataset_name: str
    default_probe: str
    primary_header_name: str
    description: str


# Canonical stream definitions
STREAM_REGISTRY: Dict[str, StreamSpec] = {
    STREAM_DECRYPTED: StreamSpec(
        stream_id=STREAM_DECRYPTED,
        display_name="Host DPI (Edge-IIoTset 56 features)",
        profile=HOST_DPI_PROFILE,
        features=list(EDGE_IIOTSET_FEATURES),
        features_count=len(EDGE_IIOTSET_FEATURES),
        labels=list(EDGE_IIOTSET_LABELS),
        labels_count=len(EDGE_IIOTSET_LABELS),
        default_dataset_name="Edge-IIoTset dataset",
        default_probe="host",
        primary_header_name="tinyml_model.h",
        description="Giai ma sau goi tin mang L3-L7 cho may tram / Gateway (56 dac trung DPI)."
    ),
    STREAM_ENCRYPTED: StreamSpec(
        stream_id=STREAM_ENCRYPTED,
        display_name="Promiscuous Sniffer L2-L4 (USTC-TFC2016 10 features)",
        profile=ESP32_PACKET_PROFILE,
        features=list(ESP32_PACKET_FEATURES),
        features_count=len(ESP32_PACKET_FEATURES),
        labels=[
            "Normal", "BitTorrent", "Facetime", "FTP", "Gmail",
            "MySQL", "Outlook", "Skype", "SMB", "Weibo"
        ],
        labels_count=10,
        default_dataset_name="USTC-TFC2016",
        default_probe="esp32",
        primary_header_name="esp32_packet_model.h",
        description="Luu luong ma hoa promisc L2-L4 IP/TCP/ARP/ICMP cho ESP32 (10 dac trung so hoc)."
    ),
    STREAM_WIRELESS: StreamSpec(
        stream_id=STREAM_WIRELESS,
        display_name="Wi-Fi 802.11 WIDS (AWID3 14 features)",
        profile=AWID3_WIFI_PROFILE,
        features=list(AWID3_WIFI_FEATURES),
        features_count=len(AWID3_WIFI_FEATURES),
        labels=list(AWID3_LABELS),
        labels_count=len(AWID3_LABELS),
        default_dataset_name="AWID3_Dataset",
        default_probe="esp32",
        primary_header_name="tinyml_model.h",
        description="Giam sat song Wi-Fi khong day 802.11 Layer 2 / Radio WIDS (14 dac trung MAC Header, tuong thich WPA2)."
    )
}


def normalize_stream(mode_or_alias: Optional[str]) -> StreamType:
    """
    Normalizes any traffic mode or dataset alias into one of the 3 canonical streams:
    'decrypted', 'encrypted', or 'wireless'.
    """
    if not mode_or_alias:
        return STREAM_DECRYPTED
    clean = str(mode_or_alias).lower().strip()
    if clean in ("wireless", "wifi", "wids", "awid", "awid3", "awid3_dataset", "awid3-wifi-v1", "802.11", "radio"):
        return STREAM_WIRELESS
    if clean in ("encrypted", "ustc", "ustc-tfc2016", "ustc_tfc2016", "esp32", "esp32-packet", "esp32-l234-packet-v1", "promiscuous"):
        return STREAM_ENCRYPTED
    if clean in ("decrypted", "host", "dpi", "edge-iiotset", "edgeiiot", "edgeiiot-packet-v1", "iiot"):
        return STREAM_DECRYPTED
    return STREAM_DECRYPTED


def get_stream_spec(mode_or_alias: Optional[str]) -> StreamSpec:
    """Returns the StreamSpec for the requested mode or alias."""
    stream_id = normalize_stream(mode_or_alias)
    return STREAM_REGISTRY[stream_id]


def get_stream_models_dir(stream: str, base_models_dir: Optional[str] = None) -> Path:
    """Returns the partitioned root directory for a given stream: ml_engine/models/<stream>/."""
    stream_id = normalize_stream(stream)
    base = Path(base_models_dir) if base_models_dir else DEFAULT_MODELS_ROOT
    stream_dir = base / stream_id
    stream_dir.mkdir(parents=True, exist_ok=True)
    return stream_dir


def resolve_training_output_dir(
    stream: str,
    classifier: str,
    anomaly_model: str,
    base_models_dir: Optional[str] = None
) -> Path:
    """
    Deterministically computes and creates the training output directory:
    ml_engine/models/<stream>/<classifier>_<anomaly>/
    """
    stream_id = normalize_stream(stream)
    stream_root = get_stream_models_dir(stream_id, base_models_dir)
    clf_clean = str(classifier).lower().strip()
    ano_clean = str(anomaly_model).lower().strip()
    combo_name = f"{clf_clean}_{ano_clean}"
    target_dir = stream_root / combo_name
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def resolve_deployed_model(
    stream: Optional[str] = None,
    classifier: Optional[str] = None,
    anomaly_model: Optional[str] = None,
    custom_dir: Optional[str] = None,
    base_models_dir: Optional[str] = None,
    prefer_demo: bool = False
) -> Tuple[str, Any]:
    """
    Routes and locates the deployed model artifact bundle for a specific stream.
    Reuses the robust discovery from ml_engine.config.artifacts.resolve_artifact_dir.
    """
    from ml_engine.config.artifacts import resolve_artifact_dir
    canonical_stream = normalize_stream(stream)
    base = str(base_models_dir or DEFAULT_MODELS_ROOT)
    return resolve_artifact_dir(
        traffic_mode=canonical_stream,
        classifier=classifier,
        anomaly_model=anomaly_model,
        custom_dir=custom_dir,
        prefer_demo=prefer_demo,
        base_models_dir=base
    )


def sync_firmware_header(
    stream: str,
    models_dir: str,
    firmware_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Synchronizes the appropriate TinyML/packet C header and .tflite files from the model
    directory to the firmware/esp32_probe/ directory.
    """
    canonical_stream = normalize_stream(stream)
    dest_dir = Path(firmware_dir or DEFAULT_FIRMWARE_DIR)
    dest_dir.mkdir(parents=True, exist_ok=True)
    src_dir = Path(models_dir)

    copied_files: List[str] = []

    if canonical_stream == STREAM_ENCRYPTED:
        # Encrypted mode prioritizes esp32_packet_model.h
        candidate = src_dir / "esp32_packet_model.h"
        if candidate.exists() and candidate.stat().st_size > 500:
            target = dest_dir / "esp32_packet_model.h"
            shutil.copy2(candidate, target)
            copied_files.append(f"esp32_packet_model.h ({target.stat().st_size:,} bytes)")
    else:
        # Wireless and Decrypted mode synchronize tinyml_model.h
        candidate = src_dir / "tinyml_model.h"
        if candidate.exists() and candidate.stat().st_size > 500:
            target = dest_dir / "tinyml_model.h"
            shutil.copy2(candidate, target)
            copied_files.append(f"tinyml_model.h ({target.stat().st_size:,} bytes)")

        # If a specialized esp32_packet_model.h was also exported (e.g. for wireless 14-features)
        packet_cand = src_dir / "esp32_packet_model.h"
        if packet_cand.exists() and packet_cand.stat().st_size > 500:
            target = dest_dir / "esp32_packet_model.h"
            shutil.copy2(packet_cand, target)
            copied_files.append(f"esp32_packet_model.h ({target.stat().st_size:,} bytes)")

    # Synchronize optional TFLite flatbuffers
    for tflite_name in ("classifier_dnn.tflite", "anomaly_autoencoder.tflite"):
        tflite_src = src_dir / tflite_name
        if tflite_src.exists():
            tflite_dst = dest_dir / tflite_name
            shutil.copy2(tflite_src, tflite_dst)
            copied_files.append(f"{tflite_name} ({tflite_dst.stat().st_size:,} bytes)")

    if copied_files:
        summary = f"Da dong bo sang ESP32 ({canonical_stream}): " + ", ".join(copied_files)
        return True, summary
    return False, f"Khong tim thay C Header hop le trong {models_dir} de dong bo sang firmware"


def clear_all_artifacts(
    base_models_dir: Optional[str] = None,
    streams: Optional[List[str]] = None
) -> Dict[str, int]:
    """
    Deletes all legacy or existing model artifacts across the partitioned streams,
    re-creating clean directory structures with .gitkeep.
    """
    base = Path(base_models_dir or DEFAULT_MODELS_ROOT)
    target_streams = [normalize_stream(s) for s in streams] if streams else list(ALL_STREAMS)

    report: Dict[str, int] = {}

    # Clear inside partitioned directories
    for s in target_streams:
        stream_path = base / s
        deleted_count = 0
        if stream_path.is_dir():
            for item in stream_path.iterdir():
                if item.name == ".gitkeep":
                    continue
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    deleted_count += 1
                else:
                    item.unlink(missing_ok=True)
                    deleted_count += 1
        stream_path.mkdir(parents=True, exist_ok=True)
        gitkeep = stream_path / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()
        report[s] = deleted_count

    # Clear any unpartitioned top-level legacy directories
    legacy_count = 0
    if base.is_dir():
        for item in base.iterdir():
            if item.name in ALL_STREAMS or item.name == ".gitkeep":
                continue
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                legacy_count += 1
            elif item.is_file():
                item.unlink(missing_ok=True)
                legacy_count += 1
    if legacy_count > 0:
        report["legacy_unpartitioned"] = legacy_count

    return report


if __name__ == "__main__":
    import sys
    print("=" * 70)
    print("   AERO ML ENGINE MULTI-STREAM ROUTING & PARTITIONING MANAGER")
    print("=" * 70)
    for s_id, spec in STREAM_REGISTRY.items():
        print(f"\n[Stream: '{s_id}'] -> {spec.display_name}")
        print(f"  * Profile        : {spec.profile}")
        print(f"  * Feature Count  : {spec.features_count} features")
        print(f"  * Labels Count   : {spec.labels_count} classes")
        print(f"  * Default Probe  : {spec.default_probe}")
        print(f"  * Storage Path   : ml_engine/models/{s_id}/")
        print(f"  * Description    : {spec.description}")

    if "--clean" in sys.argv:
        print("\n[Action] Dang xoa bo toan bo artifacts cu de refresh...")
        res = clear_all_artifacts()
        print(f"  * Ket qua: {res}")
        print("  -> Da don dep sach se toan bo thu muc artifacts!")
