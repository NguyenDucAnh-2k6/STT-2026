"""
AWID3 Wi-Fi Intrusion Dataset Loader and Preprocessor
======================================================
Loads IEEE 802.11 / Radiotap wireless network frames from the AWID3 dataset,
extracting the 14 Layer 2 MAC and physical radio features (AWID3_WIFI_FEATURES).

Canonical Feature Schema (14 features):
  1. frame.len
  2. radiotap.channel.freq
  3. radiotap.dbm_antsignal
  4. wlan.fc.type
  5. wlan.fc.subtype
  6. wlan.fc.type_subtype
  7. wlan.fc.ds
  8. wlan.fc.frag
  9. wlan.fc.retry
  10. wlan.fc.pwrmgt
  11. wlan.fc.moredata
  12. wlan.fc.protected
  13. wlan.duration
  14. wlan.seq

Attack Classes (14 classes):
  - Normal (benign 802.11 operations)
  - 13 Wi-Fi attack types: Deauth, Disass, ReAssoc, Rogue_AP, Krack, Kr00k,
    Evil_Twin, SQL_Injection, SSH, Malware, SSDP, Botnet, Website_spoofing
"""

import os
import glob
import struct
import time
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

from ml_engine.config.edge_profiles import AWID3_WIFI_FEATURES, AWID3_WIFI_PROFILE
from ml_engine.config.schema import AWID3_LABELS
from ml_engine.preprocessing.modules.wifi_wireless import WifiWirelessPreprocessor

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_AWID3_DIR = os.path.join(ROOT_DIR, "ml_engine", "datasets", "AWID3_Dataset")
DEFAULT_CACHE_DIR = os.path.join(DEFAULT_AWID3_DIR, "cache")
DEFAULT_CACHE_FILE = os.path.join(DEFAULT_CACHE_DIR, "awid3_packet_features.parquet")

# Mapping each PCAP filename to its attack scenario metadata (start frame, end frame, label)
# Derived from AWID3 Read_me.txt
AWID3_SCENARIOS = {
    "1. Deauth.pcap": {
        "label": "Deauth",
        "start": 1088022,
        "end": 1626254,
        "match": lambda ts, prot, flen, freq: ts in (10, 12) and prot == 0
    },
    "2. Disass.pcap": {
        "label": "Disass",
        "start": 1404237,
        "end": 2013346,
        "match": lambda ts, prot, flen, freq: ts in (10, 12) and prot == 0
    },
    "3. (Re)Assoc.pcap": {
        "label": "ReAssoc",
        "start": 1145178,
        "end": 1833964,
        "match": lambda ts, prot, flen, freq: ts in (0, 2, 8) and flen <= 301
    },
    "4. Rogue_AP.pcap": {
        "label": "Rogue_AP",
        "start": 1198551,
        "end": 1973111,
        "match": lambda ts, prot, flen, freq: ts == 8 and flen < 264
    },
    "5. Krack.pcap": {
        "label": "Krack",
        "start": 50000,
        "end": 500000,
        "match": lambda ts, prot, flen, freq: freq in (2412, 2417)
    },
    "6. Kr00k.pcap": {
        "label": "Kr00k",
        "start": 1555898,
        "end": 2000000,
        "match": lambda ts, prot, flen, freq: ts == 10 and prot == 0
    },
    "7. Evil_Twin.pcap": {
        "label": "Evil_Twin",
        "start": 1420038,
        "end": 3778728,
        "match": lambda ts, prot, flen, freq: ((ts == 8 and flen < 242) or (ts in (10, 12, 40) and prot == 0))
    },
    "8. SQL_Injection.pcap": {
        "label": "SQL_Injection",
        "start": 1484773,
        "end": 2589043,
        "match": lambda ts, prot, flen, freq: True
    },
    "9. SSH.pcap": {
        "label": "SSH",
        "start": 1356015,
        "end": 2440390,
        "match": lambda ts, prot, flen, freq: True
    },
    "10. Malware.pcap": {
        "label": "Malware",
        "start": 1021326,
        "end": 2310931,
        "match": lambda ts, prot, flen, freq: True
    },
    "11. SSDP.pcap": {
        "label": "SSDP",
        "start": 1198154,
        "end": 8122583,
        "match": lambda ts, prot, flen, freq: True
    },
    "12. Botnet.pcap": {
        "label": "Botnet",
        "start": 1135097,
        "end": 3325480,
        "match": lambda ts, prot, flen, freq: True
    },
    "13. Website_spoofing.pcap": {
        "label": "Website_spoofing",
        "start": 16410,
        "end": 2668583,
        "match": lambda ts, prot, flen, freq: True
    }
}


def parse_radiotap_fields(data: bytes, it_len: int) -> Tuple[float, float]:
    """Extracts channel frequency (MHz) and antenna signal (dBm) from Radiotap header."""
    freq = 2412.0
    signal_dbm = -50.0
    if len(data) < 8:
        return freq, signal_dbm

    present = struct.unpack("<I", data[4:8])[0]
    offset = 8
    # TSFT: bit 0 (8 bytes, align 8)
    if present & (1 << 0):
        offset = (offset + 7) & ~7
        offset += 8
    # Flags: bit 1 (1 byte)
    if present & (1 << 1):
        offset += 1
    # Rate: bit 2 (1 byte)
    if present & (1 << 2):
        offset += 1
    # Channel: bit 3 (4 bytes: freq uint16, flags uint16, align 2)
    if present & (1 << 3):
        offset = (offset + 1) & ~1
        if offset + 4 <= it_len and offset + 4 <= len(data):
            freq_val = struct.unpack("<H", data[offset:offset+2])[0]
            if 2000 <= freq_val <= 6000:
                freq = float(freq_val)
        offset += 4
    # FHSS: bit 4 (2 bytes)
    if present & (1 << 4):
        offset += 2
    # dBm AntSignal: bit 5 (1 byte signed int8)
    if present & (1 << 5):
        if offset < it_len and offset < len(data):
            sig_val = struct.unpack("b", data[offset:offset+1])[0]
            if -100 <= sig_val <= 0:
                signal_dbm = float(sig_val)
        offset += 1

    return freq, signal_dbm


def extract_awid3_pcap_samples(
    pcap_path: str,
    scenario_cfg: Dict[str, Any],
    max_attack: Optional[int] = 1500,
    max_normal: Optional[int] = 500
) -> List[Tuple[List[float], str]]:
    """
    Extracts labeled 802.11 features from an AWID3 PCAP file using fast binary seek.
    If max_attack <= 0 (e.g. -1), extracts all available attack frames in the active window.
    If max_normal <= 0 (e.g. -1), extracts all normal frames in the active window.
    """
    records: List[Tuple[List[float], str]] = []
    if not os.path.exists(pcap_path):
        return records

    attack_label = scenario_cfg["label"]
    start_frame = scenario_cfg.get("start", 1)
    end_frame = scenario_cfg.get("end", 99999999)
    match_fn = scenario_cfg.get("match", lambda ts, prot, flen, freq: True)

    unlimited_attack = (max_attack is not None and max_attack <= 0)
    unlimited_normal = (max_normal is not None and max_normal <= 0)

    try:
        with open(pcap_path, "rb", buffering=16 * 1024 * 1024) as f:
            ghdr = f.read(24)
            if len(ghdr) < 24:
                return records

            frame_num = 0
            attack_count = 0
            normal_count = 0

            # 1. Sample some Normal background traffic from before the attack start
            normal_lead_frames = 20000 if unlimited_normal else (max_normal * 2 if max_normal else 2000)
            normal_target_frame = max(1, start_frame - normal_lead_frames)
            while frame_num < normal_target_frame - 1:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                sec, usec, caplen, origlen = struct.unpack("<IIII", phdr)
                f.seek(caplen, 1)
                frame_num += 1

            # Read normal samples up to attack boundary
            while frame_num < start_frame - 1 and (unlimited_normal or normal_count < max_normal):
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                sec, usec, caplen, origlen = struct.unpack("<IIII", phdr)
                data = f.read(caplen)
                frame_num += 1
                if caplen < 8:
                    continue
                it_len = struct.unpack("<H", data[2:4])[0]
                if caplen < it_len + 4:
                    continue
                freq, signal_dbm = parse_radiotap_fields(data, it_len)
                wlan = data[it_len:]
                fc = struct.unpack("<H", wlan[:2])[0]
                fc_type = (fc >> 2) & 0x3
                fc_subtype = (fc >> 4) & 0xF
                fc_ts = (fc_type << 4) | fc_subtype
                fc_ds = ((fc >> 8) & 1) << 1 | ((fc >> 9) & 1)
                duration = float(struct.unpack("<H", wlan[2:4])[0]) if len(wlan) >= 4 else 0.0
                seq = float(struct.unpack("<H", wlan[22:24])[0] >> 4) if len(wlan) >= 24 else 0.0

                row = [
                    float(origlen),
                    freq,
                    signal_dbm,
                    float(fc_type),
                    float(fc_subtype),
                    float(fc_ts),
                    float(fc_ds),
                    float((fc >> 10) & 1),
                    float((fc >> 11) & 1),
                    float((fc >> 12) & 1),
                    float((fc >> 13) & 1),
                    float((fc >> 14) & 1),
                    duration,
                    seq
                ]
                records.append((row, "Normal"))
                normal_count += 1

            # Fast-forward to start_frame if not already there
            while frame_num < start_frame - 1:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                sec, usec, caplen, origlen = struct.unpack("<IIII", phdr)
                f.seek(caplen, 1)
                frame_num += 1

            # 2. Extract attack samples from the active attack interval
            norm_limit_in_attack = float("inf") if unlimited_normal else ((max_normal * 2) if max_normal else 1000)
            while frame_num <= end_frame and (unlimited_attack or attack_count < max_attack):
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                sec, usec, caplen, origlen = struct.unpack("<IIII", phdr)
                data = f.read(caplen)
                frame_num += 1
                if caplen < 8:
                    continue
                it_len = struct.unpack("<H", data[2:4])[0]
                if caplen < it_len + 4:
                    continue
                freq, signal_dbm = parse_radiotap_fields(data, it_len)
                wlan = data[it_len:]
                fc = struct.unpack("<H", wlan[:2])[0]
                fc_type = (fc >> 2) & 0x3
                fc_subtype = (fc >> 4) & 0xF
                fc_ts = (fc_type << 4) | fc_subtype
                fc_prot = (fc >> 14) & 1
                fc_ds = ((fc >> 8) & 1) << 1 | ((fc >> 9) & 1)
                duration = float(struct.unpack("<H", wlan[2:4])[0]) if len(wlan) >= 4 else 0.0
                seq = float(struct.unpack("<H", wlan[22:24])[0] >> 4) if len(wlan) >= 24 else 0.0

                is_attack = match_fn(fc_ts, fc_prot, origlen, freq)
                label = attack_label if is_attack else "Normal"

                row = [
                    float(origlen),
                    freq,
                    signal_dbm,
                    float(fc_type),
                    float(fc_subtype),
                    float(fc_ts),
                    float(fc_ds),
                    float((fc >> 10) & 1),
                    float((fc >> 11) & 1),
                    float((fc >> 12) & 1),
                    float((fc >> 13) & 1),
                    float(fc_prot),
                    duration,
                    seq
                ]

                if is_attack:
                    records.append((row, label))
                    attack_count += 1
                elif normal_count < norm_limit_in_attack:
                    records.append((row, "Normal"))
                    normal_count += 1

    except Exception as e:
        print(f"[AWID3 Loader] Warning reading {os.path.basename(pcap_path)}: {e}")

    return records


def load_awid3_dataset(
    dataset_dir: Optional[str] = None,
    cache_path: Optional[str] = None,
    sample_ratio: float = 1.0,
    force_rebuild: bool = False,
    samples_per_class: Optional[int] = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Loads the AWID3 dataset into (X, y) with Parquet caching.

    Parameters:
      dataset_dir: Root AWID3 directory containing 'pcaps/' and 'cache/'
      cache_path: Custom path to a parquet cache file
      sample_ratio: Fraction of data to retain after loading (0.0 < ratio <= 1.0)
      force_rebuild: When True, re-extracts from raw PCAP files and updates cache
      samples_per_class: Maximum attack samples per class.
                         -1: Full dataset (extracts all attack frames in window)
                         >0: Cap each attack class at this limit
                         None: Standard default (~1,500 per class -> 26,910 rows)
    """
    dataset_path = dataset_dir or DEFAULT_AWID3_DIR
    cache_dir = os.path.join(dataset_path, "cache") if dataset_dir else DEFAULT_CACHE_DIR

    if cache_path:
        cache_file = cache_path
    elif samples_per_class is None:
        cache_file = os.path.join(cache_dir, "awid3_packet_features.parquet")
    elif samples_per_class <= 0:
        cache_file = os.path.join(cache_dir, "awid3_packet_features_full.parquet")
    else:
        cache_file = os.path.join(cache_dir, f"awid3_packet_features_s{samples_per_class}.parquet")

    if os.path.exists(cache_file) and not force_rebuild:
        print(f"[AWID3 Loader] Nap cache tu Parquet: {cache_file}")
        t0 = time.perf_counter()
        df = pd.read_parquet(cache_file)
        print(f"  -> Da nap {len(df):,} mau trong {time.perf_counter() - t0:.2f}s")
        if sample_ratio < 1.0 and len(df) > 100:
            df = df.groupby("label", group_keys=False).sample(frac=sample_ratio, random_state=42).reset_index(drop=True)
        X = df[AWID3_WIFI_FEATURES]
        y = df["label"]
        return X, y

    pcaps_dir = os.path.join(dataset_path, "pcaps")
    if not os.path.isdir(pcaps_dir):
        raise FileNotFoundError(f"AWID3 pcaps directory not found at: {pcaps_dir}")

    if samples_per_class is None:
        max_att = 1500
        max_norm = 400
        mode_desc = "tieu chuan (1,500 mau/lop)"
    elif samples_per_class <= 0:
        max_att = -1
        max_norm = -1
        mode_desc = "FULL TOAN BO (khong gioi han)"
    else:
        max_att = samples_per_class
        max_norm = max(400, samples_per_class // 3)
        mode_desc = f"{samples_per_class:,} mau/lop"

    print(f"[AWID3 Loader] Dang trich xuat 14 dac trung 802.11 tu cac tep PCAP AWID3 [Che do: {mode_desc}]...")
    all_rows: List[List[float]] = []
    all_labels: List[str] = []

    for pcap_name, cfg in AWID3_SCENARIOS.items():
        pcap_file = os.path.join(pcaps_dir, pcap_name)
        if not os.path.exists(pcap_file):
            continue
        print(f"  * Dang xu ly: {pcap_name} (Kich ban: {cfg['label']})...")
        t_pcap = time.perf_counter()
        samples = extract_awid3_pcap_samples(pcap_file, cfg, max_attack=max_att, max_normal=max_norm)
        for r, l in samples:
            all_rows.append(r)
            all_labels.append(l)
        print(f"    -> Da trich xuat {len(samples):,} mau trong {time.perf_counter() - t_pcap:.2f}s")

    if not all_rows:
        raise ValueError(f"Khong trich xuat duoc mau nao tu {pcaps_dir}")

    df = pd.DataFrame(all_rows, columns=AWID3_WIFI_FEATURES)
    df["label"] = all_labels

    # Clean duplicates & NaN
    df = df.dropna().reset_index(drop=True)
    print(f"[AWID3 Loader] Hoan tat trich xuat tong cong: {len(df):,} mau. Phan bo nhan:")
    print(df["label"].value_counts().to_dict())

    # Cache to parquet
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    df.to_parquet(cache_file, index=False)
    print(f"  -> Da luu Parquet cache tai: {cache_file}")

    if sample_ratio < 1.0 and len(df) > 100:
        df = df.groupby("label", group_keys=False).sample(frac=sample_ratio, random_state=42).reset_index(drop=True)

    X = df[AWID3_WIFI_FEATURES]
    y = df["label"]
    return X, y


class AWID3TrafficPreprocessor:
    """Preprocessor and standardizer for 802.11 Wireless Frame Features."""

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = feature_names or list(AWID3_WIFI_FEATURES)
        self.wifi_module = WifiWirelessPreprocessor(
            include_extended=(len(self.feature_names) > len(AWID3_WIFI_FEATURES))
        )
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.classes_: np.ndarray = np.array([])
        self.profile = AWID3_WIFI_PROFILE
        self.traffic_mode = "wireless"

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "AWID3TrafficPreprocessor":
        self.wifi_module.fit(X)
        cleaned_df = self.wifi_module.transform(X)
        self.scaler.fit(cleaned_df[self.feature_names])
        self.label_encoder.fit(y)
        self.classes_ = self.label_encoder.classes_
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        cleaned_df = self.wifi_module.transform(X)
        return self.scaler.transform(cleaned_df[self.feature_names])

    def fit_transform(self, X: pd.DataFrame, y: pd.Series) -> Tuple[np.ndarray, np.ndarray]:
        self.fit(X, y)
        return self.transform(X), self.label_encoder.transform(y)

    def extract_features(self, payload: Dict[str, Any]) -> pd.DataFrame:
        feat_dict = self.wifi_module.extract_from_telemetry(payload)
        row = [feat_dict.get(feat, self.wifi_module.learned_baselines_.get(feat, 0.0)) for feat in self.feature_names]
        return pd.DataFrame([row], columns=self.feature_names)

    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "AWID3TrafficPreprocessor":
        return joblib.load(filepath)
