"""
USTC-TFC2016 Encrypted Network Traffic Loader and Preprocessor
==============================================================
Loads raw packet-level PCAP files from the USTC-TFC2016 dataset, extracting
the exact 10 Layer 2-4 header features measured by the ESP32 Promiscuous Sniffer
(ESP32_PACKET_FEATURES).

Canonical Feature Schema (10 features):
  1. arp.opcode
  2. arp.hw.size
  3. icmp.checksum
  4. tcp.ack_raw
  5. tcp.checksum
  6. tcp.dstport
  7. tcp.flags
  8. tcp.flags.ack
  9. tcp.len
  10. tcp.srcport

Classes:
  - Normal (Benign applications: BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, SMB, Weibo, WorldOfWarcraft)
  - 10 Malware families: Cridex, Geodo, Htbot, Miuref, Neris, Nsis-ay, Shifu, Tinba, Virut, Zeus
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
from sklearn.model_selection import train_test_split

from ml_engine.config.edge_profiles import ESP32_PACKET_FEATURES, ESP32_PACKET_PROFILE

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_USTC_DIR = os.path.join(ROOT_DIR, "ml_engine", "datasets", "USTC-TFC2016")
DEFAULT_CACHE_DIR = os.path.join(DEFAULT_USTC_DIR, "cache")
DEFAULT_CACHE_FILE = os.path.join(DEFAULT_CACHE_DIR, "ustc_tfc2016_packet_features.parquet")

USTC_TFC2016_LABELS = [
    "Normal",
    "Cridex",
    "Geodo",
    "Htbot",
    "Miuref",
    "Neris",
    "Nsis-ay",
    "Shifu",
    "Tinba",
    "Virut",
    "Zeus"
]


def extract_features_from_pcap(pcap_path: str, max_packets: int = 5000) -> List[List[float]]:
    """
    Extracts the 10 canonical L2-4 header features from a raw .pcap file in pure Python.
    Strictly replicates the extraction logic of firmware/esp32_probe/packet_features.cpp.
    """
    records = []
    if not os.path.exists(pcap_path):
        return records

    try:
        with open(pcap_path, "rb") as f:
            ghdr = f.read(24)
            if len(ghdr) < 24:
                return records
            magic = struct.unpack("<I", ghdr[:4])[0]
            endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"

            while len(records) < max_packets:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                sec, usec, caplen, origlen = struct.unpack(endian + "IIII", phdr)
                data = f.read(caplen)
                if caplen < 14:
                    continue

                # Ethernet header
                ethertype = struct.unpack(">H", data[12:14])[0]
                if ethertype == 0x8100:  # 802.1Q VLAN Tagged
                    if len(data) < 18:
                        continue
                    ethertype = struct.unpack(">H", data[16:18])[0]
                    offset = 18
                else:
                    offset = 14

                # Row maps 1-to-1 to ESP32_PACKET_FEATURES:
                # 0: arp.opcode, 1: arp.hw.size, 2: icmp.checksum, 3: tcp.ack_raw,
                # 4: tcp.checksum, 5: tcp.dstport, 6: tcp.flags, 7: tcp.flags.ack,
                # 8: tcp.len, 9: tcp.srcport
                row = [0.0] * 10

                if ethertype == 0x0806:  # ARP
                    if len(data) >= offset + 8:
                        hw_size = float(data[offset + 4])
                        opcode = float(struct.unpack(">H", data[offset + 6:offset + 8])[0])
                        row[0] = opcode
                        row[1] = hw_size
                        records.append(row)
                elif ethertype == 0x0800:  # IPv4
                    if len(data) >= offset + 20:
                        ip_ver_ihl = data[offset]
                        ihl = (ip_ver_ihl & 0x0f) * 4
                        if ihl < 20 or len(data) < offset + ihl:
                            continue
                        total_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                        proto = data[offset + 9]
                        trans_offset = offset + ihl

                        if proto == 6:  # TCP
                            if len(data) >= trans_offset + 20:
                                sport = float(struct.unpack(">H", data[trans_offset:trans_offset + 2])[0])
                                dport = float(struct.unpack(">H", data[trans_offset + 2:trans_offset + 4])[0])
                                ack_raw = float(struct.unpack(">I", data[trans_offset + 8:trans_offset + 12])[0])
                                tcp_hl = ((data[trans_offset + 12] >> 4) & 0x0f) * 4
                                flags = float(((data[trans_offset + 12] & 1) << 8) | data[trans_offset + 13])
                                flags_ack = 1.0 if (int(flags) & 0x10) else 0.0
                                checksum = float(struct.unpack(">H", data[trans_offset + 16:trans_offset + 18])[0])
                                tcp_len = float(max(0, total_len - ihl - tcp_hl))

                                row[3] = ack_raw
                                row[4] = checksum
                                row[5] = dport
                                row[6] = flags
                                row[7] = flags_ack
                                row[8] = tcp_len
                                row[9] = sport
                                records.append(row)
                        elif proto == 1:  # ICMP
                            if len(data) >= trans_offset + 4:
                                icmp_type = data[trans_offset]
                                if icmp_type in (0, 8, 13, 14):
                                    icmp_csum = float(struct.unpack(">H", data[trans_offset + 2:trans_offset + 4])[0])
                                    row[2] = icmp_csum
                                    records.append(row)
    except Exception as e:
        print(f"[USTC-TFC2016 Loader] Canh bao khi doc pcap '{pcap_path}': {e}")

    return records


def parse_ustc_label_from_path(pcap_path: str, base_dir: str) -> str:
    """Xác định nhãn danh mục (Normal hoặc tên malware family) dựa trên đường dẫn tập tin."""
    rel = os.path.relpath(pcap_path, base_dir)
    parts = rel.split(os.sep)
    category = parts[0]  # 'Benign' or 'Malware'
    if category.lower() == "benign":
        return "Normal"
    else:
        # Malware/<Family>/<Family>.pcap or Malware/<Family>.pcap
        if len(parts) > 2:
            raw_label = parts[1]
        else:
            raw_label = parts[1].split(".")[0]
        # Match against known USTC labels
        for known in USTC_TFC2016_LABELS:
            if known.lower() == raw_label.lower():
                return known
        return raw_label


def load_ustc_tfc2016_dataset(
    dataset_dir: Optional[str] = None,
    sample_ratio: Optional[float] = 1.0,
    max_packets_per_pcap: int = 5000,
    use_cache: bool = True,
    cache_path: Optional[str] = None,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Nạp và trích xuất 10 đặc trưng gói tin L2-4 từ tập dữ liệu mã hóa USTC-TFC2016.
    Có cơ chế lưu và nạp từ bộ nhớ đệm Parquet siêu tốc.
    """
    base_dir = dataset_dir or DEFAULT_USTC_DIR
    cache_file = cache_path or DEFAULT_CACHE_FILE

    if not os.path.exists(base_dir):
        raise FileNotFoundError(f"Tập dữ liệu USTC-TFC2016 không tồn tại tại: {base_dir}")

    df: Optional[pd.DataFrame] = None

    # 1. Thử đọc từ Cache Parquet nếu có
    if use_cache and os.path.exists(cache_file):
        try:
            print(f"[USTC-TFC2016] Dang nap dac trung goi tin tu Parquet Cache: {cache_file}")
            df = pd.read_parquet(cache_file)
            print(f"  -> [Cache Hit] Nap thanh cong {len(df):,} goi tin ({len(df.columns)} cot)!")
        except Exception as e:
            print(f"[USTC-TFC2016] Loi doc cache ({e}), tien hanh trich xuat tu PCAP...")
            df = None

    # 2. Nếu chưa có cache, quét và trích xuất toàn bộ PCAP
    if df is None:
        pcap_files = glob.glob(os.path.join(base_dir, "**", "*.pcap"), recursive=True)
        if not pcap_files:
            raise FileNotFoundError(f"Khong tim thay tap tin .pcap nao trong {base_dir}")

        print(f"[USTC-TFC2016] Tim thay {len(pcap_files)} tap tin PCAP. Dang trich xuat 10 dac trung Layer 2-4...")
        t0 = time.perf_counter()
        all_rows = []
        all_labels = []

        for pcap_path in sorted(pcap_files):
            lbl = parse_ustc_label_from_path(pcap_path, base_dir)
            recs = extract_features_from_pcap(pcap_path, max_packets=max_packets_per_pcap)
            for r in recs:
                all_rows.append(r)
                all_labels.append(lbl)

        t_elapsed = time.perf_counter() - t0
        print(f"  -> Trich xuat hoan tat {len(all_rows):,} goi tin trong {t_elapsed:.2f}s!")

        df = pd.DataFrame(all_rows, columns=ESP32_PACKET_FEATURES)
        df["label"] = all_labels

        # Lưu vào cache parquet để tái sử dụng ngay lập tức ở các lần chạy sau
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            df.to_parquet(cache_file, index=False)
            print(f"  -> Da luu bo nho dem Parquet tai: {cache_file}")
        except Exception as e:
            print(f"  -> [Canh bao] Khong the ghi bo nho dem: {e}")

    # 3. Loại bỏ bản ghi trùng lặp hoàn toàn để tránh data leakage qua split
    initial_rows = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    dups_removed = initial_rows - len(df)
    if dups_removed > 0:
        print(f"  -> Da loai bo {dups_removed:,} ban ghi trung lap hoan toan truoc khi phan chia.")

    # 4. Lấy mẫu phân tầng theo sample_ratio nếu cần
    if sample_ratio is not None and 0.0 < sample_ratio < 1.0:
        try:
            _, df = train_test_split(
                df, test_size=sample_ratio, random_state=random_state, stratify=df["label"]
            )
            df = df.reset_index(drop=True)
            print(f"  -> Da lay mau phan tang (Sample Ratio: {sample_ratio*100:.1f}%): {len(df):,} mau.")
        except Exception as e:
            print(f"  -> [Canh bao lay mau phan tang]: {e}")

    X_df = df[ESP32_PACKET_FEATURES].copy().reset_index(drop=True)
    y_series = df["label"].copy().reset_index(drop=True)

    X_df.attrs["data_quality"] = {
        "dataset_name": "USTC-TFC2016",
        "traffic_mode": "encrypted",
        "profile": ESP32_PACKET_PROFILE,
        "features_count": len(ESP32_PACKET_FEATURES),
        "total_extracted_records": len(X_df),
        "duplicates_removed": dups_removed
    }

    return X_df, y_series


class EncryptedTrafficPreprocessor:
    """
    Bộ tiền xử lý chuyên biệt cho lưu lượng mã hóa (10 đặc trưng Layer 2-4 ESP32).
    Hoàn toàn tương thích chuẩn với EdgeTrafficPreprocessor nhưng tối ưu cho 10 đặc trưng số.
    """

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names: List[str] = list(feature_names) if feature_names else list(ESP32_PACKET_FEATURES)
        self.scaler: StandardScaler = StandardScaler()
        self.label_encoder: LabelEncoder = LabelEncoder()
        self.fitted: bool = False
        self.label_names: List[str] = []

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "EncryptedTrafficPreprocessor":
        """Khớp scaler và label_encoder chỉ trên tập huấn luyện (chống rò rỉ dữ liệu)."""
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names)
        X_vals = X[self.feature_names].values.astype(np.float64)
        self.scaler.fit(X_vals)
        self.label_encoder.fit(y.astype(str))
        self.label_names = list(self.label_encoder.classes_)
        self.fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Chuẩn hóa dữ liệu đầu vào sử dụng scaler đã khớp."""
        if not self.fitted:
            raise RuntimeError("Preprocessor must be fitted before transform.")
        if isinstance(X, pd.DataFrame):
            X_vals = X[self.feature_names].values.astype(np.float64)
        else:
            X_vals = np.asarray(X, dtype=np.float64)
        return self.scaler.transform(X_vals)

    def extract_features(self, telemetry: Dict[str, Any]) -> pd.DataFrame:
        """Trích xuất 10 đặc trưng từ bản ghi telemetry phục vụ suy luận thời gian thực."""
        row = {}
        edge_raw = telemetry.get("edge_raw_features", {})
        for name in self.feature_names:
            if name in edge_raw:
                row[name] = float(edge_raw[name])
            elif name in telemetry:
                row[name] = float(telemetry[name])
            else:
                row[name] = 0.0
        return pd.DataFrame([row], columns=self.feature_names)

    def save(self, filepath: str) -> None:
        """Lưu trạng thái preprocessor ra tập tin."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "EncryptedTrafficPreprocessor":
        """Nạp preprocessor từ tập tin."""
        return joblib.load(filepath)
