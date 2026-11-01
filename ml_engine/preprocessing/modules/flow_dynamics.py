"""
Flow Dynamics & Bi-directional Sub-Flow Sub-Preprocessor
========================================================
Quản lý các đặc trưng động lực học luồng hai chiều (Biflow) và cửa sổ trượt Sub-flows:
- Khắc phục giới hạn của việc chỉ nhìn 1 chiều (Unidirectional) hoặc gộp toàn bộ gói tin.
- Chia luồng 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) thành 2 chiều Forward & Backward.
- Tính toán độ bất đối xứng số lượng gói và dung lượng byte (Asymmetry Ratios).
- Đo khoảng cách thời gian (IAT) và kích thước gói riêng biệt cho từng chiều.
- Hỗ trợ cắt nhỏ luồng thành các sub-flow kích thước cố định N gói (mặc định N=25)
  theo công trình của Nguyen & Armitage (Cisco/Swinburne 2006).

Tài liệu tham khảo:
- Nguyen & Armitage, "Training on multiple sub-flows to optimise the use of Machine Learning
  classifiers for IP traffic flow technique", Swinburne / Cisco Systems.
- Elmaghraby et al., "Encrypted network traffic classification...", 2024.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
from .base import BaseSubPreprocessor, numeric_series

FLOW_DYNAMICS_FEATURES: List[str] = [
    # 1. Tỉ lệ và thể tích 2 chiều (Forward / Backward Counts & Volumes)
    "fwd_pkt_count",
    "bwd_pkt_count",
    "pkt_asymmetry_ratio",
    "fwd_byte_count",
    "bwd_byte_count",
    "byte_asymmetry_ratio",
    # 2. Động lực học thời gian 2 chiều (Bi-directional IAT)
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_mean",
    "bwd_iat_std",
    # 3. Kích thước gói 2 chiều (Bi-directional Packet Length)
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    # 4. Phân vị kích thước gói (Packet Size Quantiles)
    "packet_size_p25",
    "packet_size_median",
    "packet_size_p75",
    "packet_size_p90",
    "flow_duration_sec"
]


def compute_biflow_features_from_packets(packets: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Tính toán các đặc trưng biflow từ danh sách các gói tin thuộc cùng một phiên 5-tuple.
    Mỗi phần tử trong packets cần có:
      - 'direction': 'fwd' hoặc 'bwd' (hoặc xác định qua src_ip so với client_ip)
      - 'len': độ dài gói tin (bytes)
      - 'timestamp': thời điểm đến (giây hoặc mili-giây)
    """
    if not packets:
        return {feat: 0.0 for feat in FLOW_DYNAMICS_FEATURES}

    # Nếu chưa có nhãn direction, coi gói đầu tiên đến là chiều Forward
    first_src = packets[0].get("src_ip", "")
    
    fwd_lens: List[float] = []
    bwd_lens: List[float] = []
    fwd_times: List[float] = []
    bwd_times: List[float] = []
    all_lens: List[float] = []

    for pkt in packets:
        pkt_len = float(pkt.get("len", pkt.get("frame.len", 0.0)))
        ts = float(pkt.get("timestamp", pkt.get("time_epoch", 0.0)))
        all_lens.append(pkt_len)

        direction = pkt.get("direction")
        if direction is None:
            direction = "fwd" if pkt.get("src_ip") == first_src else "bwd"

        if direction == "fwd":
            fwd_lens.append(pkt_len)
            fwd_times.append(ts)
        else:
            bwd_lens.append(pkt_len)
            bwd_times.append(ts)

    fwd_count = float(len(fwd_lens))
    bwd_count = float(len(bwd_lens))
    fwd_bytes = float(sum(fwd_lens))
    bwd_bytes = float(sum(bwd_lens))

    # Tỷ lệ bất đối xứng gói: Fwd / (Fwd + Bwd) -> [0.0, 1.0]
    total_pkts = fwd_count + bwd_count
    total_bytes = fwd_bytes + bwd_bytes
    pkt_asym = (fwd_count / total_pkts) if total_pkts > 0 else 0.5
    byte_asym = (fwd_bytes / total_bytes) if total_bytes > 0 else 0.5

    # Tính IAT từng chiều
    def calc_iat(times: List[float]) -> Tuple[float, float]:
        if len(times) < 2:
            return 0.0, 0.0
        diffs = np.diff(np.sort(times))
        return float(np.mean(diffs)), float(np.std(diffs))

    fwd_iat_mean, fwd_iat_std = calc_iat(fwd_times)
    bwd_iat_mean, bwd_iat_std = calc_iat(bwd_times)

    # Thống kê độ dài gói từng chiều
    fwd_len_mean = float(np.mean(fwd_lens)) if fwd_lens else 0.0
    fwd_len_std = float(np.std(fwd_lens)) if fwd_lens else 0.0
    bwd_len_mean = float(np.mean(bwd_lens)) if bwd_lens else 0.0
    bwd_len_std = float(np.std(bwd_lens)) if bwd_lens else 0.0

    # Phân vị độ dài toàn luồng
    if all_lens:
        all_lens_arr = np.array(all_lens)
        p25 = float(np.percentile(all_lens_arr, 25))
        median = float(np.percentile(all_lens_arr, 50))
        p75 = float(np.percentile(all_lens_arr, 75))
        p90 = float(np.percentile(all_lens_arr, 90))
    else:
        p25, median, p75, p90 = 0.0, 0.0, 0.0, 0.0

    # Thời lượng luồng
    all_times = fwd_times + bwd_times
    duration = (max(all_times) - min(all_times)) if len(all_times) > 1 else 0.0

    return {
        "fwd_pkt_count": fwd_count,
        "bwd_pkt_count": bwd_count,
        "pkt_asymmetry_ratio": round(pkt_asym, 4),
        "fwd_byte_count": fwd_bytes,
        "bwd_byte_count": bwd_bytes,
        "byte_asymmetry_ratio": round(byte_asym, 4),
        "fwd_iat_mean": round(fwd_iat_mean, 6),
        "fwd_iat_std": round(fwd_iat_std, 6),
        "bwd_iat_mean": round(bwd_iat_mean, 6),
        "bwd_iat_std": round(bwd_iat_std, 6),
        "fwd_pkt_len_mean": round(fwd_len_mean, 2),
        "fwd_pkt_len_std": round(fwd_len_std, 2),
        "bwd_pkt_len_mean": round(bwd_len_mean, 2),
        "bwd_pkt_len_std": round(bwd_len_std, 2),
        "packet_size_p25": round(p25, 2),
        "packet_size_median": round(median, 2),
        "packet_size_p75": round(p75, 2),
        "packet_size_p90": round(p90, 2),
        "flow_duration_sec": round(duration, 4),
    }


def partition_into_subflows(packets: List[Dict[str, Any]], subflow_size: int = 25) -> List[List[Dict[str, Any]]]:
    """
    Chia luồng gói tin thành các cửa sổ con (sub-flows) kích thước cố định N gói
    theo kỹ thuật của Nguyen & Armitage (2006).
    Cho phép bộ phân loại nhận diện chính xác ở bất kỳ điểm nào của luồng (giữa luồng, cuối luồng).
    """
    if not packets or subflow_size <= 0:
        return []
    return [packets[i:i + subflow_size] for i in range(0, len(packets), subflow_size)]


class FlowDynamicsPreprocessor(BaseSubPreprocessor):
    """
    Tiền xử lý và chuẩn hóa các đặc trưng động lực học luồng 2 chiều (Biflow)
    và phân vị kích thước gói tin.
    """

    def __init__(self):
        super().__init__(feature_names=FLOW_DYNAMICS_FEATURES, cat_cols=[])

    def _fit_internal(self, df: pd.DataFrame) -> None:
        """Học các giá trị phân phối baseline từ dữ liệu thật."""
        pass

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        for col in self.feature_names:
            if col in df.columns:
                s = numeric_series(df[col])
                out[col] = s.fillna(self.learned_baselines_.get(col, 0.0))
            else:
                out[col] = self.learned_baselines_.get(col, 0.0)
        return out

    def extract_from_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        """
        Trích xuất từ Telemetry:
        - Lấy trực tiếp các trường nếu đã được Host Sniffer / TShark tính toán sẵn.
        - Hoặc nếu telemetry cung cấp mảng gói tin 'flow_packets' -> tính toán động ngay lập tức.
        """
        res: Dict[str, float] = {}
        for feat in self.feature_names:
            if feat in telemetry:
                try:
                    res[feat] = float(telemetry[feat])
                except (ValueError, TypeError):
                    res[feat] = self.learned_baselines_.get(feat, 0.0)

        if len(res) == len(self.feature_names):
            return res

        # Fallback tính toán từ danh sách packet records nếu có
        raw_packets = telemetry.get("flow_packets")
        if isinstance(raw_packets, list) and len(raw_packets) > 0:
            return compute_biflow_features_from_packets(raw_packets)

        for feat in self.feature_names:
            if feat not in res:
                res[feat] = self.learned_baselines_.get(feat, 0.0)

        return res
