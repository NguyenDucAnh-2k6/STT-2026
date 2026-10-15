"""
Edge-IIoTset Comprehensive Preprocessing & Modular Feature Engineering
======================================================================
Mục đích:
- Quản lý tập trung toàn bộ logic nạp dữ liệu, làm sạch, mã hóa và chuẩn hóa đặc trưng.
- Chia tách thành các module con chuyên biệt theo tầng giao thức:
    * NetworkCorePreprocessor (ARP, ICMP)
    * TCPTransportPreprocessor (TCP)
    * UDPTransportPreprocessor (UDP)
    * HTTPApplicationPreprocessor (HTTP)
    * IoTProtocolsPreprocessor (DNS, MQTT, Modbus TCP)
- Loại bỏ hoàn toàn các số cứng (hardcoded magic numbers) nhân tạo; toàn bộ imputation
  và giá trị mặc định được học trực tiếp từ phân phối thực nghiệm (empirical distribution)
  của tập dữ liệu huấn luyện thật.
- Duy trì trọn vẹn 56 đặc trưng hành vi mạng của Edge-IIoTset.
"""

import os
import sys
from typing import Dict, List, Tuple, Optional, Any, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

from ..config.schema import (
    EDGE_IIOTSET_FEATURES,
    EDGE_IIOTSET_LABELS,
    DEFAULT_DATASET_SAMPLES
)
from .modules import (
    BaseSubPreprocessor,
    NetworkCorePreprocessor,
    TCPTransportPreprocessor,
    UDPTransportPreprocessor,
    HTTPApplicationPreprocessor,
    IoTProtocolsPreprocessor
)

# Đường dẫn mặc định đến file CSV Edge-IIoTset
DEFAULT_EDGE_IIOTSET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "datasets", "Edge-IIoTset dataset",
    "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv"
)


class EdgeTrafficPreprocessor:
    """
    Bộ tiền xử lý toàn diện kết hợp các module con chuyên biệt theo tầng giao thức mạng.
    Học phân phối thực nghiệm từ dữ liệu thật, không dùng bất kỳ số cứng nào.
    """

    def __init__(
        self,
        feature_names: Optional[List[str]] = None,
        scaler: Optional[StandardScaler] = None,
        label_encoder: Optional[LabelEncoder] = None,
        sub_preprocessors: Optional[Dict[str, BaseSubPreprocessor]] = None
    ):
        self.feature_names: List[str] = feature_names if feature_names is not None else list(EDGE_IIOTSET_FEATURES)
        self.scaler: StandardScaler = scaler if scaler is not None else StandardScaler()
        self.label_encoder: LabelEncoder = label_encoder if label_encoder is not None else LabelEncoder()

        # Khởi tạo các module con chuyên biệt theo giao thức
        if sub_preprocessors is not None:
            self.sub_preprocessors = sub_preprocessors
        else:
            self.sub_preprocessors: Dict[str, BaseSubPreprocessor] = {
                "network_core": NetworkCorePreprocessor(),
                "tcp": TCPTransportPreprocessor(),
                "udp": UDPTransportPreprocessor(),
                "http": HTTPApplicationPreprocessor(),
                "iot": IoTProtocolsPreprocessor()
            }

        self.feature_baselines_: Dict[str, float] = {}
        self.is_fitted: bool = False
        if hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None:
            self.is_fitted = True

    def fit(self, X_df: pd.DataFrame, y: Optional[Union[pd.Series, np.ndarray]] = None) -> "EdgeTrafficPreprocessor":
        """
        Học phân phối thống kê và fit các encoder trên từng module con chuyên biệt,
        sau đó fit StandardScaler trên toàn bộ ma trận đặc trưng.
        """
        # 1. Fit từng module con theo giao thức để học baseline thực nghiệm từ dữ liệu Normal thật
        # Đảm bảo khi thiếu trường trong telemetry thời gian thực, giá trị mặc định luôn là mức baseline an toàn (Normal)
        normal_df = X_df
        if y is not None:
            if pd.Series(y).isna().any():
                raise ValueError("Missing training labels must not be assumed Normal.")
            y_series = pd.Series(np.asarray(y), index=X_df.index).astype(str)
            norm_mask = (y_series.str.lower() == "normal")
            if norm_mask.sum() > 0:
                normal_df = X_df.loc[norm_mask]

        transformed_parts = []
        self.feature_baselines_ = {}

        for name, sub in self.sub_preprocessors.items():
            sub.fit(df=normal_df, full_df=X_df)
            self.feature_baselines_.update(sub.learned_baselines_)
            part_df = sub.transform(X_df)
            transformed_parts.append(part_df)

        # 2. Hợp nhất các cột theo đúng thứ tự canonical trong self.feature_names
        combined_df = pd.concat(transformed_parts, axis=1)
        for feat in self.feature_names:
            if feat not in combined_df.columns:
                combined_df[feat] = self.feature_baselines_.get(feat, 0.0)

        aligned_df = combined_df[self.feature_names].copy()
        for feat in self.feature_names:
            s = pd.to_numeric(aligned_df[feat], errors="coerce").replace([np.inf, -np.inf], np.nan)
            aligned_df[feat] = s.fillna(self.feature_baselines_.get(feat, 0.0))
        X_matrix = aligned_df.values.astype(np.float32)

        # 3. Fit StandardScaler trên ma trận số thực hoàn chỉnh
        self.scaler.fit(X_matrix)
        self.is_fitted = True

        # 4. Fit LabelEncoder cho nhãn mục tiêu y (nếu có)
        if y is not None:
            y_clean = pd.Series(y).astype(str)
            self.label_encoder.fit(y_clean)

        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Chuyển đổi dữ liệu thô sang ma trận đặc trưng số đã chuẩn hóa z-score."""
        if not self.is_fitted:
            raise RuntimeError("[EdgeTrafficPreprocessor] Preprocessor chưa được fit! Vui lòng fit() trước.")

        if isinstance(X, np.ndarray):
            if X.shape[1] == len(self.feature_names):
                return self.scaler.transform(X)
            raise ValueError(f"Ma trận đầu vào có {X.shape[1]} cột, kỳ vọng {len(self.feature_names)} cột.")

        return self.scaler.transform(self.encode_features(X))

    def encode_features(self, X: pd.DataFrame) -> np.ndarray:
        """Return fitted categorical/numeric encoding before scaling, for deployment export."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before encoding")
        # X là DataFrame: chuyển đổi qua từng module con
        transformed_parts = []
        for name, sub in self.sub_preprocessors.items():
            part_df = sub.transform(X)
            transformed_parts.append(part_df)

        combined_df = pd.concat(transformed_parts, axis=1)
        for feat in self.feature_names:
            if feat not in combined_df.columns:
                combined_df[feat] = self.feature_baselines_.get(feat, 0.0)

        aligned_df = combined_df[self.feature_names].copy()
        for feat in self.feature_names:
            s = pd.to_numeric(aligned_df[feat], errors="coerce").replace([np.inf, -np.inf], np.nan)
            aligned_df[feat] = s.fillna(self.feature_baselines_.get(feat, 0.0))
        X_matrix = aligned_df.values.astype(np.float32)
        return X_matrix

    def fit_transform(
        self,
        X_df: pd.DataFrame,
        y: Optional[Union[pd.Series, np.ndarray]] = None
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Học và chuyển đổi đồng thời tập đặc trưng và nhãn."""
        self.fit(X_df, y)
        X_transformed = self.transform(X_df)

        y_transformed = None
        if y is not None:
            y_clean = pd.Series(y).astype(str)
            y_transformed = self.label_encoder.transform(y_clean)

        return X_transformed, y_transformed

    def extract_features(self, telemetry: Dict[str, Any]) -> pd.DataFrame:
        """
        Trích xuất vector 56 đặc trưng từ dictionary telemetry của Probe (Host hoặc ESP32).
        Tất cả các module con trích xuất số liệu đo đạc thực tế hoặc sử dụng baseline
        học được từ dữ liệu huấn luyện thật, loại bỏ hoàn toàn các số cứng nhân tạo.
        """
        row_dict = {}

        # Thu thập đặc trưng từ tất cả các module con
        for name, sub in self.sub_preprocessors.items():
            sub_feats = sub.extract_from_telemetry(telemetry)
            row_dict.update(sub_feats)

        # Đảm bảo đủ các trường theo đúng thứ tự
        final_row = {feat: row_dict[feat] for feat in self.feature_names if feat in row_dict}
        # Missing packet fields stay missing until the trained imputer is applied.
        # An empty record still needs one row for scaler shape consistency.
        if not final_row:
            return pd.DataFrame(index=[0])

        return pd.DataFrame([final_row])

    def save(self, file_path: str) -> str:
        """Lưu toàn bộ preprocessor (sub-modules, scaler, encoder, baselines) bằng Joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        bundle = {
            "preprocessing_version": 2,
            "feature_names": self.feature_names,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "sub_preprocessors": self.sub_preprocessors,
            "feature_baselines_": self.feature_baselines_,
            "is_fitted": self.is_fitted
        }
        joblib.dump(bundle, file_path)
        return os.path.abspath(file_path)

    @classmethod
    def load(cls, file_path: str) -> "EdgeTrafficPreprocessor":
        """Tải preprocessor đã lưu từ đĩa."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[EdgeTrafficPreprocessor] Không tìm thấy file: {file_path}")
        bundle = joblib.load(file_path)
        if isinstance(bundle, dict) and "scaler" in bundle:
            instance = cls(
                feature_names=bundle.get("feature_names", list(EDGE_IIOTSET_FEATURES)),
                scaler=bundle.get("scaler"),
                label_encoder=bundle.get("label_encoder"),
                sub_preprocessors=bundle.get("sub_preprocessors")
            )
            instance.feature_baselines_ = bundle.get("feature_baselines_", {})
            instance.is_fitted = bundle.get("is_fitted", True)
            return instance
        elif isinstance(bundle, StandardScaler):
            instance = cls(scaler=bundle)
            instance.is_fitted = True
            return instance
        return bundle


def load_raw_dataset(
    dataset_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    sample_ratio: Optional[float] = None,
    random_state: int = 42,
    invalid_rows: str = "error"
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Hàm cấp cao nạp và tiền xử lý toàn diện tập dữ liệu Edge-IIoTset.
    Duy trì full 56 đặc trưng mạng, không drop đặc trưng nào.
    Hỗ trợ lấy mẫu phân tầng theo tỉ lệ sample_ratio cân bằng chính xác phân phối các lớp.
    """
    path = dataset_path if dataset_path is not None else DEFAULT_EDGE_IIOTSET_PATH
    if sample_ratio is not None and not 0.0 < sample_ratio <= 1.0:
        raise ValueError("sample_ratio must be in (0, 1].")
    if invalid_rows not in ("error", "drop"):
        raise ValueError("invalid_rows must be error or drop")

    if os.path.exists(path):
        print(f"[Preprocessor] Đang nạp tập dữ liệu Edge-IIoTset từ: {path}")
        from .validation import CATEGORICAL_FEATURES
        df = pd.read_csv(path, low_memory=False, dtype={col: "string" for col in CATEGORICAL_FEATURES})
        from .validation import invalid_feature_counts, invalid_record_mask
        source_rows = len(df)
        invalid = invalid_feature_counts(df)
        invalid_mask = invalid_record_mask(df)
        if invalid:
            if invalid_rows == "error":
                raise ValueError(f"Malformed benchmark numeric fields: {invalid}. Verify the source or explicitly select invalid_rows='drop'.")
            print(f"  -> Excluded {int(invalid_mask.sum()):,} malformed records before sampling: {invalid}")
            df = df.loc[~invalid_mask].copy()
        # Exact canonical records must not occur on both sides of a split.
        duplicate_columns = [col for col in EDGE_IIOTSET_FEATURES if col in df]
        duplicate_columns += [col for col in ("Attack_type", "label") if col in df]
        duplicate_count = int(df.duplicated(duplicate_columns).sum())
        if duplicate_count:
            df = df.drop_duplicates(duplicate_columns).reset_index(drop=True)
            print(f"  -> Removed {duplicate_count:,} exact feature/label duplicates before sampling/splitting.")
        total_rows = len(df)
        ratio = sample_ratio
        if ratio is None and sample_size is not None and total_rows > 0:
            ratio = min(1.0, max(0.0, sample_size / total_rows))

        if ratio is not None and 0.0 < ratio < 1.0:
            target_col_temp = "Attack_type" if "Attack_type" in df.columns else df.columns[-1]
            try:
                _, df = train_test_split(
                    df, test_size=ratio, random_state=random_state, stratify=df[target_col_temp]
                )
            except Exception:
                def _sample_group(g):
                    n = max(2, int(len(g) * ratio))
                    return g.sample(min(len(g), n), random_state=random_state)
                df = df.groupby(target_col_temp, group_keys=False).apply(_sample_group)
            df = df.reset_index(drop=True)
            print(f"  -> Đã lấy mẫu phân tầng (Stratified Sample ratio={ratio:.4f}): {len(df):,} dòng x {df.shape[1]} cột")
    else:
        raise FileNotFoundError(f"Benchmark dataset not found: {path}. Synthetic fallback is disabled.")

    # Tách X (56 đặc trưng mạng, loại bỏ metadata rò rỉ và địa chỉ IP) và y (Attack_type)
    leak_cols = ["frame.time", "ip.src_host", "ip.dst_host", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "Attack_label", "Attack_type", "label"]
    feature_cols = [c for c in EDGE_IIOTSET_FEATURES if c in df.columns]
    target_col = "Attack_type" if "Attack_type" in df.columns else "label"
    if target_col not in df or not feature_cols:
        raise ValueError("Dataset must contain a target label and canonical network features.")

    X_df = df[feature_cols].reset_index(drop=True)
    X_df.attrs["data_quality"] = {"source_file": os.path.basename(path), "source_rows": source_rows,
        "invalid_rows_policy": invalid_rows, "invalid_numeric_fields": invalid,
        "malformed_rows_removed": int(invalid_mask.sum()) if invalid_rows == "drop" else 0,
        "exact_duplicates_removed": duplicate_count}
    missing = set(EDGE_IIOTSET_FEATURES) - set(feature_cols)
    if missing:
        raise ValueError(f"Benchmark missing canonical columns: {sorted(missing)}")
    from .validation import invalid_feature_counts
    invalid = invalid_feature_counts(X_df)
    if invalid:
        raise ValueError(f"Malformed benchmark numeric fields: {invalid}. Verify the CSV schema/source; silent coercion is disabled.")
    missing = set(EDGE_IIOTSET_FEATURES) - set(feature_cols)
    if missing:
        raise ValueError(f"Benchmark missing canonical columns: {sorted(missing)}")
    from .validation import invalid_feature_counts
    invalid = invalid_feature_counts(X_df)
    if invalid:
        raise ValueError(f"Malformed benchmark numeric fields: {invalid}. Verify the CSV schema/source; silent coercion is disabled.")
    y_raw = df[target_col].reset_index(drop=True)
    if y_raw.isna().any() or not y_raw.astype(str).isin(EDGE_IIOTSET_LABELS).all():
        raise ValueError("Dataset contains missing or unsupported labels.")
    return X_df, y_raw.astype(str)


def load_and_preprocess_dataset(
    dataset_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    sample_ratio: Optional[float] = None,
    test_size: float = 0.0,
    random_state: int = 42
) -> Tuple[np.ndarray, Optional[np.ndarray], np.ndarray, Optional[np.ndarray], EdgeTrafficPreprocessor]:
    """Split raw records before fitting encoders, baselines, or the scaler."""
    X_df, y_raw = load_raw_dataset(dataset_path, sample_size, sample_ratio, random_state)
    preprocessor = EdgeTrafficPreprocessor(feature_names=list(X_df.columns))
    if test_size > 0:
        raw_train, raw_test, labels_train, labels_test = train_test_split(
            X_df, y_raw, test_size=test_size, random_state=random_state, stratify=y_raw
        )
        preprocessor.fit(raw_train, labels_train)
        return (preprocessor.transform(raw_train), preprocessor.transform(raw_test),
                preprocessor.label_encoder.transform(labels_train),
                preprocessor.label_encoder.transform(labels_test), preprocessor)

    X_scaled, y_encoded = preprocessor.fit_transform(X_df, y_raw)
    return X_scaled, None, y_encoded, None, preprocessor


def load_full_dataset(
    dataset_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    sample_ratio: Optional[float] = None,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, EdgeTrafficPreprocessor]:
    """
    Nạp và tiền xử lý toàn bộ tập dữ liệu (100% data phục vụ CV và train final model).
    """
    X, _, y, _, preprocessor = load_and_preprocess_dataset(
        dataset_path=dataset_path,
        sample_size=sample_size,
        sample_ratio=sample_ratio,
        test_size=0.0,
        random_state=random_state
    )
    return X, y, preprocessor
