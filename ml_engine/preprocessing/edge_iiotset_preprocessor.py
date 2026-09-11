"""
Edge-IIoTset Comprehensive Preprocessing & Feature Engineering Module
======================================================================
Mục đích:
- Quản lý tập trung toàn bộ logic nạp dữ liệu, làm sạch, mã hóa và chuẩn hóa đặc trưng.
- Duy trì trọn vẹn FULL 63 ĐẶC TRƯNG của tập Edge-IIoTset (61 đặc trưng đầu vào + 2 cột nhãn).
- Không tự ý drop bớt đặc trưng (logic feature selection / drop sẽ được mở rộng độc lập sau).
- Cung cấp class EdgeTrafficPreprocessor có khả năng trích xuất an toàn từ telemetry thời gian thực
  và lưu/nạp trạng thái (fitted encoders, scaler) phục vụ suy luận không độ trễ.
"""

import os
import sys
from typing import Dict, List, Tuple, Optional, Any, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, OrdinalEncoder, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

from ..config.schema import (
    EDGE_IIOTSET_FEATURES,
    EDGE_IIOTSET_LABELS,
    SLIDING_WINDOW_FEATURES,
    DEFAULT_DATASET_SAMPLES
)

# Đường dẫn mặc định đến file CSV Edge-IIoTset
DEFAULT_EDGE_IIOTSET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "datasets", "Edge-IIoTset dataset",
    "Selected dataset for ML and DL", "ML-EdgeIIoT-dataset.csv"
)


class EdgeTrafficPreprocessor:
    """
    Bộ tiền xử lý toàn diện cho tập dữ liệu an ninh mạng Edge-IIoTset.
    Duy trì đầy đủ 61 đặc trưng đầu vào, tự động xử lý chuỗi và chuẩn hóa z-score.
    """

    def __init__(
        self,
        feature_names: Optional[List[str]] = None,
        cat_cols: Optional[List[str]] = None,
        scaler: Optional[StandardScaler] = None,
        ordinal_encoder: Optional[OrdinalEncoder] = None,
        label_encoder: Optional[LabelEncoder] = None
    ):
        self.feature_names: List[str] = feature_names if feature_names is not None else list(EDGE_IIOTSET_FEATURES)
        self.cat_cols: List[str] = cat_cols if cat_cols is not None else []
        self.scaler: StandardScaler = scaler if scaler is not None else StandardScaler()
        self.ordinal_encoder: OrdinalEncoder = (
            ordinal_encoder if ordinal_encoder is not None
            else OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        )
        self.label_encoder: LabelEncoder = label_encoder if label_encoder is not None else LabelEncoder()
        self._cat_maps: Optional[List[Dict[Any, float]]] = None
        self.is_fitted: bool = False
        if hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None:
            self.is_fitted = True

    def _build_cat_maps(self):
        """Khởi tạo từ điển tra cứu O(1) cho các cột phân loại để tăng tốc suy luận thời gian thực."""
        if hasattr(self, "ordinal_encoder") and hasattr(self.ordinal_encoder, "categories_"):
            self._cat_maps = [
                {val: float(idx) for idx, val in enumerate(cats)}
                for cats in self.ordinal_encoder.categories_
            ]

    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Làm sạch các giá trị null, vô hạn (inf/-inf) và định dạng chuỗi."""
        df_clean = df.copy()
        
        # Đảm bảo đủ các cột đặc trưng, nếu thiếu thì điền 0.0
        for col in self.feature_names:
            if col not in df_clean.columns:
                df_clean[col] = 0.0

        # Chỉ giữ đúng danh sách các cột đặc trưng theo đúng thứ tự
        df_clean = df_clean[self.feature_names]

        # Xử lý các cột dạng chuỗi / categorical
        if not self.cat_cols:
            self.cat_cols = df_clean.select_dtypes(include=["object"]).columns.tolist()

        for c in self.cat_cols:
            df_clean[c] = df_clean[c].fillna("0").astype(str).str.strip()

        # Xử lý các cột số
        num_cols = [c for c in self.feature_names if c not in self.cat_cols]
        for c in num_cols:
            df_clean[c] = pd.to_numeric(df_clean[c], errors="coerce").fillna(0.0)
            df_clean[c] = df_clean[c].replace([np.inf, -np.inf], 0.0)

        return df_clean

    def fit(self, X_df: pd.DataFrame, y: Optional[Union[pd.Series, np.ndarray]] = None) -> "EdgeTrafficPreprocessor":
        """Học các thông số encode và chuẩn hóa trên tập dữ liệu huấn luyện."""
        X_clean = self._clean_dataframe(X_df)

        # 1. Fit OrdinalEncoder cho các cột chuỗi
        if self.cat_cols:
            self.ordinal_encoder.fit(X_clean[self.cat_cols])
            encoded_cats = self.ordinal_encoder.transform(X_clean[self.cat_cols])
            X_clean[self.cat_cols] = encoded_cats

        # Đảm bảo toàn bộ ma trận đều là số thực
        X_matrix = X_clean.values.astype(np.float32)

        # 2. Fit StandardScaler
        self.scaler.fit(X_matrix)
        self.is_fitted = True

        # 3. Fit LabelEncoder nếu có nhãn mục tiêu y
        if y is not None:
            y_clean = pd.Series(y).fillna("Normal").astype(str)
            # Đảm bảo 'Normal' luôn được fit và ưu tiên
            self.label_encoder.fit(y_clean)

        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Chuyển đổi dữ liệu thô sang ma trận đặc trưng số đã chuẩn hóa."""
        if not self.is_fitted:
            raise RuntimeError("[EdgeTrafficPreprocessor] Scaler chua duoc fit! Vui long fit() truoc.")

        if isinstance(X, np.ndarray):
            return self.scaler.transform(X)

        X_clean = self._clean_dataframe(X)

        if self.cat_cols:
            if getattr(self, "_cat_maps", None) is None:
                self._build_cat_maps()
            if getattr(self, "_cat_maps", None) and len(X_clean) == 1:
                row_vals = X_clean[self.cat_cols].iloc[0].values
                fast_enc = [self._cat_maps[i].get(row_vals[i], -1.0) for i in range(len(self.cat_cols))]
                X_clean[self.cat_cols] = [fast_enc]
            else:
                X_clean[self.cat_cols] = self.ordinal_encoder.transform(X_clean[self.cat_cols])

        X_matrix = X_clean.values.astype(np.float32)
        return self.scaler.transform(X_matrix)

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
            y_clean = pd.Series(y).fillna("Normal").astype(str)
            y_transformed = self.label_encoder.transform(y_clean)

        return X_transformed, y_transformed

    def extract_features(self, telemetry: Dict[str, Any]) -> pd.DataFrame:
        """
        Trích xuất an toàn DataFrame 1 dòng (61 cột) từ dictionary telemetry thời gian thực.
        Tự động tương thích với cả telemetry từ ESP32 Simulator, Host Sniffer và gói tin đầy đủ.

        Parameters:
        -----------
        telemetry : dict
            Dữ liệu gói tin telemetry từ broker MQTT.

        Returns:
        --------
        pd.DataFrame:
            DataFrame 1 dòng với 61 cột chuẩn.
        """
        row_dict = {}

        # 1. Điền các giá trị sẵn có trong telemetry khớp với 61 cột
        for feat in self.feature_names:
            if feat in telemetry:
                row_dict[feat] = telemetry[feat]
            else:
                row_dict[feat] = 0.0

        # 2. Xử lý ánh xạ tương thích ngược từ các trường sliding window nếu thiếu
        if "packet_rate" in telemetry:
            sz = float(telemetry.get("avg_packet_size", 64.0))
            syn_r = float(telemetry.get("syn_ratio", 0.0))
            ack_r = float(telemetry.get("ack_ratio", 0.0))
            udp_r = float(telemetry.get("udp_ratio", 0.0))
            icmp_r = float(telemetry.get("icmp_ratio", 0.0))

            if row_dict.get("tcp.connection.syn", 0.0) == 0.0 and syn_r > 0.5:
                row_dict["tcp.connection.syn"] = 1.0
            if row_dict.get("tcp.flags.ack", 0.0) == 0.0 and ack_r > 0.5:
                row_dict["tcp.flags.ack"] = 1.0
            if row_dict.get("tcp.len", 0.0) == 0.0:
                row_dict["tcp.len"] = sz
            if row_dict.get("udp.stream", 0.0) == 0.0 and udp_r > 0.0:
                row_dict["udp.stream"] = 1.0
            if row_dict.get("icmp.checksum", 0.0) == 0.0 and icmp_r > 0.0:
                row_dict["icmp.checksum"] = 1.0

        return pd.DataFrame([row_dict])

    def save(self, file_path: str) -> str:
        """Lưu toàn bộ preprocessor (scaler, encoders, feature_names) bằng Joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        bundle = {
            "feature_names": self.feature_names,
            "cat_cols": self.cat_cols,
            "scaler": self.scaler,
            "ordinal_encoder": self.ordinal_encoder,
            "label_encoder": self.label_encoder,
            "is_fitted": self.is_fitted
        }
        joblib.dump(bundle, file_path)
        return os.path.abspath(file_path)

    @classmethod
    def load(cls, file_path: str) -> "EdgeTrafficPreprocessor":
        """Tải preprocessor đã lưu từ đĩa."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"[EdgeTrafficPreprocessor] Khong tim thay file: {file_path}")
        bundle = joblib.load(file_path)
        if isinstance(bundle, dict) and "scaler" in bundle:
            instance = cls(
                feature_names=bundle.get("feature_names", list(EDGE_IIOTSET_FEATURES)),
                cat_cols=bundle.get("cat_cols", []),
                scaler=bundle.get("scaler"),
                ordinal_encoder=bundle.get("ordinal_encoder"),
                label_encoder=bundle.get("label_encoder")
            )
            instance.is_fitted = bundle.get("is_fitted", True)
            return instance
        elif isinstance(bundle, StandardScaler):
            # Tương thích nếu file chỉ lưu StandardScaler
            instance = cls(scaler=bundle)
            instance.is_fitted = True
            return instance
        else:
            return bundle


def load_and_preprocess_dataset(
    dataset_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    test_size: float = 0.25,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, EdgeTrafficPreprocessor]:
    """
    Hàm cấp cao nạp và tiền xử lý toàn diện tập dữ liệu Edge-IIoTset.
    Duy trì full 63 đặc trưng (61 đầu vào + labels). Không drop đặc trưng nào.

    Returns:
    --------
    Tuple: (X_train, X_test, y_train, y_test, preprocessor)
    """
    path = dataset_path if dataset_path and os.path.exists(dataset_path) else DEFAULT_EDGE_IIOTSET_PATH

    if os.path.exists(path):
        print(f"[Preprocessor] Dang nap tap du lieu Edge-IIoTset tu: {path}")
        df = pd.read_csv(path, low_memory=False)
        total_rows = len(df)
        print(f"  -> Tong so dong goc: {total_rows:,} dong x {df.shape[1]} cot")
        if sample_size is not None and 0 < sample_size < total_rows:
            frac = sample_size / total_rows
            target_col_temp = "Attack_type" if "Attack_type" in df.columns else df.columns[-1]
            _, df = train_test_split(
                df, test_size=frac, random_state=random_state, stratify=df[target_col_temp]
            )
            df = df.reset_index(drop=True)
            print(f"  -> Da lay mau phan tang (Stratified Sample): {len(df):,} dong x {df.shape[1]} cot")
    else:
        print(f"[Preprocessor] [Canh bao] Khong tim thay file {path}. Tao tap du lieu mau Edge-IIoTset...")
        # Fallback tạo dataframe giả lập đúng schema 61 đặc trưng
        rows = []
        n_samples = sample_size if sample_size else DEFAULT_DATASET_SAMPLES
        for i in range(n_samples):
            row = {feat: float(np.random.rand() * 100.0) for feat in EDGE_IIOTSET_FEATURES}
            row["frame.time"] = f"2026-09-09 21:00:{i%60:02d}"
            row["ip.src_host"] = f"192.168.1.{np.random.randint(1, 254)}"
            row["ip.dst_host"] = "192.168.1.100"
            row["Attack_label"] = 0 if i % 2 == 0 else 1
            row["Attack_type"] = "Normal" if row["Attack_label"] == 0 else EDGE_IIOTSET_LABELS[np.random.randint(1, len(EDGE_IIOTSET_LABELS))]
            rows.append(row)
        df = pd.DataFrame(rows)

    # Tách X (61 đặc trưng) và y (Attack_type)
    feature_cols = [c for c in df.columns if c not in ["Attack_label", "Attack_type", "label"]]
    target_col = "Attack_type" if "Attack_type" in df.columns else ("label" if "label" in df.columns else df.columns[-1])

    X_df = df[feature_cols]
    y_raw = df[target_col]

    print(f"  -> So dac trung dau vao su dung (Full Features): {len(feature_cols)} dac trung (khong drop)")
    print(f"  -> Cot nhan muc tieu: '{target_col}' ({y_raw.nunique()} lop)")

    # Khởi tạo và fit preprocessor
    preprocessor = EdgeTrafficPreprocessor(feature_names=feature_cols)
    X_scaled, y_encoded = preprocessor.fit_transform(X_df, y_raw)

    if test_size is not None and test_size > 0:
        # Phân chia train/test với phân tầng stratify
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=test_size, random_state=random_state, stratify=y_encoded
        )
        print(f"  -> Tap huan luyen (Train): {X_train.shape[0]:,} mau")
        print(f"  -> Tap danh gia   (Test) : {X_test.shape[0]:,} mau")
        return X_train, X_test, y_train, y_test, preprocessor
    else:
        print(f"  -> Toan bo tap du lieu (Full Dataset): {X_scaled.shape[0]:,} mau")
        return X_scaled, None, y_encoded, None, preprocessor


def load_full_dataset(
    dataset_path: Optional[str] = None,
    sample_size: Optional[int] = None,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, EdgeTrafficPreprocessor]:
    """
    Nạp và tiền xử lý toàn bộ tập dữ liệu (không chia test split riêng).
    Toàn bộ dữ liệu được dùng cho Stratified K-Fold CV và train Final Model.
    """
    X, _, y, _, preprocessor = load_and_preprocess_dataset(
        dataset_path=dataset_path,
        sample_size=sample_size,
        test_size=0.0,
        random_state=random_state
    )
    return X, y, preprocessor
