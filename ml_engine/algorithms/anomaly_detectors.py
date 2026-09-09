"""
Anomaly Detectors Collection
============================
Chỉ dẫn module:
- Module này triển khai các thuật toán phát hiện bất thường không giám sát (Unsupervised)
  hoặc phát hiện tính mới (Novelty Detection) trong lưu lượng mạng:
  1. 'isolation_forest': Phân lập điểm ngoại lai bằng cấu trúc cây nhị phân (Nhanh, hiệu quả cao).
  2. 'one_class_svm': Tìm ranh giới siêu phẳng hình cầu bao bọc không gian lưu lượng bình thường.
  3. 'elliptic_envelope': Giả định phân phối Gaussian đa biến, chống nhiễu bằng Robust Covariance.
  4. 'lof' (Local Outlier Factor): Đánh giá mật độ điểm cục bộ so với các láng giềng gần nhất (Novelty=True).
- Tất cả đều cung cấp phương thức `score_samples` tính toán điểm số bất thường.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor

from .base import BaseAnomalyDetector
from ..config.schema import DEFAULT_CONTAMINATION_RATE


class IsolationForestWrapper(BaseAnomalyDetector):
    """Mô hình Isolation Forest Anomaly Detector."""

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = DEFAULT_CONTAMINATION_RATE,
        random_state: int = 42,
        n_jobs: int = -1,
        **kwargs
    ):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=n_jobs,
            **kwargs
        )

    def fit(self, X_normal: np.ndarray) -> "IsolationForestWrapper":
        self.model.fit(X_normal)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    @property
    def underlying_estimator(self):
        return self.model


class OneClassSVMWrapper(BaseAnomalyDetector):
    """Mô hình One-Class SVM (RBF Kernel)."""

    def __init__(
        self,
        nu: float = DEFAULT_CONTAMINATION_RATE,
        kernel: str = "rbf",
        gamma: str = "scale",
        **kwargs
    ):
        self.model = OneClassSVM(
            nu=nu,
            kernel=kernel,
            gamma=gamma,
            **kwargs
        )

    def fit(self, X_normal: np.ndarray) -> "OneClassSVMWrapper":
        self.model.fit(X_normal)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        # OneClassSVM trả về decision_function (giá trị âm: ngoại lai, dương: bình thường)
        return self.model.decision_function(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    @property
    def underlying_estimator(self):
        return self.model


class EllipticEnvelopeWrapper(BaseAnomalyDetector):
    """Mô hình Elliptic Envelope (Robust Covariance Gaussian)."""

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION_RATE,
        random_state: int = 42,
        **kwargs
    ):
        self.model = EllipticEnvelope(
            contamination=contamination,
            random_state=random_state,
            **kwargs
        )

    def fit(self, X_normal: np.ndarray) -> "EllipticEnvelopeWrapper":
        self.model.fit(X_normal)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    @property
    def underlying_estimator(self):
        return self.model


class LocalOutlierFactorWrapper(BaseAnomalyDetector):
    """Mô hình Local Outlier Factor chế độ Novelty Detection."""

    def __init__(
        self,
        n_neighbors: int = 20,
        contamination: float = DEFAULT_CONTAMINATION_RATE,
        n_jobs: int = -1,
        **kwargs
    ):
        self.model = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination=contamination,
            novelty=True,
            n_jobs=n_jobs,
            **kwargs
        )

    def fit(self, X_normal: np.ndarray) -> "LocalOutlierFactorWrapper":
        self.model.fit(X_normal)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    @property
    def underlying_estimator(self):
        return self.model


SUPPORTED_ANOMALY_DETECTORS: Dict[str, Dict[str, Any]] = {
    "isolation_forest": {
        "class": IsolationForestWrapper,
        "description": "Isolation Forest (Phan lap cay ngau nhien, toi uu nhat cho mang)",
    },
    "one_class_svm": {
        "class": OneClassSVMWrapper,
        "description": "One-Class SVM (Kernel RBF phan dinh ranh gioi phi tuyen)",
    },
    "elliptic_envelope": {
        "class": EllipticEnvelopeWrapper,
        "description": "Elliptic Envelope (Mo hinh Robust Gaussian da bien)",
    },
    "lof": {
        "class": LocalOutlierFactorWrapper,
        "description": "Local Outlier Factor (Novelty Detection dua tren mat do lang gieng)",
    }
}


def list_supported_anomaly_detectors() -> List[str]:
    """Trả về danh sách tên các model phát hiện bất thường được hỗ trợ."""
    return list(SUPPORTED_ANOMALY_DETECTORS.keys())


def get_anomaly_detector(model_name: str, **kwargs) -> BaseAnomalyDetector:
    """
    Factory khởi tạo bộ phát hiện bất thường dựa vào tên.

    Parameters:
    -----------
    model_name : str
        Tên mô hình (vd: 'isolation_forest', 'one_class_svm', v.v.)
    """
    key = model_name.lower().strip()
    if key not in SUPPORTED_ANOMALY_DETECTORS:
        supported = ", ".join(SUPPORTED_ANOMALY_DETECTORS.keys())
        raise ValueError(f"Khong ho tro anomaly detector: '{model_name}'. Danh sach ho tro: [{supported}]")
    cls = SUPPORTED_ANOMALY_DETECTORS[key]["class"]
    return cls(**kwargs)
