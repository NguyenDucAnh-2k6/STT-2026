"""
Attack Classifiers Collection
==============================
Chỉ dẫn module:
- Module này chứa triển khai các thuật toán phân loại dạng tấn công mạng (Multi-class Classification):
  1. 'decision_tree': Cây quyết định cực nhẹ, giải thích rõ ràng, hỗ trợ xuất trực tiếp ra mã nguồn C (TinyML).
  2. 'random_forest': Bộ rừng ngẫu nhiên ổn định cao, chống quá khớp (overfitting) tốt trên dữ liệu nhiễu.
  3. 'extra_trees': Cây ngẫu nhiên mở rộng, tốc độ huấn luyện nhanh và phương sai thấp.
  4. 'gradient_boosting': Tăng cường độ chính xác cao bằng cơ chế học chuỗi cây phần dư.
  5. 'mlp': Multi-Layer Perceptron (Mạng nơ-ron truyền thẳng) nắm bắt quan hệ phi tuyến phức tạp.
  6. 'logistic_regression': Mô hình tuyến tính tốc độ cao làm baseline đối chiếu.
- Sử dụng hàm factory `get_classifier(name, **kwargs)` để khởi tạo mô hình theo cờ tham số (CLI flag).
"""

from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    VotingClassifier
)
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression

from .base import BaseAttackClassifier


class DecisionTreeWrapper(BaseAttackClassifier):
    """Mô hình Decision Tree - Hỗ trợ chuyển đổi sang C Header cho ESP32."""

    def __init__(
        self,
        max_depth: int = 6,
        min_samples_split: int = 5,
        min_samples_leaf: int = 3,
        random_state: int = 42,
        **kwargs
    ):
        self.model = DecisionTreeClassifier(
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            min_samples_leaf=min_samples_leaf,
            random_state=random_state,
            **kwargs
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "DecisionTreeWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return True

    @property
    def underlying_estimator(self):
        return self.model


class RandomForestWrapper(BaseAttackClassifier):
    """Mô hình Random Forest - Khả năng tổng quát hóa cao."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 12,
        random_state: int = 42,
        n_jobs: int = -1,
        **kwargs
    ):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=n_jobs,
            **kwargs
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "RandomForestWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


class ExtraTreesWrapper(BaseAttackClassifier):
    """Mô hình Extra Trees - Extremely Randomized Trees."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 12,
        random_state: int = 42,
        n_jobs: int = -1,
        **kwargs
    ):
        self.model = ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=n_jobs,
            **kwargs
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "ExtraTreesWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


class GradientBoostingWrapper(BaseAttackClassifier):
    """Mô hình Gradient Boosting Classifier."""

    def __init__(
        self,
        n_estimators: int = 80,
        learning_rate: float = 0.1,
        max_depth: int = 5,
        random_state: int = 42,
        **kwargs
    ):
        self.model = GradientBoostingClassifier(
            n_estimators=n_estimators,
            learning_rate=learning_rate,
            max_depth=max_depth,
            random_state=random_state,
            **kwargs
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "GradientBoostingWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


class MLPWrapper(BaseAttackClassifier):
    """Mo hinh Multi-Layer Perceptron (Neural Network dang nhe, tu dong chuan hoa input)."""

    def __init__(
        self,
        hidden_layer_sizes: tuple = (64, 32),
        max_iter: int = 300,
        random_state: int = 42,
        **kwargs
    ):
        self.model = make_pipeline(
            StandardScaler(),
            MLPClassifier(
                hidden_layer_sizes=hidden_layer_sizes,
                max_iter=max_iter,
                random_state=random_state,
                **kwargs
            )
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "MLPWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


class LogisticRegressionWrapper(BaseAttackClassifier):
    """Mô hình hồi quy Logistic đa biến (Linear Baseline)."""

    def __init__(
        self,
        max_iter: int = 1000,
        random_state: int = 42,
        **kwargs
    ):
        self.model = LogisticRegression(
            max_iter=max_iter,
            random_state=random_state,
            **kwargs
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticRegressionWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


class EnsembleVotingWrapper(BaseAttackClassifier):
    """Mo hinh Ensemble Soft-Voting ket hop da thuat toan giam thieu phuong sai (Variance Reduction)."""

    def __init__(
        self,
        rf_n_estimators: int = 80,
        rf_max_depth: int = 10,
        et_n_estimators: int = 80,
        et_max_depth: int = 10,
        gb_n_estimators: int = 60,
        gb_max_depth: int = 4,
        gb_learning_rate: float = 0.1,
        random_state: int = 42,
        **kwargs
    ):
        self.model = VotingClassifier(
            estimators=[
                ('rf', RandomForestClassifier(n_estimators=rf_n_estimators, max_depth=rf_max_depth, random_state=random_state, n_jobs=-1)),
                ('et', ExtraTreesClassifier(n_estimators=et_n_estimators, max_depth=et_max_depth, random_state=random_state, n_jobs=-1)),
                ('gb', GradientBoostingClassifier(n_estimators=gb_n_estimators, max_depth=gb_max_depth, learning_rate=gb_learning_rate, random_state=random_state))
            ],
            voting='soft'
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "EnsembleVotingWrapper":
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self):
        return self.model


SUPPORTED_CLASSIFIERS: Dict[str, Dict[str, Any]] = {
    "decision_tree": {
        "class": DecisionTreeWrapper,
        "description": "Decision Tree (Nhe, toc do cao, ho tro xuat C code TinyML)",
        "edge_ready": True
    },
    "random_forest": {
        "class": RandomForestWrapper,
        "description": "Random Forest Ensemble (Do chinh xac cao, on dinh vuot troi)",
        "edge_ready": False
    },
    "extra_trees": {
        "class": ExtraTreesWrapper,
        "description": "Extra Trees Classifier (Phan tan cuc dai, huan luyen cuc nhanh)",
        "edge_ready": False
    },
    "gradient_boosting": {
        "class": GradientBoostingWrapper,
        "description": "Gradient Boosting (Kha nang phan loai mau bien gioi rat manh)",
        "edge_ready": False
    },
    "mlp": {
        "class": MLPWrapper,
        "description": "Multi-Layer Perceptron (Neural Network phan loai phi tuyen)",
        "edge_ready": False
    },
    "logistic_regression": {
        "class": LogisticRegressionWrapper,
        "description": "Logistic Regression Baseline (Nhe, don gian, suy luan sieu toc)",
        "edge_ready": False
    },
    "ensemble_voting": {
        "class": EnsembleVotingWrapper,
        "description": "Ensemble Soft-Voting (Ket hop RF + ExtraTrees + GradientBoosting giam thieu variance)",
        "edge_ready": False
    }
}


def list_supported_classifiers() -> List[str]:
    """Trả về danh sách tên các model phân loại được hỗ trợ."""
    return list(SUPPORTED_CLASSIFIERS.keys())


def get_classifier(model_name: str, **kwargs) -> BaseAttackClassifier:
    """
    Factory khởi tạo bộ phân loại dựa vào tên.
    
    Parameters:
    -----------
    model_name : str
        Tên mô hình (vd: 'decision_tree', 'random_forest', v.v.)
    """
    key = model_name.lower().strip()
    if key not in SUPPORTED_CLASSIFIERS:
        supported = ", ".join(SUPPORTED_CLASSIFIERS.keys())
        raise ValueError(f"Khong ho tro classifier: '{model_name}'. Danh sach ho tro: [{supported}]")
    cls = SUPPORTED_CLASSIFIERS[key]["class"]
    return cls(**kwargs)
