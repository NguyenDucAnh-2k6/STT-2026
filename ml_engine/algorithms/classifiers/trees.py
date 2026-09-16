"""
Tree-Based Classifiers Module
=============================
Triển khai các mô hình phân loại dựa trên cây quyết định:
1. DecisionTreeWrapper: Mô hình cực nhẹ, hỗ trợ xuất C Header TinyML cho ESP32.
2. RandomForestWrapper: Rừng cây ngẫu nhiên chống quá khớp cao.
3. ExtraTreesWrapper: Cây ngẫu nhiên cực độ, huấn luyện đa luồng cực nhanh.
"""

from typing import Optional, Any
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier

from ..base import BaseAttackClassifier


class DecisionTreeWrapper(BaseAttackClassifier):
    """Mô hình Decision Tree - Hỗ trợ chuyển đổi sang C Header cho ESP32."""

    def __init__(
        self,
        max_depth: int = 16,
        min_samples_split: int = 6,
        min_samples_leaf: int = 2,
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

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "DecisionTreeWrapper":
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
    def underlying_estimator(self) -> Any:
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

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "RandomForestWrapper":
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
    def underlying_estimator(self) -> Any:
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

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "ExtraTreesWrapper":
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
    def underlying_estimator(self) -> Any:
        return self.model
