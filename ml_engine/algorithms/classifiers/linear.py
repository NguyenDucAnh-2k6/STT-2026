"""
Linear Baseline Classifiers Module
==================================
Triển khai mô hình hồi quy tuyến tính Logistic Regression làm baseline phân loại.
"""

from typing import Optional, Any
import numpy as np
from sklearn.linear_model import LogisticRegression

from ..base import BaseAttackClassifier


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

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "LogisticRegressionWrapper":
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
