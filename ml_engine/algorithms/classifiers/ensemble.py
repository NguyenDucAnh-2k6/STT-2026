"""
Ensemble Classifiers Module
===========================
Triển khai mô hình kết hợp (Ensemble Voting) đa thuật toán.
"""

from typing import Optional, Any
import numpy as np
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    VotingClassifier
)

from ..base import BaseAttackClassifier


class EnsembleVotingWrapper(BaseAttackClassifier):
    """Mô hình Ensemble Soft-Voting kết hợp Random Forest + Extra Trees + XGBoost siêu tốc."""

    def __init__(
        self,
        rf_n_estimators: int = 80,
        rf_max_depth: int = 10,
        et_n_estimators: int = 80,
        et_max_depth: int = 10,
        xgb_n_estimators: int = 60,
        xgb_max_depth: int = 5,
        xgb_learning_rate: float = 0.1,
        random_state: int = 42,
        **kwargs
    ):
        import xgboost as xgb
        self.model = VotingClassifier(
            estimators=[
                ('rf', RandomForestClassifier(n_estimators=rf_n_estimators, max_depth=rf_max_depth, random_state=random_state, n_jobs=-1)),
                ('et', ExtraTreesClassifier(n_estimators=et_n_estimators, max_depth=et_max_depth, random_state=random_state, n_jobs=-1)),
                ('xgb', xgb.XGBClassifier(n_estimators=xgb_n_estimators, max_depth=xgb_max_depth, learning_rate=xgb_learning_rate, eval_metric="mlogloss", random_state=random_state, n_jobs=-1))
            ],
            voting='soft'
        )

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "EnsembleVotingWrapper":
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
