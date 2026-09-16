"""
Gradient Boosting Classifiers Module
====================================
Triển khai các mô hình Gradient Boosted Decision Trees (GBDT) hiện đại:
1. XGBoostWrapper: GBDT đa luồng tối ưu bộ nhớ, hiệu năng hàng đầu.
2. LightGBMWrapper: Histogram GBDT siêu nhanh, tối ưu tập dữ liệu lớn.
3. CatBoostWrapper: Khả năng chống overfitting mạnh mẽ trên dữ liệu bảng/mạng.
4. GradientBoostingWrapper: Sklearn Gradient Boosting truyền thống (baseline đối chiếu).
"""

from typing import Optional, Any
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

from ..base import BaseAttackClassifier


class XGBoostWrapper(BaseAttackClassifier):
    """Mô hình XGBoost Classifier - Đa luồng hiệu năng cao."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        random_state: int = 42,
        n_jobs: int = -1,
        **kwargs
    ):
        import xgboost as xgb
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            eval_metric="mlogloss",
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
    ) -> "XGBoostWrapper":
        if X_val is not None and y_val is not None:
            self.model.fit(X, y, eval_set=[(X_val, y_val)], verbose=False)
        else:
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


class LightGBMWrapper(BaseAttackClassifier):
    """Mô hình LightGBM Classifier - Tốc độ huấn luyện siêu tốc độ."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 8,
        num_leaves: int = 31,
        learning_rate: float = 0.1,
        subsample: float = 0.8,
        random_state: int = 42,
        n_jobs: int = -1,
        verbose: int = -1,
        **kwargs
    ):
        import lightgbm as lgb
        self.model = lgb.LGBMClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            num_leaves=num_leaves,
            learning_rate=learning_rate,
            subsample=subsample,
            random_state=random_state,
            n_jobs=n_jobs,
            verbose=verbose,
            **kwargs
        )

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "LightGBMWrapper":
        if X_val is not None and y_val is not None:
            self.model.fit(X, y, eval_set=[(X_val, y_val)])
        else:
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


class CatBoostWrapper(BaseAttackClassifier):
    """Mô hình CatBoost Classifier - Xử lý đặc trưng số liệu mượt mà, chống overfitting tốt."""

    def __init__(
        self,
        iterations: int = 100,
        depth: int = 6,
        learning_rate: float = 0.1,
        l2_leaf_reg: float = 3.0,
        random_seed: int = 42,
        verbose: int = 0,
        thread_count: int = -1,
        **kwargs
    ):
        from catboost import CatBoostClassifier
        self.model = CatBoostClassifier(
            iterations=iterations,
            depth=depth,
            learning_rate=learning_rate,
            l2_leaf_reg=l2_leaf_reg,
            random_seed=random_seed,
            verbose=verbose,
            thread_count=thread_count,
            **kwargs
        )

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "CatBoostWrapper":
        if X_val is not None and y_val is not None:
            self.model.fit(X, y, eval_set=(X_val, y_val), verbose=0)
        else:
            self.model.fit(X, y, verbose=0)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X).ravel()

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    @property
    def can_export_tinyml(self) -> bool:
        return False

    @property
    def underlying_estimator(self) -> Any:
        return self.model


class GradientBoostingWrapper(BaseAttackClassifier):
    """Mô hình Gradient Boosting Classifier (Scikit-Learn - Legacy Baseline)."""

    def __init__(
        self,
        n_estimators: int = 60,
        learning_rate: float = 0.1,
        max_depth: int = 4,
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

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        **kwargs
    ) -> "GradientBoostingWrapper":
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
