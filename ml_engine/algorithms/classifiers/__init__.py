"""
Attack Classifiers Package
==========================
Package chứa toàn bộ các thuật toán phân loại tấn công mạng (Multi-class Classification)
được module hóa rõ ràng:
- trees: Decision Tree, Random Forest, Extra Trees
- boosting: XGBoost, LightGBM, CatBoost, Gradient Boosting
- deep_learning: PyTorch Deep Learning (EdgeDeepNet DNN)
- linear: Logistic Regression
- ensemble: Ensemble Soft-Voting
"""

from typing import Dict, Any, List

from .trees import (
    DecisionTreeWrapper,
    RandomForestWrapper,
    ExtraTreesWrapper
)
from .boosting import (
    XGBoostWrapper,
    LightGBMWrapper,
    CatBoostWrapper,
    GradientBoostingWrapper
)
from .deep_learning import (
    EdgeDeepNet,
    PyTorchDeepWrapper
)
from .linear import (
    LogisticRegressionWrapper
)
from .ensemble import (
    EnsembleVotingWrapper
)
from ..base import BaseAttackClassifier


SUPPORTED_CLASSIFIERS: Dict[str, Dict[str, Any]] = {
    "decision_tree": {
        "class": DecisionTreeWrapper,
        "description": "Decision Tree (Nhẹ, tốc độ cao, hỗ trợ xuất C Header TinyML cho ESP32)",
        "edge_ready": True
    },
    "random_forest": {
        "class": RandomForestWrapper,
        "description": "Random Forest Ensemble (Độ chính xác cao, ổn định vượt trội trên dữ liệu nhiễu)",
        "edge_ready": False
    },
    "extra_trees": {
        "class": ExtraTreesWrapper,
        "description": "Extra Trees Classifier (Phân tán cực đại, huấn luyện đa luồng cực nhanh)",
        "edge_ready": False
    },
    "xgboost": {
        "class": XGBoostWrapper,
        "description": "XGBoost Classifier (GBDT đa luồng tối ưu, độ chính xác hàng đầu)",
        "edge_ready": False
    },
    "xgb": {
        "class": XGBoostWrapper,
        "description": "XGBoost Alias",
        "edge_ready": False
    },
    "lightgbm": {
        "class": LightGBMWrapper,
        "description": "LightGBM Classifier (Thuật toán Histogram GBDT siêu nhanh, tối ưu bộ nhớ)",
        "edge_ready": False
    },
    "lgb": {
        "class": LightGBMWrapper,
        "description": "LightGBM Alias",
        "edge_ready": False
    },
    "catboost": {
        "class": CatBoostWrapper,
        "description": "CatBoost Classifier (Chống overfitting rất mạnh trên dữ liệu bảng)",
        "edge_ready": False
    },
    "pytorch_deep": {
        "class": PyTorchDeepWrapper,
        "description": "PyTorch Deep Learning (Kiến trúc EdgeDeepNet DNN, in loss/acc epoch & vẽ loss curve)",
        "edge_ready": False
    },
    "dnn": {
        "class": PyTorchDeepWrapper,
        "description": "Deep Neural Network (Edge-IIoTset DNN)",
        "edge_ready": False
    },
    "mlp": {
        "class": PyTorchDeepWrapper,
        "description": "Deep Learning Alias (PyTorch Neural Network)",
        "edge_ready": False
    },
    "deep_learning": {
        "class": PyTorchDeepWrapper,
        "description": "Deep Learning Alias (PyTorch Neural Network)",
        "edge_ready": False
    },
    "gradient_boosting": {
        "class": GradientBoostingWrapper,
        "description": "Gradient Boosting (Scikit-Learn baseline)",
        "edge_ready": False
    },
    "logistic_regression": {
        "class": LogisticRegressionWrapper,
        "description": "Logistic Regression Baseline (Tuyến tính, suy luận siêu tốc)",
        "edge_ready": False
    },
    "ensemble_voting": {
        "class": EnsembleVotingWrapper,
        "description": "Ensemble Soft-Voting (Kết hợp RF + ExtraTrees + XGBoost)",
        "edge_ready": False
    }
}


def list_supported_classifiers() -> List[str]:
    """Trả về danh sách tên các model phân loại được hỗ trợ."""
    return [k for k in SUPPORTED_CLASSIFIERS.keys() if k not in ("xgb", "lgb", "mlp", "deep_learning", "dnn")]


def get_classifier(model_name: str, **kwargs) -> BaseAttackClassifier:
    """
    Factory khởi tạo bộ phân loại dựa vào tên.
    
    Parameters:
    -----------
    model_name : str
        Tên mô hình (vd: 'decision_tree', 'xgboost', 'lightgbm', 'catboost', 'pytorch_deep', 'dnn', v.v.)
    """
    key = model_name.lower().strip()
    if key not in SUPPORTED_CLASSIFIERS:
        supported = ", ".join(list_supported_classifiers())
        raise ValueError(f"Khong ho tro classifier: '{model_name}'. Danh sach ho tro: [{supported}]")
    cls = SUPPORTED_CLASSIFIERS[key]["class"]
    return cls(**kwargs)


__all__ = [
    "DecisionTreeWrapper",
    "RandomForestWrapper",
    "ExtraTreesWrapper",
    "XGBoostWrapper",
    "LightGBMWrapper",
    "CatBoostWrapper",
    "GradientBoostingWrapper",
    "EdgeDeepNet",
    "PyTorchDeepWrapper",
    "LogisticRegressionWrapper",
    "EnsembleVotingWrapper",
    "SUPPORTED_CLASSIFIERS",
    "list_supported_classifiers",
    "get_classifier",
]
