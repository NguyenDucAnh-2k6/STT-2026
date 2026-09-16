"""
Feature Importance Visualizer & Extractor for Edge AI IDS.
Extracts ranked feature importances across Decision Trees, GBDTs, Linear models, and Neural Networks,
and produces high-resolution Dark Cyber SOC visualization charts.
"""

import os
import logging
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from typing import List, Dict, Any, Optional

logger = logging.getLogger("FeatureImportance")


def extract_feature_importance(model: Any, feature_names: List[str]) -> Optional[Dict[str, float]]:
    """
    Extracts numerical feature importance or weight magnitude for arbitrary models.
    Supports:
      - Sklearn / Tree models (RandomForest, ExtraTrees, DecisionTree, GBDT, etc.)
      - Linear models (LogisticRegression, Ridge, LinearSVC)
      - PyTorch DeepLearningClassifier (First-layer weight magnitude)
    """
    import numpy as np

    raw_model = model
    # Unwrap if wrapped inside custom classifier classes
    if hasattr(model, "model") and model.model is not None:
        raw_model = model.model

    importances = None

    # 1. Tree-based models
    if hasattr(raw_model, "feature_importances_"):
        importances = np.array(raw_model.feature_importances_)

    # 2. Linear models
    elif hasattr(raw_model, "coef_"):
        coef = np.array(raw_model.coef_)
        if coef.ndim > 1:
            importances = np.mean(np.abs(coef), axis=0)
        else:
            importances = np.abs(coef)

    # 3. PyTorch Deep Learning Models
    elif hasattr(raw_model, "parameters") or hasattr(raw_model, "named_parameters"):
        try:
            import torch
            # Find first linear layer weights
            first_linear_weights = None
            for name, param in raw_model.named_parameters():
                if "weight" in name and param.dim() == 2:
                    first_linear_weights = param.data.cpu().numpy()
                    break

            if first_linear_weights is not None:
                # Shape is (out_features, in_features).
                # Norm across output neurons gives the magnitude of incoming connectivity per input feature.
                importances = np.linalg.norm(first_linear_weights, axis=0)
        except Exception as e:
            logger.warning(f"Could not compute PyTorch weight norm: {e}")

    if importances is None or len(importances) == 0:
        return None

    # Normalize to [0, 1] sum or max
    total = np.sum(importances)
    if total > 0:
        norm_importances = importances / total
    else:
        norm_importances = importances

    # Align with feature names
    n_feat = min(len(feature_names), len(norm_importances))
    feat_map = {feature_names[i]: float(norm_importances[i]) for i in range(n_feat)}
    return feat_map


def plot_and_save_feature_importance(
    model: Any,
    feature_names: List[str],
    output_dir: str,
    top_n: int = 20,
    filename: str = "feature_importance.png"
) -> Optional[str]:
    """
    Extracts, ranks, and plots the Top N most influential features for the trained model.
    Saves the chart into output_dir/filename and returns the absolute file path.
    """
    feat_map = extract_feature_importance(model, feature_names)
    if not feat_map:
        logger.info("Feature importance extraction is not directly supported for this model architecture.")
        return None

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, filename)

    # Sort descending
    sorted_items = sorted(feat_map.items(), key=lambda x: x[1], reverse=True)[:top_n]
    # Reverse for horizontal bar chart (highest at the top)
    sorted_items = sorted_items[::-1]

    names = [k for k, v in sorted_items]
    scores = [v for k, v in sorted_items]

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, max(6, int(len(names) * 0.38))), facecolor='#0a0e1a')
    ax.set_facecolor('#121829')

    # Color gradient from cyan (#00f0ff) to cobalt blue (#3b82f6)
    cmap = plt.cm.cool
    norm = plt.Normalize(vmin=min(scores) * 0.8 if scores else 0, vmax=max(scores) if scores else 1)
    colors = [cmap(norm(s)) for s in scores]

    bars = ax.barh(names, scores, color=colors, height=0.65, edgecolor='#00f0ff', linewidth=0.8, alpha=0.9)

    # Annotate values
    max_score = max(scores) if scores else 1.0
    for bar, score in zip(bars, scores):
        ax.text(
            bar.get_width() + (max_score * 0.015),
            bar.get_y() + bar.get_height() / 2,
            f"{score:.4f}",
            va='center',
            ha='left',
            color='#94a3b8',
            fontsize=9,
            fontweight='bold'
        )

    ax.set_xlim(0, max_score * 1.15)
    ax.set_title(f"Top {len(names)} Most Influential Features (Feature Importance)", fontsize=13, fontweight='bold', color='#00f0ff', pad=15)
    ax.set_xlabel("Relative Importance Score (Normalized)", fontsize=10, color='#94a3b8', labelpad=10)
    ax.grid(axis='x', color='#2d3748', linestyle='--', alpha=0.5)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#2d3748')
    ax.spines['bottom'].set_color('#2d3748')
    ax.tick_params(colors='#94a3b8', labelsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()

    logger.info(f"Feature importance chart saved to: {out_path}")
    return out_path
