"""
explain.py
----------
Explainability layer for the link threat detector.

Two explanation strategies:
  1. Feature-contribution explanation using the model's internal
     feature importances (works for tree-based models).
  2. Rule-based flag explanation using get_human_readable_flags()
     (works for every model type as a fallback).

For tree-based models both strategies are combined to give the most
informative result.  For linear models, the coefficient-based approach
is used instead.

No SHAP dependency is required — SHAP is used opportunistically when
available, otherwise the built-in strategies provide a clear and
accurate explanation.
"""

import os
import sys
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extraction import get_human_readable_flags

# Optional SHAP import
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


# ---------------------------------------------------------------------------
# Contribution-based explanation (tree models)
# ---------------------------------------------------------------------------

def _get_fv_numpy(feature_vector):
    """Convert a feature_vector (DataFrame or ndarray) to a 2D numpy array."""
    if isinstance(feature_vector, pd.DataFrame):
        return feature_vector.values
    return np.atleast_2d(feature_vector)


def _tree_feature_contributions(model, feature_vector,
                                 feature_names: list,
                                 top_n: int = 8) -> list:
    """
    Use the model's feature_importances_ as a proxy for contribution.
    Returns list of dicts: {feature, value, importance, direction}
    """
    if not hasattr(model, "feature_importances_"):
        return []

    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1][:top_n]
    fv_np       = _get_fv_numpy(feature_vector)

    contributions = []
    for idx in indices:
        fname = feature_names[idx]
        fval  = float(fv_np[0, idx])
        imp   = float(importances[idx])

        # Direction: positive values on suspicious features raise risk
        # Negative features (like uses_https) lower risk
        direction = "increases" if fval > 0 else "neutral"
        if fname == "uses_https" and fval > 0:
            direction = "decreases"

        contributions.append({
            "feature":    fname,
            "value":      round(fval, 4),
            "importance": round(imp, 4),
            "direction":  direction,
        })

    return contributions


# ---------------------------------------------------------------------------
# SHAP-based explanation (optional, best quality)
# ---------------------------------------------------------------------------

def _shap_explanation(model, feature_vector: np.ndarray,
                      feature_names: list,
                      predicted_class_idx: int,
                      top_n: int = 8) -> list:
    """
    Use SHAP TreeExplainer to get exact Shapley values.
    Returns list of dicts sorted by |shap_value|.
    """
    if not SHAP_AVAILABLE:
        return []

    try:
        explainer  = shap.TreeExplainer(model)
        fv_np      = _get_fv_numpy(feature_vector)
        shap_vals  = explainer.shap_values(fv_np)

        # shap_values shape: (n_classes, n_samples, n_features) or
        # (n_samples, n_features) for binary
        if isinstance(shap_vals, list):
            # Multi-class: take values for the predicted class
            idx = min(predicted_class_idx, len(shap_vals) - 1)
            vals = shap_vals[idx][0]
        else:
            vals = shap_vals[0]

        sorted_indices = np.argsort(np.abs(vals))[::-1][:top_n]
        contributions  = []
        for i in sorted_indices:
            fv_np = _get_fv_numpy(feature_vector)
            contributions.append({
                "feature":    feature_names[i],
                "value":      round(float(fv_np[0, i]), 4),
                "shap_value": round(float(vals[i]), 4),
                "direction":  "increases" if vals[i] > 0 else "decreases",
            })
        return contributions

    except Exception:
        return []


# ---------------------------------------------------------------------------
# Linear model explanation
# ---------------------------------------------------------------------------

def _linear_feature_contributions(model, feature_vector: np.ndarray,
                                   feature_names: list,
                                   predicted_class_idx: int,
                                   top_n: int = 8) -> list:
    """
    Use model coefficients × feature values as contribution scores.
    """
    if not hasattr(model, "coef_"):
        return []

    try:
        coef = model.coef_
        if coef.ndim == 2:
            # Multi-class — take coefficients for predicted class
            idx  = min(predicted_class_idx, coef.shape[0] - 1)
            coef = coef[idx]

        fv_np             = _get_fv_numpy(feature_vector)
        contributions_raw = coef * fv_np[0]
        sorted_indices    = np.argsort(np.abs(contributions_raw))[::-1][:top_n]

        contributions = []
        for i in sorted_indices:
            contributions.append({
                "feature":    feature_names[i],
                "value":      round(float(fv_np[0, i]), 4),
                "importance": round(float(abs(contributions_raw[i])), 6),
                "direction":  "increases" if contributions_raw[i] > 0 else "decreases",
            })
        return contributions

    except Exception:
        return []


# ---------------------------------------------------------------------------
# Public explain interface
# ---------------------------------------------------------------------------

def explain(model, feature_vector: np.ndarray,
            features_dict: dict,
            feature_names: list,
            predicted_class_idx: int,
            top_n: int = 8) -> dict:
    """
    Generate a comprehensive explanation for a single prediction.

    Parameters
    ----------
    model               : fitted sklearn / XGBoost model
    feature_vector      : (1, n_features) numpy array
    features_dict       : raw feature dict from extract_features()
    feature_names       : ordered list of feature names
    predicted_class_idx : integer index of the predicted class
    top_n               : number of top features to return

    Returns
    -------
    dict with keys:
        method          : "shap" | "tree_importance" | "linear" | "rule_based"
        contributions   : list of feature contribution dicts
        flags           : list of human-readable flag strings
        summary         : one-line summary string
    """
    contributions = []
    method        = "rule_based"

    # Try SHAP first (highest fidelity, tree models)
    if SHAP_AVAILABLE and hasattr(model, "feature_importances_"):
        contributions = _shap_explanation(
            model, feature_vector, feature_names, predicted_class_idx, top_n
        )
        if contributions:
            method = "shap"

    # Fallback: tree feature importances
    if not contributions and hasattr(model, "feature_importances_"):
        contributions = _tree_feature_contributions(
            model, feature_vector, feature_names, top_n
        )
        if contributions:
            method = "tree_importance"

    # Fallback: linear coefficients
    if not contributions and hasattr(model, "coef_"):
        contributions = _linear_feature_contributions(
            model, feature_vector, feature_names, predicted_class_idx, top_n
        )
        if contributions:
            method = "linear"

    # Always include rule-based flags regardless of method
    flags = get_human_readable_flags(features_dict)

    # Build a one-line summary
    top_features = [c["feature"].replace("_", " ")
                    for c in contributions[:3]] if contributions else []
    if top_features:
        summary = f"Top contributing factors: {', '.join(top_features)}"
    elif flags:
        summary = flags[0]
    else:
        summary = "No strong risk indicators detected."

    return {
        "method":        method,
        "contributions": contributions,
        "flags":         flags,
        "summary":       summary,
    }
