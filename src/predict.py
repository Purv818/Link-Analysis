"""
predict.py
----------
Loads the trained model and provides a single predict() function
that accepts a raw URL string and returns a structured prediction result.
"""

import os
import sys
import threading
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.feature_extraction import extract_features, get_human_readable_flags
from src.explain import explain as _explain

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MODEL_PATH  = os.path.join(PROJECT_ROOT, "models", "link_detection_model.pkl")
CONFIG_PATH = os.path.join(PROJECT_ROOT, "models", "feature_config.pkl")

# ---------------------------------------------------------------------------
# Module-level cache — loaded once on first use
# ---------------------------------------------------------------------------
_model          = None
_feature_config = None
_cache_lock      = threading.Lock()


def _load_artifacts():
    """Load model and feature config from disk (cached after first call, thread-safe)."""
    global _model, _feature_config

    with _cache_lock:
        if _model is None or _feature_config is None:
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(
                    f"Trained model not found at '{MODEL_PATH}'. "
                    "Please run: python -m src.train_model"
                )
            if not os.path.exists(CONFIG_PATH):
                raise FileNotFoundError(
                    f"Feature config not found at '{CONFIG_PATH}'. "
                    "Please run: python -m src.train_model"
                )
            _model          = joblib.load(MODEL_PATH)
            _feature_config = joblib.load(CONFIG_PATH)

    return _model, _feature_config


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def _compute_risk_score(probabilities: np.ndarray,
                        int_to_label: dict) -> int:
    """
    Derive a 0–100 risk score from class probabilities.

    Weights: safe=0, suspicious=40, phishing=80, malicious=100
    Risk = weighted average of class probabilities × 100
    """
    weights = {
        "safe":       0,
        "suspicious": 40,
        "phishing":   80,
        "malicious":  100,
    }
    score = 0.0
    for idx, prob in enumerate(probabilities):
        label = int_to_label.get(str(idx), "safe")
        score += prob * weights.get(label, 0)

    return min(100, max(0, round(score)))


def _risk_level(score: int) -> str:
    if score <= 30:
        return "Low Risk"
    elif score <= 60:
        return "Medium Risk"
    elif score <= 80:
        return "High Risk"
    else:
        return "Critical Risk"


# ---------------------------------------------------------------------------
# Public prediction interface
# ---------------------------------------------------------------------------

def predict(url: str) -> dict:
    """
    Perform full static analysis on a URL and return a structured result.

    Parameters
    ----------
    url : str
        The raw URL string submitted by the user.

    Returns
    -------
    dict with keys:
        url            : original URL
        prediction     : "SAFE" | "SUSPICIOUS" | "PHISHING" | "MALICIOUS"
        risk_score     : 0–100 integer
        risk_level     : descriptive risk level string
        confidence     : float 0–1 (highest class probability)
        probabilities  : dict {label: probability}
        features       : dict of extracted numeric features
        explanation    : list of human-readable flag strings
        model_name     : name of the model that made the prediction
    """
    model, config = _load_artifacts()
    feature_names  = config["feature_names"]
    int_to_label   = config["int_to_label"]   # {"0": "safe", ...}

    # 1. Extract features
    features_dict = extract_features(url)

    # 2. Build the feature vector as a DataFrame to preserve column names
    #    (avoids sklearn "feature names" warning and ensures column alignment)
    feature_vector = pd.DataFrame(
        [[features_dict.get(name, 0) for name in feature_names]],
        columns=feature_names,
        dtype=float,
    )

    # 3. Predict
    predicted_int = int(model.predict(feature_vector)[0])
    predicted_label = int_to_label.get(str(predicted_int), "safe")

    # 4. Probabilities
    if hasattr(model, "predict_proba"):
        proba_array  = model.predict_proba(feature_vector)[0]
    else:
        # Fallback for models without probability output
        proba_array = np.zeros(len(int_to_label))
        proba_array[predicted_int] = 1.0

    probabilities = {
        int_to_label.get(str(i), str(i)): round(float(p), 4)
        for i, p in enumerate(proba_array)
    }

    confidence  = round(float(np.max(proba_array)), 4)
    risk_score  = _compute_risk_score(proba_array, int_to_label)
    level       = _risk_level(risk_score)

    # 5. Human-readable explanation flags (rule-based)
    explanation = get_human_readable_flags(features_dict)

    # 6. Feature-importance contributions (tree model or SHAP)
    try:
        explain_result = _explain(
            model        = model,
            feature_vector = feature_vector,
            features_dict  = features_dict,
            feature_names  = feature_names,
            predicted_class_idx = predicted_int,
            top_n        = 8,
        )
        contributions = explain_result.get("contributions", [])
        explain_method = explain_result.get("method", "rule_based")
    except Exception:
        contributions  = []
        explain_method = "rule_based"

    return {
        "url":           url,
        "prediction":    predicted_label.upper(),
        "risk_score":    risk_score,
        "risk_level":    level,
        "confidence":    confidence,
        "probabilities": probabilities,
        "features":      features_dict,
        "explanation":   explanation,
        "contributions": contributions,
        "explain_method": explain_method,
        "model_name":    config.get("selected_model", "Unknown"),
    }


def model_is_ready() -> bool:
    """Return True if both the model and config files exist on disk."""
    return os.path.exists(MODEL_PATH) and os.path.exists(CONFIG_PATH)
