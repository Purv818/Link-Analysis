"""
train_model.py
--------------
Trains multiple ML classifiers on the URL feature dataset,
evaluates them thoroughly, selects the best model, and saves
the trained model + feature configuration to disk.

Run from the project root:
    python -m src.train_model
or
    python src/train_model.py
"""

import os
import sys
import json
import warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")   # non-interactive backend for servers
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report, roc_curve, auc,
)
from sklearn.preprocessing import label_binarize

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Path setup — works whether invoked as a module or as a script
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.preprocessing import preprocess, INT_TO_LABEL, LABEL_ORDER

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_PATH     = os.path.join(PROJECT_ROOT, "data",   "urls.csv")
MODELS_DIR    = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH    = os.path.join(MODELS_DIR, "link_detection_model.pkl")
CONFIG_PATH   = os.path.join(MODELS_DIR, "feature_config.pkl")
REPORTS_DIR   = os.path.join(PROJECT_ROOT, "static", "reports")

os.makedirs(MODELS_DIR,  exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# XGBoost — optional
# ---------------------------------------------------------------------------
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("[train] XGBoost not available — skipping.")


# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------

def build_models(n_classes: int):
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42, class_weight="balanced"
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=10, random_state=42, class_weight="balanced"
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=15, random_state=42,
            class_weight="balanced", n_jobs=-1
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.1,
            max_depth=5, random_state=42
        ),
    }
    if XGBOOST_AVAILABLE:
        models["XGBoost"] = XGBClassifier(
            n_estimators=150, learning_rate=0.1, max_depth=5,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
        )
    return models


# ---------------------------------------------------------------------------
# Evaluation helper
# ---------------------------------------------------------------------------

def evaluate_model(model, X_test, y_test, class_names):
    y_pred   = model.predict(X_test)
    y_proba  = (model.predict_proba(X_test)
                if hasattr(model, "predict_proba") else None)

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted",
                                zero_division=0)
    recall    = recall_score(y_test, y_pred, average="weighted",
                             zero_division=0)
    f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    if y_proba is not None and len(np.unique(y_test)) > 1:
        try:
            roc_auc = roc_auc_score(
                label_binarize(y_test, classes=sorted(np.unique(y_test))),
                y_proba[:, :len(np.unique(y_test))],
                average="macro", multi_class="ovr"
            )
        except Exception:
            roc_auc = float("nan")
    else:
        roc_auc = float("nan")

    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred,
                                   target_names=class_names,
                                   zero_division=0)

    return {
        "accuracy":  round(accuracy,  4),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
        "roc_auc":   round(roc_auc,   4) if not np.isnan(roc_auc) else None,
        "confusion_matrix": cm,
        "classification_report": report,
        "y_pred": y_pred,
        "y_proba": y_proba,
    }


# ---------------------------------------------------------------------------
# Plotting helpers
# ---------------------------------------------------------------------------

def plot_confusion_matrix(cm, class_names, model_name, save_path):
    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names, ax=ax)
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=13)
    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(save_path, dpi=100)
    plt.close()


def plot_feature_importance(model, feature_names, save_path, top_n=20):
    """Works for tree-based models with feature_importances_ attribute."""
    if not hasattr(model, "feature_importances_"):
        return
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(
        [feature_names[i] for i in indices[::-1]],
        importances[indices[::-1]],
        color="#2563eb",
    )
    ax.set_title("Top Feature Importances", fontsize=13)
    ax.set_xlabel("Importance")
    plt.tight_layout()
    plt.savefig(save_path, dpi=100)
    plt.close()


def plot_model_comparison(results_df, save_path):
    metrics = ["accuracy", "precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(results_df))
    width = 0.2
    colors = ["#2563eb", "#16a34a", "#dc2626", "#d97706"]

    for i, metric in enumerate(metrics):
        ax.bar(x + i * width, results_df[metric], width, label=metric.capitalize(),
               color=colors[i])

    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(results_df["model"], rotation=15, ha="right")
    ax.set_ylim(0, 1.1)
    ax.set_title("Model Comparison", fontsize=13)
    ax.set_ylabel("Score")
    ax.legend()
    plt.tight_layout()
    plt.savefig(save_path, dpi=100)
    plt.close()


def plot_label_distribution(df, save_path):
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = {"safe": "#16a34a", "suspicious": "#d97706",
              "phishing": "#dc2626", "malicious": "#7c3aed"}
    counts = df["label"].value_counts()
    bars = ax.bar(counts.index, counts.values,
                  color=[colors.get(l, "#64748b") for l in counts.index])
    ax.set_title("Label Distribution in Dataset", fontsize=13)
    ax.set_ylabel("Count")
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                str(val), ha="center", va="bottom", fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=100)
    plt.close()


def plot_risk_score_distribution(df, feature_df, save_path):
    """Plot distribution of url_length as a proxy for complexity."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # URL length distribution by label
    for label in LABEL_ORDER:
        mask = df["label"] == label
        if mask.sum() == 0:
            continue
        lengths = feature_df.loc[mask.values, "url_length"]
        axes[0].hist(lengths, alpha=0.6, label=label, bins=20)
    axes[0].set_title("URL Length Distribution by Category")
    axes[0].set_xlabel("URL Length")
    axes[0].set_ylabel("Count")
    axes[0].legend()

    # Suspicious keyword count distribution
    for label in LABEL_ORDER:
        mask = df["label"] == label
        if mask.sum() == 0:
            continue
        kw_counts = feature_df.loc[mask.values, "suspicious_kw_count"]
        axes[1].hist(kw_counts, alpha=0.6, label=label, bins=10)
    axes[1].set_title("Suspicious Keyword Count by Category")
    axes[1].set_xlabel("Keyword Count")
    axes[1].set_ylabel("Count")
    axes[1].legend()

    plt.tight_layout()
    plt.savefig(save_path, dpi=100)
    plt.close()


# ---------------------------------------------------------------------------
# Model selection logic
# ---------------------------------------------------------------------------

def select_best_model(results: dict) -> str:
    """
    For cybersecurity detection we prioritise:
      1. F1-score (harmonic mean of precision + recall)
      2. ROC-AUC
      3. Recall (catching threats matters more than false-positive rate)

    Returns the name of the best model.
    """
    best_name  = None
    best_score = -1.0

    for name, metrics in results.items():
        # Combined score weighted toward recall for threat detection
        f1      = metrics.get("f1",      0) or 0
        roc_auc = metrics.get("roc_auc", 0) or 0
        recall  = metrics.get("recall",  0) or 0

        score = (0.45 * f1) + (0.30 * roc_auc) + (0.25 * recall)
        if score > best_score:
            best_score = score
            best_name  = name

    return best_name


# ---------------------------------------------------------------------------
# Main training entry point
# ---------------------------------------------------------------------------

def train():
    print("=" * 60)
    print("  AI Link Threat Detector — Model Training")
    print("=" * 60)

    # 1. Preprocess
    X_train, X_test, y_train, y_test, label_enc, feature_names, df = preprocess(
        DATA_PATH, test_size=0.20, random_state=42
    )
    class_names = [INT_TO_LABEL[i] for i in sorted(INT_TO_LABEL.keys())]
    n_classes   = len(class_names)

    # Plot label distribution
    plot_label_distribution(df, os.path.join(REPORTS_DIR, "label_distribution.png"))

    # Build feature_df aligned to df for plotting (use full X before split)
    from src.preprocessing import build_feature_matrix
    full_feature_df = build_feature_matrix(df)
    plot_risk_score_distribution(
        df, full_feature_df,
        os.path.join(REPORTS_DIR, "feature_distributions.png")
    )

    # 2. Train all models
    models  = build_models(n_classes)
    results = {}

    print(f"\n[train] Training {len(models)} models …\n")
    for name, model in models.items():
        print(f"  → Training {name} …")
        model.fit(X_train, y_train)
        metrics = evaluate_model(model, X_test, y_test, class_names)
        results[name] = metrics

        print(f"     Accuracy : {metrics['accuracy']:.4f}")
        print(f"     Precision: {metrics['precision']:.4f}")
        print(f"     Recall   : {metrics['recall']:.4f}")
        print(f"     F1-Score : {metrics['f1']:.4f}")
        if metrics["roc_auc"] is not None:
            print(f"     ROC-AUC  : {metrics['roc_auc']:.4f}")
        print()

        # Confusion matrix per model
        plot_confusion_matrix(
            metrics["confusion_matrix"], class_names, name,
            os.path.join(REPORTS_DIR, f"cm_{name.replace(' ', '_').lower()}.png")
        )

    # 3. Comparison table
    rows = []
    for name, m in results.items():
        rows.append({
            "model":     name,
            "accuracy":  m["accuracy"],
            "precision": m["precision"],
            "recall":    m["recall"],
            "f1":        m["f1"],
            "roc_auc":   m["roc_auc"] if m["roc_auc"] is not None else "N/A",
        })
    results_df = pd.DataFrame(rows)

    print("\n" + "=" * 60)
    print("  MODEL COMPARISON REPORT")
    print("=" * 60)
    print(results_df.to_string(index=False))
    print()

    # Save comparison as JSON for the web app
    results_df.to_json(
        os.path.join(REPORTS_DIR, "model_comparison.json"),
        orient="records", indent=2
    )

    # Plot comparison chart
    numeric_df = results_df[results_df["roc_auc"] != "N/A"].copy()
    numeric_df["roc_auc"] = numeric_df["roc_auc"].astype(float)
    plot_model_comparison(
        results_df[["model", "accuracy", "precision", "recall", "f1"]],
        os.path.join(REPORTS_DIR, "model_comparison.png")
    )

    # 4. Select best model
    best_name  = select_best_model(results)
    best_model = models[best_name]
    print(f"\n[train] Selected model: {best_name}")
    print(f"        Selection criteria: weighted F1 + ROC-AUC + Recall")
    print(f"\n[train] Classification Report ({best_name}):")
    print(results[best_name]["classification_report"])

    # Feature importance plot for the best model
    plot_feature_importance(
        best_model, feature_names,
        os.path.join(REPORTS_DIR, "feature_importance.png")
    )

    # 5. Save model + configuration
    joblib.dump(best_model, MODEL_PATH)

    feature_config = {
        "feature_names":  feature_names,
        "label_to_int":   {k: int(v) for k, v in
                           # rebuild from preprocessing module
                           zip(LABEL_ORDER, range(len(LABEL_ORDER)))},
        "int_to_label":   {str(i): l for i, l in enumerate(LABEL_ORDER)},
        "selected_model": best_name,
        "n_classes":      n_classes,
        "class_names":    class_names,
        "train_size":     len(X_train),
        "test_size":      len(X_test),
        "metrics": {
            k: {mk: mv for mk, mv in v.items()
                if mk not in ("confusion_matrix",
                              "classification_report",
                              "y_pred", "y_proba")}
            for k, v in results.items()
        },
    }
    joblib.dump(feature_config, CONFIG_PATH)

    print(f"\n[train] Model saved  → {MODEL_PATH}")
    print(f"[train] Config saved → {CONFIG_PATH}")
    print("[train] Training complete.\n")

    return best_model, feature_config


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    train()
