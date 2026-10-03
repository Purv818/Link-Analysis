"""
preprocessing.py
----------------
Loads the raw URL dataset, applies feature extraction on every row,
handles missing values, removes duplicates, encodes labels, and
returns train/test splits ready for model training.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Local import — works both when run from project root and from src/
try:
    from src.feature_extraction import extract_features, get_feature_names
except ImportError:
    from feature_extraction import extract_features, get_feature_names

# ---------------------------------------------------------------------------
# Label mappings
# ---------------------------------------------------------------------------

LABEL_ORDER = ["safe", "suspicious", "phishing", "malicious"]

# Map text labels → integer class indices (consistent across train & predict)
LABEL_TO_INT = {label: idx for idx, label in enumerate(LABEL_ORDER)}
INT_TO_LABEL = {idx: label for label, idx in LABEL_TO_INT.items()}


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load the raw CSV containing 'url' and 'label' columns.
    Performs basic sanity checks and returns a clean DataFrame.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)

    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"CSV must contain columns: {required_cols}. "
                         f"Found: {list(df.columns)}")

    # Drop rows missing either URL or label
    before = len(df)
    df.dropna(subset=["url", "label"], inplace=True)

    # Strip whitespace
    df["url"]   = df["url"].str.strip()
    df["label"] = df["label"].str.strip().str.lower()

    # Remove exact duplicates
    df.drop_duplicates(subset=["url"], inplace=True)

    # Keep only recognised labels
    df = df[df["label"].isin(LABEL_ORDER)].copy()
    after = len(df)

    print(f"[preprocessing] Loaded {before} rows → {after} clean rows")
    print(f"[preprocessing] Label distribution:\n{df['label'].value_counts().to_string()}")

    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Feature extraction over the whole dataset
# ---------------------------------------------------------------------------

def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply extract_features() to every URL in the DataFrame.
    Returns a new DataFrame containing only the numeric feature columns.
    """
    print("[preprocessing] Extracting features for all URLs …")
    feature_rows = []
    for url in df["url"]:
        try:
            features = extract_features(url)
        except Exception as exc:
            # On failure fill with zeros so one bad row doesn't abort training
            print(f"  [warning] Feature extraction failed for '{url}': {exc}")
            features = {name: 0 for name in get_feature_names()}
        feature_rows.append(features)

    feature_df = pd.DataFrame(feature_rows)

    # Ensure consistent column ordering
    feature_names = get_feature_names()
    for col in feature_names:
        if col not in feature_df.columns:
            feature_df[col] = 0

    return feature_df[feature_names]


# ---------------------------------------------------------------------------
# Full preprocessing pipeline
# ---------------------------------------------------------------------------

def preprocess(csv_path: str,
               test_size: float = 0.20,
               random_state: int = 42):
    """
    End-to-end preprocessing pipeline.

    Returns
    -------
    X_train, X_test : pd.DataFrame
        Feature matrices.
    y_train, y_test : np.ndarray
        Integer-encoded label arrays.
    label_encoder : dict
        LABEL_TO_INT mapping for reference.
    feature_names : list[str]
        Ordered list of feature column names.
    df : pd.DataFrame
        Full cleaned DataFrame (for EDA / notebooks).
    """
    df = load_dataset(csv_path)

    X = build_feature_matrix(df)
    y = df["label"].map(LABEL_TO_INT).values

    # Verify no NaN slipped through
    if np.isnan(X.values).any():
        print("[preprocessing] Warning: NaN values detected — filling with 0")
        X = X.fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    print(f"[preprocessing] Train size: {len(X_train)} | Test size: {len(X_test)}")

    return X_train, X_test, y_train, y_test, LABEL_TO_INT, list(X.columns), df
