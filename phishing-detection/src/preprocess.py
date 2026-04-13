"""
preprocess.py
Data loading, cleaning, and preprocessing for the phishing detection pipeline.

The UCI Phishing Websites Dataset encodes most features as:
  -1  = phishing indicator
   0  = suspicious
   1  = legitimate indicator
Target column (Result): -1 = phishing, 1 = legitimate (remapped to 0/1).
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


# ── Feature names matching the UCI dataset (lowercase) ────────────────────────
UCI_FEATURE_NAMES = [
    "having_ip_address", "url_length", "shortining_service", "having_at_symbol",
    "double_slash_redirecting", "prefix_suffix", "having_sub_domain",
    "sslfinal_state", "domain_registration_length", "favicon", "port",
    "https_token", "request_url", "url_of_anchor", "links_in_tags", "sfh",
    "submitting_to_email", "abnormal_url", "redirect", "on_mouseover",
    "rightclick", "popupwindow", "iframe", "age_of_domain", "dnsrecord",
    "web_traffic", "page_rank", "google_index", "links_pointing_to_page",
    "statistical_report", "result",
]

# ── Grouped feature categories for Step 2 analysis ───────────────────────────
FEATURE_GROUPS = {
    "URL-based": [
        "having_ip_address", "url_length", "shortining_service",
        "having_at_symbol", "double_slash_redirecting", "prefix_suffix",
        "having_sub_domain", "https_token",
    ],
    "Domain-based": [
        "sslfinal_state", "domain_registration_length", "age_of_domain",
        "dnsrecord", "web_traffic", "page_rank", "google_index",
        "statistical_report",
    ],
    "HTML/Content-based": [
        "favicon", "port", "request_url", "url_of_anchor", "links_in_tags",
        "sfh", "submitting_to_email", "abnormal_url", "redirect",
        "on_mouseover", "rightclick", "popupwindow", "iframe",
        "links_pointing_to_page",
    ],
}


def load_from_ucimlrepo() -> pd.DataFrame:
    """Download the dataset directly from UCI ML Repository (requires ucimlrepo)."""
    from ucimlrepo import fetch_ucirepo
    print("Downloading UCI Phishing Websites dataset (ID=327)…")
    dataset = fetch_ucirepo(id=327)
    X = dataset.data.features
    y = dataset.data.targets
    df = pd.concat([X, y], axis=1)
    # Normalise to lowercase so downstream code has a single convention
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def load_from_csv(path: str) -> pd.DataFrame:
    """Load dataset from a local CSV file."""
    print(f"Loading dataset from {path}…")
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    return df


def generate_synthetic_dataset(n_samples: int = 11055, random_state: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic dataset that mimics the statistical distribution of
    the real UCI Phishing Websites dataset.  Used as a last-resort fallback
    so the notebook runs end-to-end even without an internet connection.
    """
    print(f"Generating synthetic phishing dataset with {n_samples} samples…")
    rng = np.random.RandomState(random_state)

    features = {}
    for col in UCI_FEATURE_NAMES[:-1]:          # exclude 'result'
        features[col] = rng.choice([-1, 0, 1], size=n_samples, p=[0.45, 0.10, 0.45])

    # Realistic class balance: ~55 % phishing (-1), 45 % legitimate (1)
    result = rng.choice([-1, 1], size=n_samples, p=[0.55, 0.45])
    features["result"] = result

    df = pd.DataFrame(features)

    # Inject correlations: phishing samples tend to have IP addresses / short domains
    phishing_mask = df["result"] == -1
    df.loc[phishing_mask, "having_ip_address"] = rng.choice(
        [-1, 0, 1], size=phishing_mask.sum(), p=[0.70, 0.05, 0.25]
    )
    df.loc[~phishing_mask, "sslfinal_state"] = rng.choice(
        [-1, 0, 1], size=(~phishing_mask).sum(), p=[0.10, 0.05, 0.85]
    )
    return df


def load_dataset(csv_path: str = None) -> pd.DataFrame:
    """
    Load the dataset with a three-step fallback strategy:
      1. Local CSV (if csv_path provided and file exists)
      2. ucimlrepo download
      3. Synthetic generation
    """
    if csv_path and os.path.exists(csv_path):
        return load_from_csv(csv_path)
    try:
        df = load_from_ucimlrepo()
        if csv_path:
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            df.to_csv(csv_path, index=False)
            print(f"Dataset saved to {csv_path}")
        return df
    except Exception as e:
        print(f"ucimlrepo download failed ({e}), using synthetic data.")
        df = generate_synthetic_dataset()
        if csv_path:
            os.makedirs(os.path.dirname(csv_path), exist_ok=True)
            df.to_csv(csv_path, index=False)
            print(f"Synthetic dataset saved to {csv_path}")
        return df


def preprocess(df: pd.DataFrame, target_col: str = "result", test_size: float = 0.2,
               random_state: int = 42):
    """
    Full preprocessing pipeline:
      - Drop rows with missing values
      - Separate features from target
      - Remap target: -1 → 0 (phishing), 1 → 1 (legitimate)
      - Train/test split (80/20)
      - StandardScaler normalization

    Returns
    -------
    X_train, X_test, y_train, y_test, scaler, feature_names
    """
    print(f"Raw shape: {df.shape}")

    # Drop missing values
    df = df.dropna()
    print(f"Shape after dropping NaN: {df.shape}")

    # Separate features and target
    feature_cols = [c for c in df.columns if c != target_col]
    X = df[feature_cols].copy()
    y = df[target_col].copy()

    # Remap labels to binary 0/1
    y = y.map({-1: 0, 1: 1}).fillna(y)
    y = y.astype(int)

    # Convert all feature columns to numeric (coerce any stray strings)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    print(f"Class distribution:\n{y.value_counts().to_string()}")
    print(f"  (0 = phishing, 1 = legitimate)")

    # Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Feature scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Convert back to DataFrames for downstream readability
    X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_cols)
    X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_cols)

    print(f"Train size: {X_train_scaled.shape[0]} | Test size: {X_test_scaled.shape[0]}")
    return X_train_scaled, X_test_scaled, y_train.reset_index(drop=True), \
           y_test.reset_index(drop=True), scaler, feature_cols
