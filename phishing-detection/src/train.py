"""
train.py
Model definitions, training, and prediction for the phishing detection pipeline.

Classifiers
-----------
1. Logistic Regression  – linear baseline
2. Random Forest        – ensemble, provides feature importances
3. Support Vector Machine (RBF kernel) – strong non-linear classifier
4. Decision Tree        – interpretable single-tree model (bonus)
"""

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier


def build_models() -> dict:
    """
    Return a dict of {name: unfitted_estimator} for all four classifiers.
    Hyperparameters are set according to the project specification.
    """
    models = {
        "Logistic Regression": LogisticRegression(
            solver="lbfgs",
            max_iter=1000,
            random_state=42,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        ),
        "SVM": SVC(
            kernel="rbf",
            C=1.0,
            probability=True,   # needed for ROC AUC / predict_proba
            random_state=42,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=10,
            random_state=42,
        ),
    }
    return models


def train_all(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict:
    """
    Fit every classifier on the training set and collect predictions /
    probabilities on the test set.

    Parameters
    ----------
    X_train, y_train : training features and labels
    X_test,  y_test  : test features and labels

    Returns
    -------
    results : dict keyed by classifier name, each value is a dict with:
        - "model"       : fitted estimator
        - "y_pred"      : hard predictions on X_test
        - "y_prob"      : predicted probabilities for the positive class
    """
    models = build_models()
    results = {}

    for name, clf in models.items():
        print(f"Training {name}…", end=" ", flush=True)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        # All classifiers support predict_proba (SVC has probability=True)
        y_prob = clf.predict_proba(X_test)[:, 1]

        results[name] = {
            "model": clf,
            "y_pred": y_pred,
            "y_prob": y_prob,
        }
        print("done.")

    return results


def get_feature_importances(results: dict, feature_names: list) -> pd.DataFrame:
    """
    Extract feature importances from the Random Forest classifier.

    Returns a DataFrame sorted by importance (descending).
    """
    rf = results["Random Forest"]["model"]
    importances = rf.feature_importances_
    df = pd.DataFrame(
        {"Feature": feature_names, "Importance": importances}
    ).sort_values("Importance", ascending=False).reset_index(drop=True)
    return df
