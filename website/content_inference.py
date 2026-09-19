"""Lightweight runtime-only loading and inference for the email text model."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import pickle
import platform
import re

import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.naive_bayes import ComplementNB


ARTIFACT_SCHEMA = "phishguard-content-model-v1"
PIPELINE_KEYS = {"vectorizer", "clf", "decision_threshold", "metrics", "top_terms"}


def _major_minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def load_content_pipeline_artifact(path: Path | str, expected_sha256: str) -> dict:
    """Verify a trusted artifact before deserializing and validating it."""
    expected = (expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("A complete content-model SHA-256 digest is required")
    payload = Path(path).read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("Content-model SHA-256 digest does not match")

    envelope = pickle.loads(payload)
    if not isinstance(envelope, dict) or envelope.get("schema") != ARTIFACT_SCHEMA:
        raise ValueError("Unsupported content-model artifact schema")
    if envelope.get("python") != _major_minor(platform.python_version()):
        raise ValueError("Content-model artifact Python version is incompatible")
    if envelope.get("scikit_learn") != _major_minor(sklearn.__version__):
        raise ValueError("Content-model artifact scikit-learn version is incompatible")
    pipeline = envelope.get("pipeline")
    if not isinstance(pipeline, dict) or not PIPELINE_KEYS.issubset(pipeline):
        raise ValueError("Content-model artifact has an invalid pipeline payload")
    return pipeline


def _extract_coefficients(clf) -> np.ndarray | None:
    if hasattr(clf, "coef_"):
        coefficients = np.asarray(clf.coef_)
        return coefficients[0] if coefficients.ndim == 2 else coefficients
    if isinstance(clf, CalibratedClassifierCV):
        coefficients = []
        for calibrated in clf.calibrated_classifiers_:
            estimator = (
                getattr(calibrated, "estimator", None)
                or getattr(calibrated, "base_estimator", None)
            )
            if estimator is not None and hasattr(estimator, "coef_"):
                coefficients.append(np.asarray(estimator.coef_).ravel())
        if coefficients:
            return np.mean(coefficients, axis=0)
    if isinstance(clf, ComplementNB):
        feature_log_prob = clf.feature_log_prob_
        if feature_log_prob.shape[0] == 2:
            return feature_log_prob[1] - feature_log_prob[0]
    return None


def _flat_feature_names(vectorizer) -> np.ndarray:
    if hasattr(vectorizer, "transformer_list"):
        names: list[str] = []
        for name, transformer in vectorizer.transformer_list:
            if hasattr(transformer, "get_feature_names_out"):
                names.extend(
                    f"{name}:{term}" for term in transformer.get_feature_names_out()
                )
        return np.array(names)
    return np.array(vectorizer.get_feature_names_out())


def predict_content(pipeline: dict, subject: str, body: str) -> dict:
    """Score one subject/body pair and return bounded explainability details."""
    text = (subject or "") + "\n" + (body or "")
    features = pipeline["vectorizer"].transform([text])
    probabilities = pipeline["clf"].predict_proba(features)[0]
    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])
    threshold = float(pipeline.get("decision_threshold", 0.5))
    prediction = int(phishing_probability >= threshold)

    feature_names = _flat_feature_names(pipeline["vectorizer"])
    coefficients = _extract_coefficients(pipeline["clf"])
    contributors = []
    if coefficients is not None and len(coefficients) == len(feature_names):
        dense_features = features.toarray()[0]
        contributions = dense_features * coefficients
        pairs = []
        for index in np.nonzero(dense_features)[0]:
            if contributions[index] <= 0:
                continue
            name = str(feature_names[index])
            kind, _, term = name.partition(":")
            if kind == "word":
                pairs.append((term, float(contributions[index])))
        pairs.sort(key=lambda pair: pair[1], reverse=True)
        seen = set()
        for term, contribution in pairs:
            if any(term in prior and term != prior for prior in seen):
                continue
            seen.add(term)
            contributors.append({"term": term, "contribution": round(contribution, 4)})
            if len(contributors) >= 8:
                break

    return {
        "ml_phishing_probability": round(phishing_probability * 100, 1),
        "ml_legitimate_probability": round(legitimate_probability * 100, 1),
        "ml_label": "Likely Phishing" if prediction == 1 else "Likely Legitimate",
        "ml_prediction": prediction,
        "ml_decision_threshold": round(threshold * 100, 1),
        "ml_top_contributors": contributors,
    }
