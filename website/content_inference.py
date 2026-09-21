"""Lightweight runtime-only loading and inference for the email text model."""

from __future__ import annotations

import hashlib
import hmac
from html import unescape
from pathlib import Path
import pickle
import platform
import re
import warnings

import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.naive_bayes import ComplementNB
from language_coverage import non_latin_script_segments
from model_environment import validate_runtime_package_versions


ARTIFACT_SCHEMA = "phishguard-content-model-v1"
PIPELINE_KEYS = {"vectorizer", "clf", "decision_threshold", "metrics", "top_terms"}
MIN_MODEL_CONTEXT_TOKENS = 5
MIN_MODEL_CONTEXT_NONSPACE_CHARS = 40
MIN_SUBSTANTIAL_BODY_CHARS = 40
MIN_UNCOVERED_SCRIPT_LETTERS = 12


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

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            envelope = pickle.loads(payload)
    except InconsistentVersionWarning as exc:
        raise ValueError(
            "Content-model artifact scikit-learn version is incompatible: "
            f"{exc.original_sklearn_version} != {exc.current_sklearn_version}"
        ) from exc
    if not isinstance(envelope, dict) or envelope.get("schema") != ARTIFACT_SCHEMA:
        raise ValueError("Unsupported content-model artifact schema")
    if envelope.get("python") != _major_minor(platform.python_version()):
        raise ValueError("Content-model artifact Python version is incompatible")
    if envelope.get("scikit_learn") not in {
        sklearn.__version__, _major_minor(sklearn.__version__)
    }:
        raise ValueError("Content-model artifact scikit-learn version is incompatible")
    if "runtime_package_versions" in envelope:
        validate_runtime_package_versions(envelope["runtime_package_versions"])
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


def _explanation_metadata(pipeline: dict) -> tuple[np.ndarray, np.ndarray | None]:
    """Cache immutable model metadata used by every explanation request."""
    names_key = "_runtime_feature_names"
    coefficients_key = "_runtime_coefficients"
    if names_key not in pipeline:
        feature_names = _flat_feature_names(pipeline["vectorizer"])
        feature_names.setflags(write=False)
        pipeline[names_key] = feature_names
    if coefficients_key not in pipeline:
        coefficients = _extract_coefficients(pipeline["clf"])
        if coefficients is not None:
            coefficients = np.asarray(coefficients)
            coefficients.setflags(write=False)
        pipeline[coefficients_key] = coefficients
    return pipeline[names_key], pipeline[coefficients_key]


def predict_content(pipeline: dict, subject: str, body: str, *, canonical_text: bool = False) -> dict:
    """Score one subject/body pair and return bounded explainability details."""
    text = (subject or "") + "\n" + (body or "")
    threshold = float(pipeline.get("decision_threshold", 0.5))
    # Endpoint callers already supply MIME-aware visible text. Keep literal
    # text/plain markup intact for both the context gate and the vectorizer.
    context_text = text if canonical_text else re.sub(r"<[^>]*>", " ", unescape(text))
    token_count = len(re.findall(r"\w+", context_text, flags=re.UNICODE))
    nonspace_char_count = sum(not character.isspace() for character in context_text)
    if (
        token_count < MIN_MODEL_CONTEXT_TOKENS
        or nonspace_char_count < MIN_MODEL_CONTEXT_NONSPACE_CHARS
    ):
        return {
            "ml_status": "insufficient_context",
            "_phishing_probability": None,
            "ml_phishing_probability": None,
            "ml_legitimate_probability": None,
            "ml_label": None,
            "ml_prediction": None,
            "ml_decision_threshold": round(threshold * 100, 1),
            "ml_top_contributors": [],
        }
    vectorizer = pipeline["vectorizer"]
    features = vectorizer.transform([text])
    # Subject features do not establish that a substantial body was represented
    # by the fitted model. Check the body and meaningful non-Latin segments
    # separately, so English padding cannot mask an uncovered segment.
    context_body = (
        (body or "") if canonical_text
        else re.sub(r"<[^>]*>", " ", unescape(body or ""))
    )
    substantial_body = sum(not character.isspace() for character in context_body) >= MIN_SUBSTANTIAL_BODY_CHARS
    uncovered_body = substantial_body and vectorizer.transform([context_body]).nnz == 0
    uncovered_segment = any(
        vectorizer.transform([segment]).nnz == 0
        for segment in non_latin_script_segments(context_body, MIN_UNCOVERED_SCRIPT_LETTERS)
    )
    if features.nnz == 0 or uncovered_body or uncovered_segment:
        return {
            "ml_status": "insufficient_feature_coverage",
            "_phishing_probability": None,
            "ml_phishing_probability": None,
            "ml_legitimate_probability": None,
            "ml_label": None,
            "ml_prediction": None,
            "ml_decision_threshold": round(threshold * 100, 1),
            "ml_top_contributors": [],
        }
    probabilities = pipeline["clf"].predict_proba(features)[0]
    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])
    prediction = int(phishing_probability >= threshold)

    feature_names, coefficients = _explanation_metadata(pipeline)
    contributors = []
    if coefficients is not None and len(coefficients) == len(feature_names):
        sparse_features = features.getrow(0)
        pairs = []
        for index, value in zip(sparse_features.indices, sparse_features.data):
            contribution = value * coefficients[index]
            if contribution <= 0:
                continue
            name = str(feature_names[index])
            kind, _, term = name.partition(":")
            if kind == "word":
                pairs.append((term, float(contribution)))
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
        "ml_status": "available",
        # Internal fraction for decisions and MIME ranking; display fields are rounded.
        "_phishing_probability": phishing_probability,
        "ml_phishing_probability": round(phishing_probability * 100, 1),
        "ml_legitimate_probability": round(legitimate_probability * 100, 1),
        "ml_label": "Likely Phishing" if prediction == 1 else "Likely Legitimate",
        "ml_prediction": prediction,
        "ml_decision_threshold": round(threshold * 100, 1),
        "ml_top_contributors": contributors,
    }
