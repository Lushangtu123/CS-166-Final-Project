import sys
from pathlib import Path
import unittest

import numpy as np


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from content_inference import predict_content
from language_coverage import has_substantial_han_text


class _SparseFeatures:
    shape = (1, 3)
    indices = np.array([0, 2])
    data = np.array([2.0, 1.0])
    nnz = 2

    def getrow(self, _index):
        return self

    def toarray(self):
        raise AssertionError("content explanations must remain sparse")


class _CountingVectorizer:
    def __init__(self):
        self.feature_name_calls = 0

    def transform(self, _texts):
        return _SparseFeatures()

    def get_feature_names_out(self):
        self.feature_name_calls += 1
        return np.array(["word:urgent", "char:x", "word:account"])


class _CapturingVectorizer(_CountingVectorizer):
    def transform(self, texts):
        self.texts = texts
        return super().transform(texts)


class _Classifier:
    coef_ = np.array([[0.4, -0.2, 0.3]])

    def predict_proba(self, _features):
        return np.array([[0.1, 0.9]])


class _EmptySparseFeatures:
    shape = (1, 3)
    indices = np.array([], dtype=int)
    data = np.array([], dtype=float)
    nnz = 0

    def getrow(self, _index):
        return self


class _EmptyVectorizer(_CountingVectorizer):
    def transform(self, _texts):
        return _EmptySparseFeatures()


class _UnexpectedClassifier(_Classifier):
    def predict_proba(self, _features):
        raise AssertionError("classifier must not score a zero-feature message")


class _UnexpectedVectorizer(_CountingVectorizer):
    def transform(self, _texts):
        raise AssertionError("short input must not reach the vectorizer")


class ContentInferenceTests(unittest.TestCase):
    def test_han_extensions_are_bounded_to_unicode_blocks(self):
        for codepoint in (0x20000, 0x2EBF0, 0x323B0):
            with self.subTest(codepoint=codepoint):
                self.assertTrue(has_substantial_han_text(chr(codepoint) * 12))
        for codepoint in (0x2EE60, 0x33480):
            with self.subTest(codepoint=codepoint):
                self.assertFalse(has_substantial_han_text(chr(codepoint) * 12))

    def test_explanation_metadata_is_cached_and_sparse(self):
        vectorizer = _CountingVectorizer()
        pipeline = {
            "vectorizer": vectorizer,
            "clf": _Classifier(),
            "decision_threshold": 0.5,
        }

        subject = "Urgent account review required today"
        body = "Please review the complete account information before continuing."
        first = predict_content(pipeline, subject, body)
        second = predict_content(pipeline, subject, body)

        self.assertEqual(vectorizer.feature_name_calls, 1)
        self.assertEqual(first["ml_top_contributors"], second["ml_top_contributors"])
        self.assertEqual(
            first["ml_top_contributors"],
            [
                {"term": "urgent", "contribution": 0.8},
                {"term": "account", "contribution": 0.3},
            ],
        )
        self.assertEqual(first["ml_status"], "available")

    def test_short_input_abstains_before_vectorization(self):
        pipeline = {
            "vectorizer": _UnexpectedVectorizer(),
            "clf": _UnexpectedClassifier(),
            "decision_threshold": 0.5,
        }

        result = predict_content(pipeline, "File shared with you", "")

        self.assertEqual(result["ml_status"], "insufficient_context")
        self.assertIsNone(result["ml_phishing_probability"])
        self.assertIsNone(result["ml_legitimate_probability"])
        self.assertIsNone(result["ml_prediction"])
        self.assertEqual(result["ml_top_contributors"], [])

    def test_html_markup_does_not_count_as_model_context(self):
        pipeline = {
            "vectorizer": _UnexpectedVectorizer(),
            "clf": _UnexpectedClassifier(),
            "decision_threshold": 0.5,
        }

        result = predict_content(
            pipeline,
            "",
            '<div class="message"><span data-kind="content">Hello</span></div>',
        )

        self.assertEqual(result["ml_status"], "insufficient_context")
        self.assertIsNone(result["ml_prediction"])

    def test_canonical_literal_text_uses_same_context_and_vector_input(self):
        vectorizer = _CapturingVectorizer()
        pipeline = {
            "vectorizer": vectorizer,
            "clf": _Classifier(),
            "decision_threshold": 0.5,
        }
        literal = '<project notes about the planned meeting and release timeline>'
        result = predict_content(pipeline, '', literal, canonical_text=True)
        self.assertEqual(result['ml_status'], 'available')
        self.assertEqual(vectorizer.texts, ['\n' + literal])

    def test_zero_feature_message_abstains_without_calling_classifier(self):
        pipeline = {
            "vectorizer": _EmptyVectorizer(),
            "clf": _UnexpectedClassifier(),
            "decision_threshold": 0.5,
        }

        result = predict_content(
            pipeline,
            "Detailed project planning notes",
            "Please review this complete coordination summary before tomorrow's meeting.",
        )

        self.assertEqual(result["ml_status"], "insufficient_feature_coverage")
        self.assertIsNone(result["ml_phishing_probability"])
        self.assertIsNone(result["ml_legitimate_probability"])
        self.assertIsNone(result["ml_prediction"])
        self.assertEqual(result["ml_top_contributors"], [])


if __name__ == "__main__":
    unittest.main()
