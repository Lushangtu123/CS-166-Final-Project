import asyncio
from email.message import EmailMessage
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class SequenceClassifier:
    """Controlled boundary scores; text parsing and inference remain real."""
    def __init__(self, probabilities):
        self.probabilities = iter(probabilities)

    def predict_proba(self, features):
        probability = next(self.probabilities)
        return np.array([[1 - probability, probability]])


class RiskPrecisionTests(unittest.TestCase):
    body = 'Please review the regular project planning notes for our meeting tomorrow.'

    def analyze(self, probabilities, threshold, request):
        pipeline = {
            'vectorizer': TfidfVectorizer().fit([self.body]),
            'clf': SequenceClassifier(probabilities),
            'decision_threshold': threshold,
            'metrics': {},
        }
        with patch.object(app, '_content_pipeline', pipeline):
            result = json.loads(asyncio.run(app._analyze_content(
                request, observe_sender_history=False,
            )).body)
        self.assertNotIn('_phishing_probability', result)
        return result

    def test_fusion_uses_unrounded_probability_at_threshold(self):
        for threshold in (0.37355294511560266, 0.5004):
            for offset, expected in ((-0.00002, 0), (0, 1), (0.00002, 1)):
                with self.subTest(threshold=threshold, offset=offset):
                    probability = threshold + offset
                    result = self.analyze([probability], threshold, app.ContentRequest(body=self.body))
                    self.assertEqual(result['ml_prediction'], expected)
                    self.assertEqual(result['total_score'], 0)
                    self.assertEqual(result['risk_level'], 'high' if expected else 'medium')
                    self.assertEqual(result['ml_phishing_probability'], round(probability * 100, 1))

    def test_mime_selection_distinguishes_scores_that_round_to_the_same_value(self):
        threshold = 0.37355294511560266
        message = EmailMessage()
        message.set_content(self.body + ' First version.')
        message.add_alternative('<p>' + self.body + ' Second version.</p>', subtype='html')
        result = self.analyze(
            [threshold - 0.00002, threshold + 0.00002], threshold,
            app.ContentRequest(raw_email=message.as_string()),
        )
        self.assertEqual(result['ml_prediction'], 1)
        self.assertEqual(result['risk_level'], 'high')

    def test_rounding_does_not_promote_supported_high_risk_to_critical(self):
        request = app.ContentRequest(
            subject='Your account has been suspended. Act now and enter your password.',
            body=self.body,
        )
        result = self.analyze([0.79996], 0.35, request)
        self.assertEqual(result['risk_level'], 'high')
        self.assertEqual(result['ml_phishing_probability'], 80.0)
