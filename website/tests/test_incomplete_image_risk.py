"""Weak evidence cannot make an image-dominant message look fully inspected."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from config import Settings
from email_structure import analyze_raw_email


class IncompleteImageRiskTests(unittest.TestCase):
    def analyze(self, body):
        raw = ('From: alice@example.org\nReply-To: discussion@example.net\n'
               'Content-Type: text/html; charset=utf-8\n\n' + body)
        with patch.object(app, 'SETTINGS', Settings(app_env='test', enable_email_verification=False)), \
             patch.object(app, '_content_pipeline', None):
            return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(),
                analyze_raw_email(raw), observe_sender_history=False)).body)

    def test_low_routing_concern_with_uninspected_dominant_image_is_unknown(self):
        result = self.analyze('<p>Hello</p><img src="https://images.example/notice.png">')
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertIsNone(result['combined_phishing_score'])
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['remote_image_coverage']['inspection_status'], 'metadata_only')
        self.assertTrue(any('Reply-To domain' in i['msg'] for i in result['extra_indicators']))

    def test_dominant_image_cannot_hide_independent_danger(self):
        result = self.analyze('<a href="https://paypa1.example/login">Verify your password</a>'
                              '<img src="https://images.example/notice.png">')
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['analysis_complete'])

    def test_substantial_readable_text_with_decorative_image_keeps_low_evidence(self):
        result = self.analyze('<p>Our project planning meeting is scheduled for Thursday afternoon. '
                             'Please bring your notes and review the agenda before the discussion.</p>'
                             '<img src="https://images.example/logo.png">')
        self.assertEqual(result['risk_level'], 'low')
        self.assertFalse(result['analysis_complete'])

if __name__ == '__main__': unittest.main()
