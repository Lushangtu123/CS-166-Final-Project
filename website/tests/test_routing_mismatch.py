"""Routing differences stay visible without masquerading as independent attacks."""
import asyncio
from email.message import EmailMessage
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from config import Settings
from email_structure import analyze_raw_email


class RoutingMismatchTests(unittest.TestCase):
    def message(self, *, reply=True, envelope=True, list_header=False):
        message = EmailMessage()
        message['From'] = 'Alice <alice@example.org>'
        message['To'] = 'Bob <bob@example.net>'
        message['Subject'] = 'Project discussion'
        if reply:
            message['Reply-To'] = 'discussion@lists.example.net'
        if envelope:
            message['Return-Path'] = '<bounce@delivery.example.com>'
        if list_header:
            message['List-Id'] = 'Project discussion <project.lists.example.net>'
        message.set_content('Please review the project planning notes before our meeting tomorrow.')
        return message

    def analyze(self, message):
        settings = Settings(app_env='test', enable_email_verification=False,
                            content_model_enabled=False,
                            trusted_authserv_ids=frozenset({'mx.example.net'}))
        with patch.object(app, 'SETTINGS', settings), patch.object(app, '_content_pipeline', None):
            structure = analyze_raw_email(message.as_bytes(), trusted_authserv_ids=settings.trusted_authserv_ids)
            return json.loads(asyncio.run(app._analyze_content(
                app.ContentRequest(), structure, observe_sender_history=False)).body)

    def test_single_and_combined_routing_mismatches_are_one_weak_concern(self):
        for reply, envelope in ((True, False), (False, True), (True, True)):
            for list_header in (False, True):
                with self.subTest(reply=reply, envelope=envelope, list_header=list_header):
                    message = self.message(reply=reply, envelope=envelope, list_header=list_header)
                    structure = analyze_raw_email(message.as_bytes())
                    self.assertEqual(structure['structure_score'], 2)
                    self.assertEqual(structure['risk_floor'], 'safe')
                    findings = [item for item in structure['indicators'] if 'differs from From domain' in item['msg']]
                    self.assertEqual(len(findings), int(reply) + int(envelope))
                    self.assertTrue(all(item['level'] == 'low' for item in findings))
                    self.assertEqual(self.analyze(message)['risk_level'], 'low')

    def test_routing_and_list_headers_cannot_suppress_independent_danger(self):
        for risk in ('trusted_auth_failure', 'dangerous_link', 'dangerous_attachment', 'credential_threat'):
            with self.subTest(risk=risk):
                message = self.message(list_header=True)
                if risk == 'trusted_auth_failure':
                    message['Authentication-Results'] = 'mx.example.net; dmarc=fail; spf=fail; dkim=fail'
                elif risk == 'dangerous_link':
                    message.add_alternative('<a href="https://paypa1.example/login">Review the document</a>', subtype='html')
                elif risk == 'dangerous_attachment':
                    message.add_attachment(b'inert test bytes', maintype='application', subtype='octet-stream', filename='invoice.exe')
                else:
                    message.set_content('Your account has been suspended. Act now and enter your password immediately.')
                result = self.analyze(message)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertIn(result['risk_floor'], {'high', 'critical'})

    def test_duplicate_routing_headers_preserve_mismatch_and_uncertainty(self):
        for name in ('Reply-To', 'Return-Path'):
            for values in (('alice@example.org', 'reply@elsewhere.example'),
                           ('reply@elsewhere.example', 'alice@example.org')):
                raw = ('From: alice@example.org\n' + ''.join(f'{name}: {value}\n' for value in values)
                       + '\nPlease review the project planning notes before our meeting tomorrow.')
                structure = analyze_raw_email(raw)
                self.assertEqual(structure['structure_score'], 2)
                self.assertTrue(structure['parse_warnings'])
                self.assertTrue(any(f'{name} domain' in item['msg'] for item in structure['indicators']))
