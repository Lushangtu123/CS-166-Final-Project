import asyncio
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from config import Settings


class HeaderAmbiguityTests(unittest.TestCase):
    def analyze(self, raw):
        return json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email=raw))).body)

    def test_multiple_from_mailboxes_preserve_each_display_identity(self):
        bad = 'Apple <alice@unrelated.net>'
        good = 'Alice <alice@gmail.com>'
        for value in (bad, f'{good}, {bad}', f'{bad}, {good}'):
            with self.subTest(value=value):
                result = self.analyze(f'From: {value}\nSender: alice@gmail.com\n\nHello')
                self.assertIn(result['risk_level'], ('high', 'critical'))
                self.assertTrue(any('Protected brand identity' in item['msg']
                                    for item in result['extra_indicators']))
        ordinary = self.analyze('From: "Doe, Alice" <alice@gmail.com>, Bob <bob@outlook.com>\n'
                                'Sender: alice@gmail.com\n\nHello')
        self.assertEqual(ordinary['risk_level'], 'safe')
        self.assertTrue(ordinary['analysis_complete'])

    def test_multi_author_reply_can_align_with_either_author(self):
        headers = ('From: Alice <alice@gmail.com>, Bob <bob@outlook.com>\n'
                   'Sender: alice@gmail.com\n')
        for domain in ('gmail.com', 'outlook.com'):
            result = self.analyze(headers + f'Reply-To: reply@{domain}\nReturn-Path: bounce@{domain}\n\nHello')
            self.assertEqual(result['risk_level'], 'safe')
            self.assertFalse(any('differs from From domain' in item['msg'] for item in result['extra_indicators']))
        result = self.analyze(headers + 'Reply-To: collector@unrelated.net\n\nHello')
        self.assertTrue(any('Reply-To domain' in item['msg'] for item in result['extra_indicators']))

    def test_duplicate_headers_preserve_risk_in_either_order(self):
        pairs = [
            ('From', 'alice@gmail.com', 'Apple <service@unrelated.example>'),
            ('Subject', 'Hello', 'Your account has been suspended. Act now and enter your password.'),
            ('From', 'alice@gmail.com', 'billing@secure-account.xyz'),
        ]
        for name, benign, risky in pairs:
            for values in ((benign, risky), (risky, benign)):
                with self.subTest(name=name, values=values):
                    raw = ''.join(f'{name}: {value}\n' for value in values) + '\nHello'
                    result = self.analyze(raw)
                    self.assertIn(result['risk_level'], ('high', 'critical'))
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(result['message_structure']['parse_warnings'])

    def test_header_defects_are_incomplete_but_repeatable_headers_are_valid(self):
        malformed = self.analyze('From: Alice <alice@gmail.com\n\nHello')
        self.assertFalse(malformed['analysis_complete'])
        self.assertEqual(malformed['risk_level'], 'unknown')
        ordinary = self.analyze('From: alice@gmail.com\nReceived: by a\nReceived: by b\n'
                                'Authentication-Results: a; spf=pass\n'
                                'Authentication-Results: b; spf=pass\n\nHello')
        self.assertTrue(ordinary['analysis_complete'])
        self.assertEqual(ordinary['risk_level'], 'safe')

    def test_duplicate_reply_and_return_paths_keep_mismatch_evidence(self):
        for name in ('Reply-To', 'Return-Path'):
            result = self.analyze(f'From: alice@gmail.com\n{name}: alice@gmail.com\n'
                                  f'{name}: collector@unrelated.example\n\nHello')
            self.assertFalse(result['analysis_complete'])
            self.assertTrue(any(f'{name} domain' in indicator['msg']
                                for indicator in result['extra_indicators']))

    def test_unparseable_headers_do_not_discard_content_risk(self):
        for name in ('To', 'From', 'Reply-To'):
            for value in ('"', 'a@['):
                with self.subTest(name=name, value=value):
                    result = self.analyze(f'{name}: {value}\nSubject: Your account has been suspended. '
                                          'Act now and enter your password.\n\nHello')
                    self.assertIn(result['risk_level'], ('high', 'critical'))
                    self.assertFalse(result['analysis_complete'])


class ParserResourceTests(unittest.TestCase):
    def test_mime_part_budget_includes_flat_multipart_and_preserves_normal_mail(self):
        for parts, complete in ((199, True), (200, False)):
            raw = ('Content-Type: multipart/mixed; boundary=b\n\n' +
                   '--b\nContent-Type: text/plain\n\nHello\n' * parts + '--b--\n')
            result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)
            self.assertEqual(result['analysis_complete'], complete)
            self.assertEqual(result['risk_level'], 'safe' if complete else 'unknown')

    def test_deep_email_is_incomplete_and_keeps_outer_identity(self):
        for outer, expected in (('', 'unknown'), ('From: Apple <alice@unrelated.net>\n', 'high')):
            raw = outer + 'Content-Type: message/rfc822\n\n' * 1100 + 'Hello'
            for source in (raw, raw.encode()):
                with self.subTest(outer=outer, binary=isinstance(source, bytes)):
                    if isinstance(source, bytes):
                        async def receive():
                            return {'type': 'http.request', 'body': source, 'more_body': False}
                        request = app.Request({'type': 'http', 'headers': [(b'content-type', b'message/rfc822')]}, receive)
                        response = asyncio.run(app.analyze_eml_endpoint(request))
                    else:
                        response = asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=source)))
                    result = json.loads(response.body)
                    self.assertEqual(result['risk_level'], expected)
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(any('resource limit' in warning.lower()
                                        for warning in result['message_structure']['parse_warnings']))


class AmountResourceTests(unittest.TestCase):
    def test_long_amounts_cannot_abort_analysis_or_expand_evidence(self):
        for digits, large in (('9' * 4400, True), ('0' * 4400, False),
                              ('0' * 4400 + '10000', True), ('٠' * 4400, False),
                              ('9999', False), ('10000', True)):
            with self.subTest(length=len(digits), large=large):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(body='$' + digits))).body)
                findings = [item['msg'] for item in result['extra_indicators']
                            if 'monetary amounts' in item['msg']]
                self.assertEqual(bool(findings), large)
                self.assertTrue(all(len(item) < 300 for item in findings))
                self.assertTrue(result['analysis_complete'])


class VerificationSemanticsTests(unittest.TestCase):
    def verify(self, reply=(250, b'2.1.5 Accepted'), *, mx=None, whois_error=None, dns_error_kind=None,
               address_answers=None):
        import dns.resolver
        import dns.exception
        def resolve(_name, kind, **_kwargs):
            if kind == dns_error_kind:
                raise dns.exception.Timeout
            if kind == 'MX':
                return mx if mx is not None else [SimpleNamespace(preference=0, exchange='mx.example.com.')]
            if address_answers is not None and kind in {'A', 'AAAA'}:
                if address_answers.get(kind):
                    return address_answers[kind]
                raise dns.resolver.NoAnswer
            if kind == 'A':
                return ['8.8.8.8']
            raise dns.resolver.NoAnswer
        with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=True)), \
             patch('dns.resolver.resolve', side_effect=resolve), \
             patch('whois.whois', return_value=SimpleNamespace(creation_date=None), side_effect=whois_error), \
             patch('smtplib.SMTP') as smtp:
            smtp.return_value.rcpt.return_value = reply
            result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email='user@example.com')).body)
            return result, smtp.called

    def test_ipv6_implicit_mx_and_uncertain_address_lookups(self):
        result, contacted = self.verify(mx=[], address_answers={'AAAA': ['2606:4700:4700::1111']})
        self.assertTrue(result['mx_found'])
        self.assertEqual(result['overall'], 'verified')
        self.assertTrue(contacted)
        self.assertIn('AAAA', result['note'])
        for failed_kind in ('A', 'AAAA'):
            with self.subTest(failed_kind=failed_kind):
                result, contacted = self.verify(mx=[], address_answers={}, dns_error_kind=failed_kind)
                self.assertEqual(result['overall'], 'unverifiable')
                self.assertFalse(contacted)
        result, contacted = self.verify(mx=[], address_answers={})
        self.assertEqual(result['overall'], 'likely_invalid')
        self.assertFalse(contacted)

    def test_null_mx_never_falls_back_to_ipv6(self):
        result, contacted = self.verify(mx=[SimpleNamespace(preference=0, exchange='.')],
                                        address_answers={'AAAA': ['2606:4700:4700::1111']})
        self.assertEqual(result['overall'], 'no_mail_service')
        self.assertFalse(contacted)

    def test_smtp_rejections_do_not_all_mean_missing_mailbox(self):
        for reply, expected, overall in (
            ((250, b'2.1.5 Accepted'), 'exists', 'verified'),
            ((550, b'5.1.1 No such user'), 'does_not_exist', 'likely_invalid'),
            ((550, b'5.7.1 Access denied by policy'), 'policy_rejected', 'unverifiable'),
            ((552, b'5.2.2 Mailbox full'), 'mailbox_full', 'unverifiable'),
            ((550, b'Rejected'), 'unknown', 'unverifiable'),
            ((551, b'User not local'), 'unknown', 'unverifiable'),
            ((553, b'Mailbox name not allowed'), 'unknown', 'unverifiable'),
            ((450, b'4.2.0 Try later'), 'temporarily_unavailable', 'unverifiable'),
        ):
            with self.subTest(reply=reply):
                result, _ = self.verify(reply)
                self.assertEqual(result['smtp_result'], expected)
                self.assertEqual(result['overall'], overall)

    def test_null_mx_stops_probing_without_claiming_phishing(self):
        result, contacted = self.verify(mx=[SimpleNamespace(preference=0, exchange='.')])
        self.assertEqual(result['overall'], 'no_mail_service')
        self.assertTrue(result['null_mx'])
        self.assertFalse(result['mx_found'])
        self.assertFalse(contacted)
        self.assertIsNone(result['domain_age'])

    def test_fast_lookup_errors_are_not_complete_verification(self):
        for error, expected in ((TimeoutError('simulated timeout'), 'timeout'),
                                (OSError('simulated failure'), 'error')):
            with self.subTest(error=error):
                result, _ = self.verify(whois_error=error)
                self.assertFalse(result['verification_complete'])
                self.assertEqual(result['domain_age']['status'], expected)
                self.assertEqual(result['overall'], 'verified')
        result, _ = self.verify(dns_error_kind='TXT')
        self.assertFalse(result['verification_complete'])
        self.assertEqual(result['spf']['status'], 'timeout')
        self.assertEqual(result['dmarc']['status'], 'timeout')

    def test_successful_absence_is_distinct_from_failed_lookup(self):
        result, _ = self.verify()
        self.assertTrue(result['verification_complete'])
        for key in ('spf', 'dmarc', 'mx_ptr', 'domain_age'):
            self.assertEqual(result[key]['status'], 'not_found')

    def test_mixed_null_mx_is_inconclusive_not_a_mail_host(self):
        result, contacted = self.verify(mx=[SimpleNamespace(preference=0, exchange='.'),
                                           SimpleNamespace(preference=10, exchange='mx.example.com.')])
        self.assertEqual(result['overall'], 'unverifiable')
        self.assertFalse(result['mx_found'])
        self.assertFalse(contacted)
