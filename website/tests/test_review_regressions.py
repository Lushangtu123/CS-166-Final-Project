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
    def test_authentication_comments_and_reason_cannot_replace_results(self):
        tails = ('dmarc=fail', 'dmarc=fail (previous dmarc=pass)',
                 'dmarc=fail reason="previous; dmarc=pass"',
                 'dmarc (nested (dmarc=pass)) = fail', 'dmarc/1 = fail')
        with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=False,
                                                  trusted_authserv_ids=frozenset({'mx.example.com'}))):
            for tail in tails:
                with self.subTest(tail=tail):
                    result = self.analyze('From: alice@gmail.com\nAuthentication-Results: mx.example.com; '
                                          + tail + '\n\nHello')
                    self.assertEqual(result['message_structure']['auth_results']['dmarc'], 'fail')
                    self.assertIn(result['risk_level'], ('high', 'critical'))
            result = self.analyze('From: alice@gmail.com\nAuthentication-Results: mx.example.com; '
                                  'dmarc=pass reason="old dmarc=fail"\n\nHello')
            self.assertEqual(result['risk_level'], 'safe')

    def test_unclosed_authentication_explanation_cannot_confer_trusted_pass(self):
        with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=False,
                                                  trusted_authserv_ids=frozenset({'mx.example.com'}))):
            for tail in ('dmarc=pass (unfinished', 'dmarc=pass reason="unfinished'):
                result = self.analyze('From: alice@gmail.com\nAuthentication-Results: mx.example.com; '
                                      + tail + '\n\nHello')
                self.assertFalse(result['analysis_complete'])
                self.assertFalse(result['message_structure']['authentication_trusted'])
                self.assertEqual(result['risk_level'], 'unknown')


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
    def test_multipart_alternative_retains_explicit_dangerous_metadata(self):
        for first, second in (('multipart/mixed; boundary=b', 'application/x-msdownload'),
                              ('application/x-msdownload', 'multipart/mixed; boundary=b')):
            raw = f'Content-Type: {first}\nContent-Type: {second}\n\n--b\nContent-Type: text/plain\n\nHello\n--b--\n'
            result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)
            self.assertEqual(result['risk_level'], 'high')
            self.assertFalse(result['analysis_complete'])

    def test_mime_candidates_are_bounded_and_binary_decoding_is_preserved(self):
        raw = (''.join(f'Content-Type: text/plain; charset=x-unknown-{i}\n' for i in range(12))
               + 'Content-Type: text/html\n\nHello')
        structure = app.analyze_raw_email(raw)
        self.assertTrue(any('candidate limit' in warning.lower() for warning in structure['parse_warnings']))
        raw = (b'Content-Type: text/plain\nContent-Type: text/html\n'
               b'Content-Transfer-Encoding: 7bit\nContent-Transfer-Encoding: base64\n\n'
               b'PGZvcm0+PGlucHV0IHR5cGU9InBhc3N3b3JkIj48L2Zvcm0+')
        async def receive():
            return {'type': 'http.request', 'body': raw, 'more_body': False}
        request = app.Request({'type': 'http', 'headers': [(b'content-type', b'message/rfc822')]}, receive)
        result = json.loads(asyncio.run(app.analyze_eml_endpoint(request)).body)
        self.assertEqual(result['risk_level'], 'medium')
        self.assertFalse(result['analysis_complete'])

    def test_duplicate_mime_headers_preserve_recoverable_risk(self):
        import base64
        text = 'Your account has been suspended. Act now and enter your password.'
        encoded = base64.b64encode(text.encode()).decode()
        samples = [
            ('Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n'
             'Content-Transfer-Encoding: base64\n\n' + encoded, 'high'),
            ('Content-Type: text/plain\nContent-Type: text/html\n\n'
             '<form><input type="password"></form>', 'medium'),
            ('Content-Type: text/plain\nContent-Type: application/x-msdownload\n\nHello', 'high'),
        ]
        for raw, expected in samples:
            for envelope in ('{}', 'Content-Type: multipart/mixed; boundary=b\n\n--b\n{}\n--b--\n'):
                with self.subTest(raw=raw[:80], nested=envelope != '{}'):
                    result = json.loads(asyncio.run(app.analyze_content_endpoint(
                        app.ContentRequest(raw_email=envelope.format(raw)))).body)
                    self.assertEqual(result['risk_level'], expected)
                    self.assertFalse(result['analysis_complete'])

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


class LinkNormalizationTests(unittest.TestCase):
    def test_normalization_preserves_relative_links_and_query_boundaries(self):
        for target in ('https:news', '/news', 'https://paypal.com/?next=\\example.org',
                       'https://paypal.com\\@example.org/'):
            with self.subTest(target=target):
                body = '<base href="https://paypal.com/docs/"><a href="' + target + '">Read more</a>'
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertEqual(result['risk_level'], 'safe')
                self.assertTrue(result['analysis_complete'])

    def test_unparseable_web_targets_are_not_complete_analysis(self):
        for target in ('https://', 'https://#notice', 'https://example.org:bad/', 'https://[bad/'):
            for base in ('', '<base href="https://example.org/docs/">'):
                with self.subTest(target=target, base=bool(base)):
                    result = json.loads(asyncio.run(app.analyze_content_endpoint(
                        app.ContentRequest(body=base + f'<a href="{target}">Read document</a>'))).body)
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(any('destination' in warning for warning in result['analysis_warnings']))

    def test_equivalent_web_targets_keep_the_same_host_risk(self):
        for host, expected in (('paypal.com.evil.example', 'high'), ('paypal.com', 'safe')):
            for prefix in ('https://', 'https:////', 'https:\\\\', '//', '////'):
                for base in ('', '<base href="https://example.org/docs/">'):
                    body = base + f'<a href="{prefix}{host}/">Review document</a>'
                    for request in (app.ContentRequest(body=body), app.ContentRequest(
                            raw_email='Content-Type: text/html\n\n' + body)):
                        with self.subTest(host=host, prefix=prefix, base=bool(base), raw=bool(request.raw_email)):
                            result = json.loads(asyncio.run(app.analyze_content_endpoint(request)).body)
                            self.assertEqual(result['risk_level'], expected)
                            self.assertTrue(result['analysis_complete'])


class HtmlRecoveryTests(unittest.TestCase):
    def test_implicit_head_end_keeps_metadata_and_inert_text_hidden(self):
        risky = 'Act now. Enter your password immediately or your account will be suspended.'
        for tag in ('title', 'script', 'style', 'template'):
            body = f'<head><{tag}>{risky}</{tag}><body>The meeting is on Tuesday.</body>'
            with self.subTest(tag=tag):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=body))).body)
                self.assertEqual(result['risk_level'], 'safe')
                self.assertTrue(result['analysis_complete'])

    def test_implicit_head_end_preserves_body_risk(self):
        risky = 'Act now. Enter your password immediately or your account will be suspended.'
        for text, expected in ((risky, 'high'), ('The meeting is on Tuesday.', 'safe')):
            for boundary in ('</head><body>', '<body>', '<p>', ''):
                body = '<html><head><title>Notice</title>' + boundary + text + '</p></body></html>'
                for request in (app.ContentRequest(body=body), app.ContentRequest(
                        raw_email='Content-Type: text/html\n\n' + body)):
                    with self.subTest(boundary=boundary, expected=expected, raw=bool(request.raw_email)):
                        result = json.loads(asyncio.run(app.analyze_content_endpoint(request)).body)
                        self.assertEqual(result['risk_level'], expected)
                        self.assertTrue(result['analysis_complete'])

    def test_recovery_does_not_depend_on_stdlib_raising(self):
        original = app.HTMLParser.parse_html_declaration

        def tolerant_declaration(parser, index):
            # New CPython releases consume unknown declarations as bogus
            # comments rather than raising. Keep all other parser work real.
            if parser.rawdata.startswith(('<![foo]', '<![if_foo]'), index):
                return parser.parse_bogus_comment(index)
            return original(parser, index)

        with patch.object(app.HTMLParser, 'parse_html_declaration', tolerant_declaration):
            self.test_malformed_html_preserves_evidence_and_marks_incomplete()
            self.test_nested_html_recovery_propagates_and_valid_plain_text_is_unchanged()

    def test_literal_markers_and_supported_declarations_do_not_trigger_recovery(self):
        for body in (
            '<!-- <![foo]> --><p>Hello</p>',
            '<div title="<![foo]>">Hello</div>',
            '<script>const marker = "<![foo]>";</script><p>Hello</p>',
            '<style>/* <![foo]> */</style><p>Hello</p>',
            '<!DOCTYPE html><p>Hello</p>',
            '<![CDATA[ordinary text]]><p>Hello</p>',
            '<![if !mso]><p>Hello</p><![endif]>',
        ):
            with self.subTest(body=body):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(raw_email='Content-Type: text/html\n\n' + body))).body)
                self.assertTrue(result['analysis_complete'])
                self.assertEqual(result['risk_level'], 'safe')
                self.assertEqual(result['analysis_warnings'], [])

    def test_supported_mso_comment_warns_about_rendering_not_malformed_html(self):
        body = '<!--[if mso]>Hello<![endif]--><p>Hello</p>'
        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email='Content-Type: text/html\n\n' + body))).body)
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertEqual(result['analysis_warnings'], [app._MSO_CONDITIONAL_WARNING])

    def test_nested_html_recovery_propagates_and_valid_plain_text_is_unchanged(self):
        raw = 'Content-Type: message/rfc822\n\nContent-Type: text/html\n\n<![foo]>Hello'
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)
        self.assertFalse(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertTrue(any('Attached message' in warning for warning in result['analysis_warnings']))
        raw = 'Content-Type: text/plain\n\n<![foo]>Hello'
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)
        self.assertTrue(result['analysis_complete'])
        self.assertEqual(result['risk_level'], 'safe')

    def test_malformed_html_preserves_evidence_and_marks_incomplete(self):
        for body, expected in (
            ('<![foo]>Hello', 'unknown'),
            ('<![if_foo]>Hello', 'unknown'),
            ('<![foo]>Your account has been suspended. Act now and enter your password.', 'high'),
            ('<![foo]><form><input type="password"></form>', 'medium'),
            ('<![foo]><a href="https://paypa1.example/">Continue</a>', 'high'),
        ):
            for request in (app.ContentRequest(body=body),
                            app.ContentRequest(raw_email='Content-Type: text/html\n\n' + body)):
                with self.subTest(body=body, raw=bool(request.raw_email)):
                    result = json.loads(asyncio.run(app.analyze_content_endpoint(request)).body)
                    self.assertEqual(result['risk_level'], expected)
                    self.assertFalse(result['analysis_complete'])
                    self.assertTrue(result['analysis_warnings'])


class AmountResourceTests(unittest.TestCase):
    def test_decimal_amounts_do_not_become_large_by_removing_the_decimal_point(self):
        for amount, large in (('$100', False), ('$100.00', False), ('$9,999.99', False),
                              ('$10,000.00', True), ('EUR 100,00', False),
                              ('EUR 10.000,00', True), ('$1,234,567.89', True),
                              ('$10,00,00', False)):
            with self.subTest(amount=amount):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(body=amount))).body)
                self.assertEqual(any('monetary amounts' in item['msg'] for item in result['extra_indicators']), large)

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
    def test_public_config_separates_domain_and_mailbox_capabilities(self):
        settings = Settings(
            app_env='production',
            enable_email_verification=True,
            verification_mode='lite',
        )

        with patch.object(app, 'SETTINGS', settings):
            result = json.loads(asyncio.run(app.get_public_config()).body)

        self.assertEqual(result['verification_mode'], 'lite')
        self.assertTrue(result['domain_verification_enabled'])
        self.assertFalse(result['smtp_verification_enabled'])
        self.assertTrue(result['email_verification_enabled'])

    def test_verification_and_sender_validation_agree_on_addresses(self):
        with patch.object(app, 'SETTINGS', Settings(app_env='development', enable_email_verification=True)):
            for email, domain in (
                ('user@example.com', 'example.com'),
                ('user@example.com.', 'example.com'),
                ('user@例子.公司', 'xn--fsqu00a.xn--55qx5d'),
                ('user@xn--fsqu00a.xn--55qx5d', 'xn--fsqu00a.xn--55qx5d'),
                ('user+tag@EXAMPLE.COM', 'example.com'),
            ):
                with self.subTest(email=email), patch('dns.resolver.resolve', return_value=[
                        SimpleNamespace(preference=0, exchange='.')]) as resolve:
                    sender = asyncio.run(app.analyze_email(app.EmailRequest(email=email)))
                    result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email=email)).body)
                    self.assertEqual(sender.status_code, 200)
                    self.assertTrue(result['format_valid'])
                    self.assertEqual(result['email'], email)
                    self.assertEqual(result['overall'], 'no_mail_service')
                    self.assertEqual(resolve.call_args.args[0], domain)
            for email in ('.user@example.com', 'user.@example.com', 'user@-example.com',
                          'user@example-.com', 'user..tag@example.com', 'a@example.com,b@example.com'):
                with self.subTest(email=email), patch('dns.resolver.resolve',
                        side_effect=AssertionError('Invalid input must not query DNS')) as resolve:
                    with self.assertRaises(app.HTTPException):
                        asyncio.run(app.analyze_email(app.EmailRequest(email=email)))
                    result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email=email)).body)
                    self.assertFalse(result['format_valid'])
                    self.assertEqual(result['overall'], 'invalid_format')
                    resolve.assert_not_called()

    def verify(self, reply=(250, b'2.1.5 Accepted'), *, mx=None, whois_error=None, dns_error_kind=None,
               address_answers=None, txt_records=None, email='user@example.com', settings=None):
        import dns.resolver
        import dns.exception
        import dns.rdata
        def resolve(_name, kind, **_kwargs):
            if kind == dns_error_kind:
                raise dns.exception.Timeout
            if kind == 'MX':
                return mx if mx is not None else [SimpleNamespace(preference=0, exchange='mx.example.com.')]
            if kind == 'TXT' and txt_records is not None:
                key = 'dmarc' if str(_name).startswith('_dmarc.') else 'spf'
                return [dns.rdata.from_text('IN', 'TXT', record) for record in txt_records.get(key, [])]
            if address_answers is not None and kind in {'A', 'AAAA'}:
                if address_answers.get(kind):
                    return address_answers[kind]
                raise dns.resolver.NoAnswer
            if kind == 'A':
                return ['8.8.8.8']
            raise dns.resolver.NoAnswer
        settings = settings or Settings(app_env='development', enable_email_verification=True)
        with patch.object(app, 'SETTINGS', settings), \
             patch('dns.resolver.resolve', side_effect=resolve), \
             patch('whois.whois', return_value=SimpleNamespace(creation_date=None), side_effect=whois_error), \
             patch('smtplib.SMTP') as smtp:
            smtp.return_value.rcpt.return_value = reply
            result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email=email)).body)
            return result, smtp.called

    def test_lite_mode_verifies_domain_without_contacting_smtp(self):
        settings = Settings(
            app_env='production',
            enable_email_verification=True,
            verification_mode='lite',
        )

        result, contacted = self.verify(settings=settings)

        self.assertFalse(contacted)
        self.assertEqual(result['overall'], 'domain_valid')
        self.assertEqual(result['domain_verification']['status'], 'valid')
        self.assertTrue(result['domain_verification']['complete'])
        self.assertEqual(result['mailbox_verification']['status'], 'unavailable')
        self.assertEqual(result['smtp_status'], 'skipped')
        self.assertFalse(result['verification_complete'])

    def test_split_txt_records_keep_their_policy(self):
        for records in (
            {'spf': ['"v=spf1 -all"'], 'dmarc': ['"v=DMARC1; p=reject"']},
            {'spf': ['"v=spf1 -" "all"'], 'dmarc': ['"v=DMARC1; p=" "reject"']},
        ):
            with self.subTest(records=records):
                result, _ = self.verify(txt_records=records)
                self.assertEqual(result['spf']['policy'], 'strict')
                self.assertEqual(result['dmarc']['policy'], 'reject')
                self.assertTrue(result['verification_complete'])

    def test_spf_policy_uses_complete_mechanisms_in_order(self):
        for txt, policy in (
            ('v=spf1 -all', 'strict'), ('v=spf1 ~all', 'softfail'),
            ('v=spf1 include:mail-all.example ~all', 'softfail'),
            ('v=spf1 +all -all', 'open'), ('v=spf1 all', 'open'),
            ('v=spf1 ?all -all', 'neutral'), ('v=spf1 -all +all', 'strict'),
            ('v=spf1 redirect=mail-all.example', 'unknown'),
        ):
            with self.subTest(txt=txt):
                result, _ = self.verify(txt_records={'spf': [json.dumps(txt)]})
                self.assertEqual(result['spf']['policy'], policy)

    def test_dmarc_policy_uses_tags_not_substrings(self):
        for txt, expected in (
            ('v=DMARC1; p = reject; pct = 25', 'reject'),
            ('v=DMARC1; rua=mailto:p=reject@example.com; p=none', 'none'),
        ):
            with self.subTest(txt=txt):
                result, _ = self.verify(txt_records={'dmarc': [json.dumps(txt)]})
                self.assertEqual(result['dmarc']['policy'], expected)
                if expected == 'reject':
                    self.assertEqual(result['dmarc']['pct'], 25)

    def test_ambiguous_policy_records_do_not_claim_success(self):
        for records in (
            {'spf': ['"v=spf1 -all"', '"v=spf1 +all"']},
            {'spf': ['"v=spf1 include: -all"']},
            {'spf': ['"v=spf1 -all:example.com"']},
            {'dmarc': ['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"']},
            {'dmarc': ['"v=DMARC1; p=reject; p=none"']},
            {'dmarc': ['"v=DMARC1; p=reject; pct=101"']},
            {'dmarc': ['"v=DMARC1; rua=mailto:p=reject@example.com"']},
        ):
            with self.subTest(records=records):
                result, _ = self.verify(txt_records=records)
                key = next(iter(records))
                self.assertIsNone(result[key]['policy'])
                self.assertEqual(result[key]['status'], 'error')
                self.assertFalse(result['verification_complete'])

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
