"""Browser-extracted evidence must be rescored and never certify image safety."""
import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from test_case_api import request
import app


def observation(**changes):
    value = dict(name='synthetic.png', mime_type='image/png', source='upload',
                sha256='a' * 64, status='processed', qr_payloads=['https://paypa1.example/login'],
                ocr_text='', ocr_confidence=0, warnings=[])
    return {**value, **changes}


class VisualAPITests(unittest.TestCase):
    def setUp(self):
        app._rate_limit_buckets.clear()
        self.model = patch.object(app, '_content_pipeline', None)
        self.model.start()

    def tearDown(self):
        self.model.stop()

    def test_qr_evidence_is_rescored_with_provenance_and_incomplete_coverage(self):
        status, data, _ = asyncio.run(request('POST', '/api/analyze-visual', token=None,
            payload={'observations': [observation()]}))
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})
        self.assertFalse(data['analysis_complete'])
        self.assertEqual(data['visual_analysis']['provenance'], 'browser_extracted_unverified')
        self.assertEqual(data['visual_analysis']['observations'][0]['qr_payloads'],
                         ['https://paypa1.example/login'])

    def call(self, payload, path='/api/analyze-visual'):
        return asyncio.run(request('POST', path, token=None, payload=payload))

    def test_actual_ocr_language_is_preserved_without_trusting_it_as_a_verdict(self):
        for language in ('eng', 'chi_sim', 'eng+chi_sim', None):
            status, data, _ = self.call({'observations': [observation(ocr_language=language)]})
            self.assertEqual(status, 200)
            evidence = data['visual_analysis']
            self.assertEqual(evidence['observations'][0]['ocr_language'], language)
            self.assertNotIn('(eng+chi_sim)', evidence['extractors'])
            self.assertEqual(evidence['provenance'], 'browser_extracted_unverified')
            self.assertFalse(data['analysis_complete'])
        self.assertEqual(self.call({'observations': [observation(ocr_language='unknown-language') ]})[0], 422)

    def test_high_confidence_ocr_does_not_certify_url_spelling(self):
        for text in ('https://paypal.example/login', 'httbs:/ /baybal.example/login'):
            status, data, _ = self.call({'observations': [observation(
                qr_payloads=[], ocr_text=text, ocr_confidence=99)]})
            self.assertEqual(status, 200)
            record = data['visual_analysis']['observations'][0]
            self.assertEqual(record['ocr_text'], text)
            self.assertTrue(any('character by character' in warning
                                for warning in record['assessment_warnings']))
            self.assertFalse(data['analysis_complete'])
            self.assertNotEqual(data['risk_level'], 'safe')

    def test_benign_blank_or_failed_extraction_never_certifies_safety(self):
        for item in [observation(qr_payloads=[], ocr_text='Team meeting on Thursday.'),
                     observation(qr_payloads=[], status='failed', warnings=['OCR failed']),
                     observation(qr_payloads=['https://example.com/meeting'])]:
            with self.subTest(item=item):
                status, data, _ = self.call({'observations': [item]})
                self.assertEqual(status, 200)
                self.assertNotIn(data['risk_level'], {'safe', 'high', 'critical'})
                self.assertFalse(data['analysis_complete'])

    def test_original_email_is_authoritative_and_benign_ocr_cannot_lower_risk(self):
        raw = b'Subject: Real\nContent-Type: text/plain; charset=iso-8859-1\n\nH\xe9llo https://paypa1.example/login'
        status, data, _ = self.call({'subject': 'stale', 'body': 'stale',
            'eml_base64': base64.b64encode(raw).decode(),
            'observations': [observation(qr_payloads=[], ocr_text='Have a nice day')]})
        self.assertEqual(status, 200)
        self.assertEqual(data['input_mode'], 'raw-email')
        self.assertIn(data['risk_level'], {'high', 'critical'})

    def test_ocr_is_text_not_html_and_no_links_are_requested(self):
        with patch('socket.create_connection', side_effect=AssertionError('no network')):
            status, data, _ = self.call({'observations': [observation(qr_payloads=[],
                ocr_text='<style>URGENT</style> Your account will be suspended. Enter your password now https://paypa1.example/login')]})
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})

    def test_visual_input_validation_and_existing_small_endpoint_limit(self):
        for payload in [{'observations': [observation(risk_level='safe')]},
                        {'observations': [observation(ocr_confidence=float('nan'))]},
                        {'observations': [observation(ocr_text='x'*6001)]},
                        {'observations': [observation()]*5},
                        {'eml_base64': 'not base64!'}, {'risk_level': 'safe'}]:
            app._rate_limit_buckets.clear()
            self.assertEqual(self.call(payload)[0], 422)
        self.assertEqual(self.call({})[0], 400)
        self.assertEqual(self.call({'body': 'x'*70000}, '/api/analyze-content')[0], 413)

    def test_larger_image_email_keeps_text_bounded(self):
        raw = b'Subject: Large\n\n' + b'normal text ' * 10000
        status, data, _ = self.call({'eml_base64': base64.b64encode(raw).decode()})
        self.assertEqual(status, 200)
        self.assertFalse(data['analysis_complete'])
        self.assertTrue(any('text limit' in warning for warning in data['analysis_warnings']))

    def test_visual_case_auth_and_persisted_provenance(self):
        from test_case_api import CaseAPITests
        fixture = CaseAPITests(); fixture.setUp()
        try:
            payload = {'observations': [observation()]}
            key = '00000000-0000-4000-8000-000000000099'
            self.assertEqual(asyncio.run(request('POST', '/api/cases/visual', payload=payload, token=None, key=key))[0], 401)
            status, case, _ = fixture.call('POST', '/api/cases/visual', payload=payload, key=key)
            self.assertEqual(status, 201)
            self.assertIn(case['risk'], {'high', 'critical'})
            self.assertEqual(case['analysis']['visual_analysis']['provenance'], 'browser_extracted_unverified')
            self.assertNotIn('eml_base64', case['source'])
            self.assertEqual(fixture.call('POST', '/api/cases/visual', payload=payload, key=key)[1]['id'], case['id'])
            payload['observations'][0]['ocr_text'] = 'changed'
            self.assertEqual(fixture.call('POST', '/api/cases/visual', payload=payload, key=key)[0], 409)
        finally:
            fixture.tearDown()

    def test_visual_case_retains_text_but_not_inline_image_bytes(self):
        from email.message import EmailMessage
        from test_case_api import CaseAPITests
        image = base64.b64encode((app.BASE_DIR / 'tests/fixtures/vision/synthetic-qr.png').read_bytes()).decode()
        mail = EmailMessage()
        mail['Subject'] = 'Inline image'
        mail.set_content('Literal <style>URGENT</style> text. data:image/png;base64,' + image)
        mail.add_alternative('<p>Visible message</p><img src="data:image/png;base64,' + image + '">', subtype='html')
        fixture = CaseAPITests(); fixture.setUp()
        try:
            status, case, _ = fixture.call('POST', '/api/cases/visual', key='00000000-0000-4000-8000-000000000100', payload={
                'eml_base64': base64.b64encode(mail.as_bytes()).decode(),
                'observations': [observation(source='data-uri')]})
            self.assertEqual(status, 201)
            self.assertNotIn(image, json.dumps(case))
            self.assertIn('Literal <style>URGENT</style> text.', case['source']['body'])
            self.assertIn('Visible message', case['source']['body'])
            self.assertNotIn('<img', case['source']['body'])
            self.assertEqual(case['analysis']['visual_analysis']['observations'][0]['qr_payloads'],
                             ['https://paypa1.example/login'])
        finally:
            fixture.tearDown()

    def test_visual_case_marks_previously_truncated_text(self):
        raw = b'Subject: Large\n\n' + b'normal text ' * 10000
        source, _, _ = asyncio.run(app._analyze_case(app.VisualRequest(
            eml_base64=base64.b64encode(raw).decode()), None))
        self.assertTrue(source['text_truncated'])


if __name__ == '__main__':
    unittest.main()
