import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import app
from case_api import build_case_service
from test_case_api import request, TOKEN


KEY = '00000000-0000-4000-8000-000000000099'
FINGERPRINT = 'sha256:' + 'a' * 64


def payload(**changes):
    value = {
        'report_type': 'false_positive', 'note': 'This seems legitimate',
        'include_source': False, 'input_mode': 'content',
        'input_fingerprint': FINGERPRINT,
        'analysis': {'risk_level': 'high', 'risk_score': 78,
                     'risk_label': 'High risk', 'analysis_complete': True,
                     'evidence_codes': ['high']},
        'source': None,
    }
    value.update(changes)
    return value


class FeedbackAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        env = {'CASE_MANAGEMENT_ENABLED': 'true',
               'CASE_DB_PATH': str(Path(self.temp.name) / 'cases.sqlite3'),
               'CASE_ANALYST_TOKEN_HASHES': json.dumps({
                   'alice': hashlib.sha256(TOKEN.encode()).hexdigest()})}
        self.previous = getattr(app.app.state, 'case_service', None)
        self.previous_error = getattr(app.app.state, 'case_configuration_error', False)
        app.app.state.case_service = build_case_service(env)
        app.app.state.case_configuration_error = False
        app._rate_limit_buckets.clear()

    def tearDown(self):
        app.app.state.case_service = self.previous
        app.app.state.case_configuration_error = self.previous_error
        app._rate_limit_buckets.clear()
        self.temp.cleanup()

    def call(self, method, path, **kwargs):
        return asyncio.run(request(method, path, **kwargs))

    def submit(self, value=None, key=KEY):
        return self.call('POST', '/api/feedback', payload=value or payload(), key=key, token=None)

    def test_default_report_is_private_source_free_and_idempotent(self):
        self.assertTrue(self.call('GET', '/api/config', token=None)[1]['feedback_enabled'])
        status, receipt, headers = self.submit()
        self.assertEqual(status, 201)
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(self.submit()[1], receipt)
        self.assertEqual(self.call('GET', '/api/cases?kind=feedback', token=None)[0], 401)
        status, queue, _ = self.call('GET', '/api/cases?kind=feedback')
        self.assertEqual(status, 200)
        self.assertEqual(queue['total'], 1)
        self.assertEqual(queue['items'][0]['kind'], 'feedback')
        self.assertEqual(self.call('GET', '/api/cases?kind=case')[1]['total'], 0)
        report = self.call('GET', '/api/cases/' + receipt['id'])[1]
        self.assertEqual(report['kind'], 'feedback')
        self.assertEqual(report['source']['body'], '')
        self.assertNotIn('This seems legitimate', json.dumps(report['source']))
        self.assertTrue(report['provenance']['client_reported'])
        self.assertFalse(report['provenance']['source_consent'])
        self.assertFalse(report['provenance']['evaluation_consent'])
        self.assertEqual(self.call('POST', '/api/cases/' + receipt['id'] + '/auxiliary',
                                   payload={'allow_external_processing': True})[0], 422)

    def test_explicit_source_is_reviewable_and_separate_from_cases(self):
        value = payload(include_source=True, evaluation_consent=True,
                        source={'subject': 'Payroll notice', 'body': 'Routine update'})
        status, receipt, _ = self.submit(value)
        self.assertEqual(status, 201)
        report = self.call('GET', '/api/cases/' + receipt['id'])[1]
        self.assertEqual(report['source']['body'], 'Routine update')
        self.assertTrue(report['provenance']['source_consent'])
        self.assertTrue(report['provenance']['evaluation_consent'])
        update = {'expected_version': 1, 'status': 'in_progress', 'verdict': 'legitimate',
                  'note': 'Checked the original content'}
        self.assertEqual(self.call('PATCH', '/api/cases/' + receipt['id'], payload=update)[0], 200)
        self.assertEqual(self.call('GET', '/api/cases?kind=case')[1]['total'], 0)
        self.assertEqual(self.call('GET', '/api/cases?kind=feedback&status=in_progress')[1]['total'], 1)

    def test_feedback_closure_requires_structured_reason_and_evidence(self):
        value = payload(include_source=True, evaluation_consent=True,
                        source={'subject': 'Synthetic', 'body': 'Routine mail'})
        _, receipt, _ = self.submit(value)
        path = '/api/cases/' + receipt['id']
        self.assertEqual(self.call('PATCH', path, payload={
            'expected_version': 1, 'status': 'in_progress', 'note': 'Investigating'})[0], 200)
        closure = {'expected_version': 2, 'status': 'closed', 'verdict': 'legitimate',
                   'note': 'Checked the saved message'}
        self.assertEqual(self.call('PATCH', path, payload=closure)[0], 422)
        self.assertEqual(self.call('PATCH', path, payload={**closure,
            'note': '', 'feedback_reason': 'false_alert', 'evidence_basis': 'retained_message'})[0], 422)
        self.assertEqual(self.call('PATCH', path, payload={**closure,
            'feedback_reason': 'false_alert', 'evidence_basis': 'report_only'})[0], 422)
        status, saved, _ = self.call('PATCH', path, payload={**closure,
            'feedback_reason': 'false_alert', 'evidence_basis': 'retained_message'})
        self.assertEqual(status, 200)
        self.assertEqual(saved['events'][-1]['changes']['feedback_reason']['to'], 'false_alert')
        self.assertEqual(saved['events'][-1]['changes']['evidence_basis']['to'], 'retained_message')

    def test_source_free_feedback_cannot_claim_retained_message(self):
        _, receipt, _ = self.submit()
        path = '/api/cases/' + receipt['id']
        self.assertEqual(self.call('PATCH', path, payload={
            'expected_version': 1, 'status': 'in_progress', 'note': 'Investigating'})[0], 200)
        closure = {'expected_version': 2, 'status': 'closed', 'verdict': 'phishing',
                   'note': 'Source was not supplied', 'feedback_reason': 'missed_threat'}
        self.assertEqual(self.call('PATCH', path, payload={**closure,
            'evidence_basis': 'retained_message'})[0], 422)
        self.assertEqual(self.call('PATCH', path, payload={**closure,
            'evidence_basis': 'report_only'})[0], 422)
        self.assertEqual(self.call('PATCH', path, payload={**closure,
            'verdict': 'uncertain', 'evidence_basis': 'report_only'})[0], 200)

    def test_in_progress_feedback_can_clear_an_incorrect_reason(self):
        _, receipt, _ = self.submit()
        path = '/api/cases/' + receipt['id']
        self.assertEqual(self.call('PATCH', path, payload={
            'expected_version': 1, 'status': 'in_progress', 'note': 'Initial triage',
            'feedback_reason': 'evidence_error', 'evidence_basis': 'report_only'})[0], 200)
        status, saved, _ = self.call('PATCH', path, payload={
            'expected_version': 2, 'status': 'in_progress', 'note': 'Need more information',
            'feedback_reason': '', 'evidence_basis': ''})
        self.assertEqual(status, 200)
        self.assertIsNone(saved['events'][-1]['changes']['feedback_reason']['to'])
        self.assertIsNone(saved['events'][-1]['changes']['evidence_basis']['to'])
        self.assertEqual(self.call('PATCH', path, payload={
            'expected_version': 3, 'status': 'closed', 'verdict': 'uncertain',
            'note': 'Still cannot confirm'})[0], 422)

    def test_consented_eml_keeps_original_bytes_but_image_keeps_only_extraction(self):
        raw = b'Subject: Synthetic\n\nnon-utf8 \xff'
        value = payload(input_mode='eml', include_source=True,
                        source={'eml_base64': base64.b64encode(raw).decode()})
        self.assertEqual(self.submit(value)[0], 201)
        report = self.call('GET', '/api/cases?kind=feedback')[1]['items'][0]
        saved = self.call('GET', '/api/cases/' + report['id'])[1]
        self.assertEqual(base64.b64decode(saved['source']['eml_base64']), raw)
        app._rate_limit_buckets.clear()
        image = payload(input_mode='image', include_source=True,
                        source={'ocr_text': 'Synthetic text', 'qr_text': 'https://example.test'})
        self.assertEqual(self.submit(image, key='00000000-0000-4000-8000-000000000098')[0], 201)
        latest = self.call('GET', '/api/cases?kind=feedback')[1]['items'][0]
        saved = self.call('GET', '/api/cases/' + latest['id'])[1]
        self.assertNotIn('image', json.dumps(saved['source']).lower())
        self.assertIn('Synthetic text', saved['source']['body'])

    def test_consent_and_size_validation(self):
        bad = [
            payload(evaluation_consent=True),
            payload(input_mode='image', include_source=True, evaluation_consent=True,
                    source={'ocr_text': 'example'}),
            payload(source={'body': 'private'}),
            payload(include_source=True, source=None),
            payload(include_source=True, source={'unknown': 'secret'}),
            payload(include_source=True, source={'body': 'data:image/png;base64,abc'}),
            payload(include_source='true', source={'body': 'private'}),
            payload(input_fingerprint='not a digest'),
            payload(note='x' * 2001),
            payload(analysis={'risk_level': 'high', 'evidence_codes': ['raw@email.example']}),
            payload(input_mode='eml', include_source=True,
                    source={'eml_base64': base64.b64encode(b'x' * 60001).decode()}),
            payload(input_mode='image', include_source=True, source={'ocr_text': 'data:image/png;base64,xyz'}),
        ]
        for index, value in enumerate(bad):
            with self.subTest(index=index):
                app._rate_limit_buckets.clear()
                self.assertEqual(self.submit(value)[0], 422)
        self.assertEqual(self.call('GET', '/api/cases?kind=feedback')[1]['total'], 0)

    def test_rate_limit_and_storage_outage_leave_analyzer_independent(self):
        for n in range(5):
            self.assertEqual(self.submit(payload(note=str(n)),
                              key=f'00000000-0000-4000-8000-{n:012d}')[0], 201)
        self.assertEqual(self.submit(key='00000000-0000-4000-8000-000000000090')[0], 429)
        app._rate_limit_buckets.clear()
        app.app.state.case_service = None
        self.assertEqual(self.submit()[0], 503)
        self.assertFalse(self.call('GET', '/api/config', token=None)[1]['feedback_enabled'])
        self.assertEqual(self.call('GET', '/health')[0], 200)

    def test_merged_queue_paginates_beyond_first_store_page(self):
        store = app.app.state.case_service.store
        for index in range(101):
            store.create(actor='alice', request_key=f'case-{index}', input_sha256='a' * 64,
                         source={'subject': f'Synthetic case {index}', 'body': ''},
                         analysis={'risk_level': 'low'}, provenance={})
        app._rate_limit_buckets.clear()
        self.assertEqual(self.submit()[0], 201)
        status, page, _ = self.call('GET', '/api/cases?kind=all&offset=100&limit=25')
        self.assertEqual(status, 200)
        self.assertEqual(page['total'], 102)
        self.assertEqual(len(page['items']), 2)
        self.assertEqual(self.call('GET', '/api/cases?kind=case&offset=100')[1]['total'], 101)

    def test_feedback_namespace_cannot_overlap_cases(self):
        cloud = {'CASE_MANAGEMENT_ENABLED': 'true', 'CASE_STORE': 'upstash',
                 'CASE_WORKSPACE': 'production-cases',
                 'CASE_FEEDBACK_WORKSPACE': 'production-cases',
                 'CASE_REDIS_REST_URL': 'https://synthetic.upstash.io',
                 'CASE_REDIS_REST_TOKEN': 'synthetic',
                 'CASE_ANALYST_TOKEN_HASHES': json.dumps({
                     'alice': hashlib.sha256(TOKEN.encode()).hexdigest()})}
        with self.assertRaisesRegex(ValueError, 'must differ'):
            build_case_service(cloud)
        cloud.pop('CASE_FEEDBACK_WORKSPACE')
        first = build_case_service({**cloud, 'CASE_WORKSPACE': 'a' * 60 + 'one'})
        second = build_case_service({**cloud, 'CASE_WORKSPACE': 'a' * 60 + 'two'})
        self.assertNotEqual(first.feedback_store.key, second.feedback_store.key)
        self.assertNotEqual(first.store.key, first.feedback_store.key)


if __name__ == '__main__':
    unittest.main()
