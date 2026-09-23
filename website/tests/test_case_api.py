import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from case_api import build_case_service

TOKEN = 'synthetic-alice-token-with-at-least-32-characters'


async def request(method, path, *, payload=None, raw=None, token=TOKEN, key=None):
    from urllib.parse import urlsplit
    url = urlsplit(path)
    headers = [(b'host', b'localhost')]
    if token:
        headers.append((b'authorization', ('Bearer ' + token).encode()))
    if key:
        headers.append((b'idempotency-key', key.encode()))
    body = raw if raw is not None else json.dumps(payload).encode() if payload is not None else b''
    headers.append((b'content-type', b'message/rfc822' if raw is not None else b'application/json'))
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
             'method': method, 'scheme': 'http', 'path': url.path, 'raw_path': url.path.encode(),
             'query_string': url.query.encode(), 'root_path': '', 'headers': headers,
             'client': ('127.0.0.1', 12345), 'server': ('localhost', 8000)}
    sent = False
    output = []
    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {'type': 'http.request', 'body': body, 'more_body': False}
        await asyncio.Event().wait()
    async def send(event):
        output.append(event)
    await asyncio.wait_for(app.app(scope, receive, send), 10)
    start = next(e for e in output if e['type'] == 'http.response.start')
    content = b''.join(e.get('body', b'') for e in output if e['type'] == 'http.response.body')
    return start['status'], json.loads(content), dict(start['headers'])


class CaseAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {'CASE_MANAGEMENT_ENABLED': 'true',
                    'CASE_DB_PATH': str(Path(self.temp.name) / 'cases.sqlite3'),
                    'CASE_ANALYST_TOKEN_HASHES': json.dumps({'alice': hashlib.sha256(TOKEN.encode()).hexdigest()})}
        self.previous = getattr(app.app.state, 'case_service', None)
        self.previous_error = getattr(app.app.state, 'case_configuration_error', False)
        app.app.state.case_configuration_error = False
        app.app.state.case_service = build_case_service(self.env)
        app._rate_limit_buckets.clear()
        self.model_patch = patch.object(app, '_content_pipeline', None)
        self.model_patch.start()

    def tearDown(self):
        self.model_patch.stop()
        app.app.state.case_service = self.previous
        app.app.state.case_configuration_error = self.previous_error
        self.temp.cleanup()

    def call(self, *args, **kwargs):
        return asyncio.run(request(*args, **kwargs))

    def test_invalid_token_identifies_the_deployment_scope(self):
        self.env['VERCEL_ENV'] = 'production'
        app.app.state.case_service = build_case_service(self.env)

        status, result, _ = self.call(
            'GET', '/api/cases/me', token='invalid-token-that-is-still-long-enough-1234')

        self.assertEqual(status, 401)
        self.assertEqual(
            result['detail'],
            'A valid analyst access token is required for this production deployment. '
            'Production and Preview credentials are separate.',
        )
        self.assertNotIn('invalid-token', result['detail'])

    def create(self):
        return self.call('POST', '/api/cases', key='00000000-0000-4000-8000-000000000001',
                         payload={'subject': 'Review', 'body': '<a href="https://paypa1.example">Review</a>'})

    def test_capacity_is_private_unfiltered_and_each_store_can_fail_independently(self):
        from case_cloud import CaseUnavailable
        service = app.app.state.case_service
        self.assertEqual(self.call('GET', '/api/cases/capacity', token=None)[0], 401)
        self.create()
        status, result, headers = self.call('GET', '/api/cases/capacity?status=closed')
        self.assertEqual(status, 200)
        self.assertEqual(result, {'cases': {'status': 'available', 'used': 1, 'limit': None},
                                  'feedback': {'status': 'available', 'used': 0, 'limit': None}})
        self.assertEqual(headers[b'cache-control'], b'no-store')
        with patch.object(service.store, 'capacity', side_effect=CaseUnavailable('private-store-url')):
            status, result, _ = self.call('GET', '/api/cases/capacity')
        self.assertEqual(status, 200)
        self.assertEqual(result['cases'], {'status': 'unavailable'})
        self.assertEqual(result['feedback']['used'], 0)
        self.assertNotIn('private-store-url', str(result))
        self.assertEqual(self.call('GET', '/api/cases')[0], 200)

    def test_partial_list_keeps_healthy_records_and_explicit_kind_isolates_detail_and_review(self):
        from case_cloud import CaseUnavailable
        service = app.app.state.case_service
        self.create()
        feedback = service.feedback_store.create(actor='user_feedback', request_key='synthetic',
            input_sha256='a' * 64, source={'subject':'Synthetic','body':''},
            analysis={'risk_level':'low'}, provenance={'record_kind':'user_feedback'})
        with patch.object(service.store, 'list', side_effect=CaseUnavailable('secret endpoint')):
            status, result, _ = self.call('GET', '/api/cases')
            self.assertEqual(status, 200)
            self.assertTrue(result['partial'])
            self.assertEqual(result['total'], 1)
            self.assertEqual(result['sources'], {'case':'unavailable','feedback':'available'})
            self.assertEqual(result['items'][0]['id'], feedback['id'])
            self.assertNotIn('secret endpoint', str(result))
            self.assertEqual(self.call('GET', '/api/cases?kind=case')[0], 503)
            with patch.object(service.feedback_store, 'list', side_effect=CaseUnavailable('offline')):
                self.assertEqual(self.call('GET', '/api/cases')[0], 503)
        path = '/api/cases/' + feedback['id'] + '?kind=feedback'
        with patch.object(service.store, 'get', side_effect=CaseUnavailable('offline')) as other:
            self.assertEqual(self.call('GET', path)[0], 200)
            self.assertEqual(self.call('PATCH', path, payload={'expected_version':1,
                'status':'in_progress','note':'Checking source'})[0], 200)
            other.assert_not_called()
        self.assertEqual(self.call('GET', path, token=None)[0], 401)
        self.assertEqual(self.call('GET', path.replace('feedback','invalid'))[0], 422)

    def test_auxiliary_auth_consent_disabled_and_unchanged_case(self):
        from jev import JevClient
        from unittest.mock import Mock
        _, case, _ = self.create()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        client = JevClient(enabled=True, key='synthetic')
        client.evaluate = Mock(return_value={'status': 'available', 'affects_risk': False})
        with patch('case_api.jev_client', return_value=client):
            self.assertEqual(self.call('POST', path, token=None, payload={'allow_external_processing': True})[0], 401)
            for consent in (False, 'true', 1, None):
                self.assertEqual(self.call('POST', path, payload={'allow_external_processing': consent})[0], 422)
            client.evaluate.assert_not_called()
            status, result, headers = self.call('POST', path, payload={'allow_external_processing': True})
            self.assertEqual(status, 200)
            self.assertFalse(result['affects_risk'])
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertEqual(self.call('GET', '/api/cases/' + case['id'])[1], case)
            prepared = client.evaluate.call_args.kwargs
            self.assertNotIn('<a ', prepared['body'])
            client.enabled = False
            self.assertEqual(self.call('POST', path, payload={'allow_external_processing': True})[0], 503)

    def test_saved_mime_plain_text_is_preserved_for_auxiliary_analysis(self):
        raw = b'Subject: Review\nContent-Type: text/plain\n\nVisit <https://evil.example/login> to verify'
        status, case, _ = self.call('POST', '/api/cases/eml', raw=raw,
                                   key='00000000-0000-4000-8000-000000000004')
        self.assertEqual(status, 201)
        self.assertIn('<https://evil.example/login>', case['source']['auxiliary_text'])

    def test_auxiliary_retries_reuse_result_across_service_instances(self):
        from jev import JevClient
        from unittest.mock import Mock
        _, case, _ = self.create()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        client = JevClient(enabled=True, key='synthetic')
        client.evaluate = Mock(return_value={'status': 'unavailable', 'reason': 'provider_timeout', 'affects_risk': False})
        with patch('case_api.jev_client', return_value=client):
            first = self.call('POST', path, payload={'allow_external_processing': True})
            app.app.state.case_service = build_case_service(self.env)
            second = self.call('POST', path, payload={'allow_external_processing': True})
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(second[1]['reason'], 'provider_timeout')
        self.assertTrue(second[1]['reused'])
        client.evaluate.assert_called_once()

    def test_local_capacity_failure_releases_allowance_for_manual_retry(self):
        import io
        import jev
        import threading
        from case_api import jev_control
        from tests.test_jev import answer
        from unittest.mock import Mock
        _, case, _ = self.create()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        opener = Mock(return_value=io.BytesIO(json.dumps(answer()).encode()))
        client = jev.JevClient('synthetic', enabled=True, max_calls=1, opener=opener)
        with patch('case_api.jev_client', return_value=client), patch.dict('os.environ', {'PHISHGUARD_JEV_DAILY_LIMIT': '1'}):
            # Exercise the real adapter's local rejection before any provider I/O.
            with patch('jev._INFLIGHT', threading.BoundedSemaphore(0)):
                status, result, _ = self.call('POST', path, payload={'allow_external_processing': True})
            self.assertEqual(status, 200)
            self.assertEqual(result['reason'], 'local_capacity_exhausted')
            opener.assert_not_called()
            self.assertEqual(jev_control(app.app.state.case_service).snapshot(1)['used'], 0)
            self.assertIsNone(result['receipt_expires_at'])
            status, result, _ = self.call('POST', path, payload={'allow_external_processing': True})
            self.assertEqual(status, 200)
            self.assertEqual(result['status'], 'available')
            self.assertFalse(result['reused'])
            self.assertEqual(result['quota']['used'], 1)
            opener.assert_called_once()

    def test_uncertain_release_failure_keeps_pending_receipt_and_does_not_retry(self):
        from case_api import jev_control
        from case_cloud import CaseUnavailable
        from jev import JevClient
        from unittest.mock import Mock
        _, case, _ = self.create()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        control = jev_control(app.app.state.case_service)
        client = JevClient('synthetic', enabled=True)
        client.evaluate = Mock(return_value={'status': 'unavailable', 'reason': 'local_capacity_exhausted', 'affects_risk': False})
        with patch('case_api.jev_client', return_value=client):
            with patch.object(control, 'release_unsent', side_effect=CaseUnavailable('private error')):
                status, result, _ = self.call('POST', path, payload={'allow_external_processing': True})
                self.assertEqual(status, 503)
                self.assertNotIn('private error', json.dumps(result))
            status, result, _ = self.call('POST', path, payload={'allow_external_processing': True})
            self.assertEqual(status, 200)
            self.assertEqual(result['reason'], 'request_pending')
            self.assertEqual(result['quota']['used'], 1)
        client.evaluate.assert_called_once()

    def test_me_explains_configuration_without_exposing_key(self):
        with patch.dict('os.environ', {'PHISHGUARD_JEV_ENABLED': 'true', 'TYPESAFE_API_KEY': ''}):
            status, result, _ = self.call('GET', '/api/cases/me')
        self.assertEqual(status, 200)
        self.assertEqual(result['jev']['status'], 'configuration_error')
        self.assertFalse(result['jev_available'])

    def test_daily_quota_blocks_new_calls_but_permits_existing_receipts(self):
        from jev import JevClient
        from unittest.mock import Mock
        _, case, _ = self.create()
        _, another, _ = self.call('POST', '/api/cases', key='00000000-0000-4000-8000-000000000003',
                                  payload={'body': 'A different message'})
        client = JevClient(enabled=True, key='synthetic')
        client.evaluate = Mock(return_value={'status': 'available', 'affects_risk': False})
        settings = {'PHISHGUARD_JEV_ENABLED': 'true', 'PHISHGUARD_JEV_DAILY_LIMIT': '1', 'TYPESAFE_API_KEY': 'synthetic'}
        with patch('case_api.jev_client', return_value=client), patch.dict('os.environ', settings):
            def opinion(item):
                return self.call('POST', '/api/cases/' + item['id'] + '/auxiliary', payload={'allow_external_processing': True})
            self.assertEqual(opinion(case)[1]['status'], 'available')
            self.assertEqual(opinion(another)[1]['reason'], 'daily_quota_exhausted')
            status, me, _ = self.call('GET', '/api/cases/me')
            self.assertEqual(status, 200)
            self.assertEqual(me['jev']['status'], 'quota_exhausted')
            self.assertEqual(me['jev']['used'], 1)
            self.assertTrue(opinion(case)[1]['reused'])
        client.evaluate.assert_called_once()

    def test_storage_failure_before_or_after_provider_never_retries_automatically(self):
        from case_cloud import CaseUnavailable
        from case_api import jev_control
        from jev import JevClient
        from unittest.mock import Mock
        _, case, _ = self.create()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        control = jev_control(app.app.state.case_service)
        client = JevClient(enabled=True, key='synthetic')
        client.evaluate = Mock(return_value={'status': 'available', 'affects_risk': False})
        with patch('case_api.jev_client', return_value=client):
            with patch.object(control, 'reserve', side_effect=CaseUnavailable('private-error')):
                self.assertEqual(self.call('POST', path, payload={'allow_external_processing': True})[0], 503)
            client.evaluate.assert_not_called()
            with patch.object(control, 'finish', side_effect=CaseUnavailable('private-error')):
                status, body, _ = self.call('POST', path, payload={'allow_external_processing': True})
                self.assertEqual(status, 503)
                self.assertNotIn('private-error', json.dumps(body))
            status, body, _ = self.call('POST', path, payload={'allow_external_processing': True})
            self.assertEqual(status, 200)
            self.assertEqual(body['reason'], 'request_pending')
        client.evaluate.assert_called_once()

    def test_public_jev_flags_never_call_provider_or_storage(self):
        from case_cloud import CaseUnavailable
        settings = {'PHISHGUARD_JEV_ENABLED': 'true', 'TYPESAFE_API_KEY': 'synthetic-private-key'}
        with patch.dict('os.environ', settings), patch('case_api.jev_client') as client, \
                patch('case_api.jev_control', side_effect=CaseUnavailable('private-store-error')) as control:
            for path in ('/health', '/api/config'):
                status, result, _ = self.call('GET', path, token=None)
                self.assertEqual(status, 200)
                self.assertTrue(result['jev_configured'])
                self.assertTrue(result['jev_enabled'])
                self.assertNotIn('synthetic-private-key', json.dumps(result))
            control.assert_not_called()
            status, me, _ = self.call('GET', '/api/cases/me')
            self.assertEqual(status, 200)
            self.assertEqual(me['jev']['status'], 'control_unavailable')
            client.assert_not_called()

    def test_disabled_and_invalid_configuration_fail_closed(self):
        self.assertIsNone(build_case_service({}))
        for changes in ({'VERCEL': '1'}, {'CASE_DB_PATH': 'relative.db'},
                        {'CASE_ANALYST_TOKEN_HASHES': '{}'}):
            with self.assertRaises(ValueError):
                build_case_service({**self.env, **changes})
        app.app.state.case_service = None
        self.assertEqual(self.call('GET', '/api/cases')[0], 404)

    def test_every_data_route_requires_auth_and_is_not_cached(self):
        for method, path in [('GET', '/api/cases'), ('GET', '/api/cases/me'),
                             ('GET', '/api/cases/missing'), ('POST', '/api/cases'),
                             ('POST', '/api/cases/eml'), ('PATCH', '/api/cases/missing')]:
            with self.subTest(path=path):
                status, _, headers = self.call(method, path, token=None, payload={})
                self.assertEqual(status, 401)
                self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertEqual(self.call('GET', '/api/cases', token='wrong')[0], 401)

    def test_real_analysis_review_history_and_conflicts(self):
        status, case, _ = self.create()
        self.assertEqual(status, 201)
        self.assertEqual(case['risk'], 'high')
        self.assertEqual(case['created_by'], 'alice')
        self.assertRegex(case['provenance']['code_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(self.create()[1]['id'], case['id'])
        path = '/api/cases/' + case['id']
        update = {'expected_version': 1, 'status': 'in_progress', 'verdict': 'phishing', 'note': 'Confirmed link'}
        status, changed, _ = self.call('PATCH', path, payload=update)
        self.assertEqual(status, 200)
        self.assertEqual(changed['events'][-1]['actor'], 'alice')
        self.assertEqual(self.call('PATCH', path, payload=update)[0], 409)
        self.assertEqual(self.call('GET', '/api/cases?status=pending')[1]['total'], 0)
        self.assertEqual(self.call('GET', '/api/cases?risk=high')[1]['total'], 1)
        self.assertEqual(self.call('GET', '/api/cases?created_from=invalid')[0], 422)
        self.assertEqual(self.call('GET', '/api/cases?created_from=2026-10-01&created_to=2026-01-01')[0], 422)
        self.assertEqual(self.call('PATCH', path, payload={
            'expected_version': 2, 'status': 'in_progress', 'note': 'Unexpected feedback fields',
            'feedback_reason': 'false_alert'})[0], 422)

    def test_original_eml_bytes_and_no_client_verdict_override(self):
        raw = b'Subject: Uploaded\nContent-Type: text/html\n\n<a href="https://paypa1.example">Review</a>'
        status, case, _ = self.call('POST', '/api/cases/eml', raw=raw,
                                   key='00000000-0000-4000-8000-000000000002')
        self.assertEqual(status, 201)
        self.assertEqual(case['risk'], 'high')
        self.assertEqual(case['source']['subject'], 'Uploaded')
        self.assertNotIn('raw_bytes', case['source'])
        status, _, _ = self.call('POST', '/api/cases', payload={'body': 'hello', 'analysis': {'risk_level': 'safe'}},
                                key='00000000-0000-4000-8000-000000000003')
        self.assertEqual(status, 422)
        status, _, _ = self.call('POST', '/api/cases/eml', raw=raw + b'changed',
                                key='00000000-0000-4000-8000-000000000002')
        self.assertEqual(status, 409)

    def test_two_analysts_authorship_and_outage(self):
        from case_cloud import CaseUnavailable
        bob = 'synthetic-bob-token-at-least-32-characters'
        app.app.state.case_service.analysts['bob'] = hashlib.sha256(bob.encode()).hexdigest()
        _, case, _ = self.create()
        status, changed, _ = self.call('PATCH', '/api/cases/' + case['id'], token=bob,
            payload={'expected_version': 1, 'status': 'in_progress', 'note': 'Bob took this case'})
        self.assertEqual(status, 200)
        self.assertEqual(changed['events'][-1]['actor'], 'bob')
        with patch.object(app.app.state.case_service.store, 'list', side_effect=CaseUnavailable('secret token')):
            status, body, headers = self.call('GET', '/api/cases')
            self.assertEqual(status, 200)
            self.assertTrue(body['partial'])
            self.assertEqual(body['sources']['case'], 'unavailable')
            self.assertNotIn('secret token', str(body))
            self.assertEqual(headers[b'cache-control'], b'no-store')

    def test_cloud_config_requires_private_namespace_and_unique_identities(self):
        cloud = {**self.env, 'VERCEL': '1', 'CASE_STORE': 'upstash', 'CASE_WORKSPACE': 'production-cases',
                 'UPSTASH_REDIS_REST_URL': 'https://synthetic.upstash.io', 'UPSTASH_REDIS_REST_TOKEN': 'test'}
        self.assertIsNotNone(build_case_service(cloud))
        for changes in [{'CASE_WORKSPACE': ''}, {'CASE_STORE': 'other'}, {'CASE_ANALYST_TOKEN_HASHES':
                        json.dumps({'alice': hashlib.sha256(TOKEN.encode()).hexdigest(), 'bob': hashlib.sha256(TOKEN.encode()).hexdigest()})}]:
            with self.assertRaises(ValueError):
                build_case_service({**cloud, **changes})

    def test_invalid_optional_config_does_not_break_public_service(self):
        async def check():
            with patch.dict('os.environ', {'CASE_MANAGEMENT_ENABLED': 'true',
                                         'CASE_ANALYST_TOKEN_HASHES': 'not-json'}), \
                 patch.object(app, 'SETTINGS', replace(app.SETTINGS, content_model_enabled=False)):
                async with app.lifespan(app.app):
                    status, health, _ = await request('GET', '/health', token=None)
                    self.assertEqual(status, 200)
                    self.assertEqual(health['status'], 'ok')
                    status, analysis, _ = await request('POST', '/api/analyze-content', token=None,
                        payload={'subject': 'Synthetic', 'body': '<a href="https://paypa1.example">Review</a>'})
                    self.assertEqual(status, 200)
                    self.assertEqual(analysis['risk_level'], 'high')
                    for method, path in [('GET', '/api/cases'), ('POST', '/api/cases'),
                                         ('GET', '/api/cases/me'), ('PATCH', '/api/cases/missing')]:
                        status, body, headers = await request(method, path, token=None, payload={})
                        self.assertEqual(status, 503)
                        self.assertEqual(headers[b'cache-control'], b'no-store')
                        self.assertNotIn('not-json', str(body))
        asyncio.run(check())
