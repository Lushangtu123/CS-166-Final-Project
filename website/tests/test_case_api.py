import asyncio
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
        app.app.state.case_service = build_case_service(self.env)
        app._rate_limit_buckets.clear()
        self.model_patch = patch.object(app, '_content_pipeline', None)
        self.model_patch.start()

    def tearDown(self):
        self.model_patch.stop()
        app.app.state.case_service = self.previous
        self.temp.cleanup()

    def call(self, *args, **kwargs):
        return asyncio.run(request(*args, **kwargs))

    def create(self):
        return self.call('POST', '/api/cases', key='00000000-0000-4000-8000-000000000001',
                         payload={'subject': 'Review', 'body': '<a href="https://paypa1.example">Review</a>'})

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
            self.assertEqual(status, 503)
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
