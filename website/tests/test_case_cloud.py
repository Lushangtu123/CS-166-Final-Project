"""Transport/security tests. Actual Redis Lua execution is a separate integration gate."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_cloud import UpstashCaseStore, CaseUnavailable, CREATE_SCRIPT, UPDATE_SCRIPT, LIST_SCRIPT
from case_store import CaseConflict, CaseInvalid, CaseNotFound


class CloudCaseTests(unittest.TestCase):
    def store(self, opener=None):
        return UpstashCaseStore('https://test-case.upstash.io', 'synthetic-token', 'test-workspace', opener=opener)

    def test_endpoint_and_namespace_validation(self):
        for url in ['http://test.upstash.io', 'https://upstash.io.evil.test', 'https://test.upstash.io/path', 'https://user@test.upstash.io']:
            with self.assertRaises(ValueError):
                UpstashCaseStore(url, 'token', 'test-workspace')
        with self.assertRaises(ValueError):
            UpstashCaseStore('https://test.upstash.io', 'token', '../prod')

    def test_rest_headers_body_and_timeout(self):
        captured = []
        def opener(request, timeout):
            captured.append((request, timeout))
            return io.BytesIO(b'{"result":null}')
        self.assertIsNone(self.store(opener).existing('alice', 'key', 'digest'))
        request, timeout = captured[0]
        self.assertEqual(timeout, 5)
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertNotIn('token', request.full_url)
        command = json.loads(request.data)
        self.assertEqual(command[0], 'HGET')
        self.assertEqual(command[1], 'phishguard:cases:v1:test-workspace')
        self.assertTrue(command[2].startswith('q:'))

    def test_errors_never_expose_credentials_or_report_success(self):
        for payload in [b'{"error":"secret-value"}', b'not-json', b'[]', b'x' * 4_000_001]:
            with self.subTest(payload=payload[:30]):
                with self.assertRaises(CaseUnavailable) as raised:
                    self.store(lambda *a, **kw: io.BytesIO(payload)).get('missing')
                self.assertNotIn('secret-value', str(raised.exception))
        with self.assertRaises(CaseUnavailable):
            self.store(Mock(side_effect=TimeoutError('secret-value'))).get('missing')

    def test_atomic_create_cas_update_and_limits(self):
        store = self.store()
        store.execute = Mock(side_effect=lambda *cmd: ['ok', cmd[7]])
        case = store.create(actor='alice', request_key='key', input_sha256='digest',
                            source={'subject': 'Synthetic', 'body': 'hello'},
                            analysis={'risk_level': 'low'}, provenance={})
        command = store.execute.call_args.args
        self.assertEqual(command[:3], ('EVAL', CREATE_SCRIPT, 1))
        self.assertEqual(case['events'][0]['actor'], 'alice')
        store.get = Mock(return_value=case)
        store.execute = Mock(return_value=['conflict'])
        with self.assertRaises(CaseConflict):
            store.update(case['id'], actor='bob', expected_version=1, status='in_progress', verdict=None, note='')
        command = store.execute.call_args.args
        self.assertEqual(command[:3], ('EVAL', UPDATE_SCRIPT, 1))
        updated = json.loads(command[6])
        self.assertEqual(updated['version'], 2)
        self.assertEqual(updated['events'][-1]['actor'], 'bob')
        self.assertEqual(updated['source']['body'], 'hello')
        for result, error in [(['capacity'], CaseInvalid), (['missing'], CaseNotFound), (['ok', False], CaseUnavailable)]:
            with self.assertRaises(error):
                store._result(result)
        with self.assertRaises(CaseInvalid):
            store._bounded({'body': 'x' * 750001})

    def test_cloud_filters_and_summary_only(self):
        store = self.store()
        store.execute = Mock(return_value=[json.dumps(dict(id=str(i), status=status, risk='high', created_at=f'2026-09-2{i}T00:00:00Z'))
                                           for i, status in [(0, 'pending'), (1, 'closed')]])
        result = store.list(status='closed', created_from='2026-09-21', limit=1)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['items'][0]['id'], '1')
        self.assertEqual(store.execute.call_args.args[:3], ('EVAL', LIST_SCRIPT, 1))

    def test_feedback_review_fields_are_saved_in_atomic_cloud_history(self):
        store = self.store()
        current = {'id': '00000000-0000-4000-8000-000000000001', 'title': 'Feedback',
                   'risk': 'high', 'status': 'in_progress', 'verdict': None, 'version': 2,
                   'created_at': '2026-09-22T00:00:00Z', 'updated_at': '2026-09-22T00:00:00Z',
                   'created_by': 'user_feedback', 'input_sha256': 'a' * 64,
                   'source': {'subject': 'Synthetic', 'body': 'Example'},
                   'analysis': {'risk_level': 'high'},
                   'provenance': {'record_kind': 'user_feedback', 'source_consent': True},
                   'events': [{'actor': 'user_feedback', 'happened_at': '2026-09-22T00:00:00Z',
                               'action': 'created', 'changes': {}, 'note': ''}]}
        store.get = Mock(return_value=current)
        store.execute = Mock(side_effect=lambda *command: ['ok', command[6]])
        saved = store.update(current['id'], actor='alice', expected_version=2,
                             status='closed', verdict='legitimate', note='Checked message',
                             feedback_reason='false_alert', evidence_basis='retained_message')
        self.assertEqual(saved['events'][-1]['changes']['feedback_reason']['to'], 'false_alert')
        self.assertEqual(store.execute.call_args.args[:3], ('EVAL', UPDATE_SCRIPT, 1))
