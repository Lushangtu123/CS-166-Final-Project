import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_store import CaseStore
from case_cloud import UpstashCaseStore, CaseUnavailable
from jev_control import JevControl, DAY, request_identity


def identity(number):
    return hashlib.sha256(str(number).encode()).hexdigest()


class JevControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CaseStore(Path(self.temp.name) / 'cases.db')
        self.now = 10 * DAY + 100
        self.control = JevControl(self.store, clock=lambda: self.now)

    def tearDown(self):
        self.temp.cleanup()

    def test_quota_survives_new_instances_and_resets_at_utc_midnight(self):
        self.assertEqual(self.control.reserve(identity(1), 1)['status'], 'reserved')
        other = JevControl(self.store, clock=lambda: self.now)
        self.assertEqual(other.reserve(identity(2), 1)['status'], 'quota_exhausted')
        self.now = 11 * DAY
        self.assertEqual(other.snapshot(1)['used'], 0)
        self.assertEqual(other.reserve(identity(1), 1)['status'], 'pending')
        self.assertEqual(other.reserve(identity(2), 1)['status'], 'reserved')
        self.assertEqual(other.snapshot(1)['reset_at'], 12 * DAY)

    def test_result_and_uncertain_receipts_block_duplicates_for_24_hours(self):
        claim = self.control.reserve(identity(1), 1)
        result = {'status': 'unavailable', 'reason': 'provider_timeout'}
        self.control.finish(identity(1), claim['claim'], result, 1)
        cached = self.control.reserve(identity(1), 1)
        self.assertEqual(cached['status'], 'cached')
        self.assertEqual(cached['result'], result)
        self.now += DAY
        self.assertEqual(self.control.reserve(identity(1), 1)['status'], 'reserved')
        with self.assertRaises(CaseUnavailable):
            self.control.finish(identity(1), claim['claim'], result, 1)

    def test_concurrent_instances_cannot_exceed_budget_or_double_reserve(self):
        controls = [JevControl(self.store, clock=lambda: self.now) for _ in range(8)]
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda pair: pair[1].reserve(identity(pair[0]), 3), enumerate(controls)))
        self.assertEqual(sum(r['status'] == 'reserved' for r in results), 3)
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda c: c.reserve(identity('same'), 20), controls))
        self.assertEqual(sum(r['status'] == 'reserved' for r in results), 1)
        self.assertEqual(sum(r['status'] == 'pending' for r in results), 7)

    def test_environments_do_not_share_budget(self):
        preview = JevControl(self.store, 'preview', clock=lambda: self.now)
        production = JevControl(self.store, 'production', clock=lambda: self.now)
        preview.reserve(identity(1), 1)
        self.assertEqual(production.reserve(identity(1), 1)['status'], 'reserved')

    def test_identity_tracks_actor_case_model_questions_and_redacted_input(self):
        from unittest.mock import patch
        prepared = {'subject': 'Notice', 'body': 'Write alice@example.test https://example.test/?secret=1'}
        first = request_identity('alice', 'case-1', prepared)
        self.assertNotEqual(first, request_identity('bob', 'case-1', prepared))
        self.assertNotEqual(first, request_identity('alice', 'case-2', prepared))
        self.assertNotEqual(first, request_identity('alice', 'case-1', {**prepared, 'evidence_incomplete': True}))
        for constant in ('MODEL', 'QUESTIONS_SHA256'):
            with patch('jev_control.' + constant, 'changed'):
                self.assertNotEqual(first, request_identity('alice', 'case-1', prepared))
        redacted_equivalent = {**prepared, 'body': 'Write bob@example.test https://example.test/?secret=2'}
        self.assertEqual(first, request_identity('alice', 'case-1', redacted_equivalent))

    def test_redis_uses_separate_key_and_fails_closed_on_malformed_reply(self):
        store = UpstashCaseStore('https://synthetic.upstash.io', 'synthetic', 'workspace')
        control = JevControl(store, 'preview')
        store.execute = Mock(return_value=json.dumps({'used': 0, 'daily_limit': 20, 'reset_at': DAY}))
        self.assertEqual(control.snapshot(20)['used'], 0)
        command = store.execute.call_args.args
        self.assertEqual(command[0], 'EVAL')
        self.assertEqual(command[2:4], (1, 'phishguard:jev:v1:workspace:preview'))
        for response in (None, '{}', '[]', '{"status":"reserved"}', 'invalid'):
            store.execute.return_value = response
            with self.assertRaises(CaseUnavailable):
                control.reserve(identity(1), 20)


if __name__ == '__main__':
    unittest.main()
