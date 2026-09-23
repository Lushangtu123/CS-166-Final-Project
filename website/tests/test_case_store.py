import concurrent.futures
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_store import CaseStore, CaseConflict, CaseInvalid, CaseNotFound


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'cases.sqlite3'
        self.store = CaseStore(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def create(self, key='first', digest='a' * 64):
        return self.store.create(actor='alice', request_key=key, input_sha256=digest,
            source={'subject': 'Review meeting', 'body': '<script>private</script>'},
            analysis={'risk_level': 'high', 'analysis_complete': True},
            provenance={'code_sha256': 'b' * 64, 'model_sha256': None})

    def test_creation_persists_evidence_and_initial_event_across_restart(self):
        case = self.create()
        loaded = CaseStore(self.path).get(case['id'])
        self.assertEqual(case, loaded)
        self.assertEqual(loaded['status'], 'pending')
        self.assertEqual(loaded['version'], 1)
        self.assertIsNone(loaded['verdict'])
        self.assertEqual(loaded['events'][0]['actor'], 'alice')
        self.assertEqual(loaded['events'][0]['action'], 'created')
        self.assertEqual(loaded['source']['body'], '<script>private</script>')

    def test_capacity_counts_all_records_without_inventing_a_sqlite_limit(self):
        self.assertEqual(self.store.capacity(), {'used': 0, 'limit': None})
        case = self.create()
        self.store.update(case['id'], actor='alice', expected_version=1,
                          status='in_progress', verdict=None, note='Started')
        self.assertEqual(self.store.capacity(), {'used': 1, 'limit': None})

    def test_idempotent_create_and_conflicting_reuse(self):
        first = self.create()
        self.assertEqual(first['id'], self.create()['id'])
        self.assertEqual(len(self.store.get(first['id'])['events']), 1)
        with self.assertRaises(CaseConflict):
            self.create(digest='c' * 64)
        self.assertEqual(self.store.list()['total'], 1)

    def test_review_close_reopen_and_stale_write(self):
        case = self.create()
        with self.assertRaises(CaseInvalid):
            self.store.update(case['id'], actor='bob', expected_version=1,
                              status='closed', verdict=None, note='Reviewed')
        changed = self.store.update(case['id'], actor='bob', expected_version=1,
                                   status='in_progress', verdict='phishing', note='Confirmed impersonation')
        self.assertEqual(changed['version'], 2)
        with self.assertRaises(CaseConflict):
            self.store.update(case['id'], actor='alice', expected_version=1,
                              status='closed', verdict='legitimate', note='Stale')
        closed = self.store.update(case['id'], actor='bob', expected_version=2,
                                  status='closed', verdict='phishing', note='Review complete')
        with self.assertRaises(CaseInvalid):
            self.store.update(case['id'], actor='alice', expected_version=3,
                              status='closed', verdict='legitimate', note='Change without reopening')
        reopened = self.store.update(case['id'], actor='alice', expected_version=3,
                                    status='in_progress', verdict='phishing', note='New evidence')
        self.assertEqual([e['actor'] for e in reopened['events']], ['alice', 'bob', 'bob', 'alice'])
        self.assertEqual(len(reopened['events']), 4)
        self.assertEqual(closed['analysis'], case['analysis'])

    def test_concurrent_writes_cannot_overwrite_each_other(self):
        case = self.create()
        def change(actor):
            try:
                self.store.update(case['id'], actor=actor, expected_version=1,
                                  status='in_progress', verdict='uncertain', note=actor)
                return 'saved'
            except CaseConflict:
                return 'conflict'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(change, ['alice', 'bob']))
        self.assertCountEqual(results, ['saved', 'conflict'])
        self.assertEqual(len(self.store.get(case['id'])['events']), 2)

    def test_list_filters_pagination_and_no_private_evidence(self):
        first = self.create()
        self.create('second')
        self.store.update(first['id'], actor='alice', expected_version=1,
                          status='in_progress', verdict=None, note='Assigned')
        self.assertEqual(self.store.list(status='pending')['total'], 1)
        self.assertEqual(self.store.list(risk='safe')['total'], 0)
        self.assertEqual(self.store.list(created_from='2999-01-01')['total'], 0)
        page = self.store.list(limit=1, offset=1)
        self.assertEqual(page['total'], 2)
        self.assertEqual(len(page['items']), 1)
        self.assertNotIn('source', page['items'][0])
        self.assertNotIn('analysis', page['items'][0])
        with self.assertRaises(CaseNotFound):
            self.store.get('missing')


if __name__ == '__main__':
    unittest.main()
