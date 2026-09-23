"""Execute production Lua against an isolated localhost Redis in CI.

Set PHISHGUARD_TEST_REDIS_PORT to opt in. Only random test namespaces are touched.
No external credentials, third-party Python client, or TypeSafe call is needed.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_cloud import UpstashCaseStore, CaseUnavailable
from jev_control import JevControl, DAY


class LocalRedis(UpstashCaseStore):
    def execute(self, *command):
        def read(stream):
            line = stream.readline()
            kind, data = line[:1], line[1:-2]
            if kind == b'+':
                return data.decode()
            if kind == b'-':
                raise CaseUnavailable('Local test Redis command failed')
            if kind == b':':
                return int(data)
            if kind == b'$':
                length = int(data)
                if length == -1:
                    return None
                value = stream.read(length)
                if stream.read(2) != b'\r\n':
                    raise CaseUnavailable('Invalid local Redis reply')
                return value.decode()
            if kind == b'*':
                return [read(stream) for _ in range(int(data))]
            raise CaseUnavailable('Invalid local Redis reply')
        parts = [str(value).encode() for value in command]
        wire = ('*%d\r\n' % len(parts)).encode() + b''.join(
            ('$%d\r\n' % len(part)).encode() + part + b'\r\n' for part in parts)
        with socket.create_connection(('127.0.0.1', int(os.environ['PHISHGUARD_TEST_REDIS_PORT'])), timeout=5) as client:
            client.sendall(wire)
            with client.makefile('rb') as stream:
                return read(stream)


@unittest.skipUnless(os.environ.get('PHISHGUARD_TEST_REDIS_PORT'), 'Local Redis integration service is not configured')
class JevRedisTests(unittest.TestCase):
    def setUp(self):
        self.store = LocalRedis('https://synthetic.upstash.io', 'synthetic', 'test-jev-' + uuid4().hex)
        self.control = JevControl(self.store, 'preview')
        self.production = JevControl(self.store, 'production')

    def tearDown(self):
        self.store.execute('DEL', self.control.key, self.production.key, self.store.key)

    def test_real_lua_concurrency_quota_and_cached_failures(self):
        self.store.execute('HSET', self.store.key, 'sentinel', 'untouched')
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: JevControl(self.store, 'preview').reserve('a' * 64, 3), range(8)))
        reserved = [result for result in results if result['status'] == 'reserved']
        self.assertEqual(len(reserved), 1)
        self.assertEqual(sum(r['status'] == 'pending' for r in results), 7)
        failure = {'status': 'unavailable', 'reason': 'provider_timeout'}
        self.control.finish('a' * 64, reserved[0]['claim'], failure, 3)
        self.assertEqual(self.control.reserve('a' * 64, 3)['result'], failure)
        with ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda i: self.control.reserve(f'{i:064x}', 3), range(8)))
        self.assertEqual(sum(r['status'] == 'reserved' for r in results), 2)
        self.assertEqual(self.control.snapshot(3)['used'], 3)
        self.assertEqual(self.production.snapshot(3)['used'], 0)
        self.assertEqual(self.store.execute('HGET', self.store.key, 'sentinel'), 'untouched')
        self.assertTrue(0 < self.store.execute('TTL', self.control.key) <= 2 * DAY)

    def test_real_lua_lookup_does_not_write_or_renew_receipts(self):
        self.assertEqual(self.control.lookup('a'*64), {'status':'missing'})
        self.assertEqual(self.store.execute('EXISTS',self.control.key),0)
        claim = self.control.reserve('a'*64,1)
        self.assertEqual(self.control.lookup('a'*64)['status'],'pending')
        self.control.finish('a'*64,claim['claim'],{'status':'available'},1)
        before = self.store.execute('HGETALL',self.control.key)
        ttl = self.store.execute('PTTL',self.control.key)
        cached = self.control.lookup('a'*64)
        self.assertEqual(cached['result'],{'status':'available'})
        self.assertEqual(self.store.execute('HGETALL',self.control.key),before)
        self.assertLessEqual(self.store.execute('PTTL',self.control.key),ttl)
        self.assertNotIn('claim',cached)
        entry=json.loads(self.store.execute('HGET',self.control.key,'r:'+'a'*64))
        entry['expires_at']=1
        self.store.execute('HSET',self.control.key,'r:'+'a'*64,json.dumps(entry))
        self.assertEqual(self.control.lookup('a'*64),{'status':'missing'})
        self.assertIsNotNone(self.store.execute('HGET',self.control.key,'r:'+'a'*64))

    def test_real_lua_opinion_save_preserves_indexes_and_retries_once(self):
        from test_case_opinions import synthetic_opinion
        from case_store import CaseConflict
        case=self.store.create(actor='alice',request_key='synthetic',input_sha256='f'*64,
            source={'subject':'Synthetic','body':'Synthetic'},analysis={'risk_level':'low'},provenance={})
        def save(_):
            try:
                return self.store.save_opinion(case['id'],actor='alice',expected_version=1,opinion=synthetic_opinion())
            except CaseConflict:
                return None
        with ThreadPoolExecutor(4) as pool:
            results=list(pool.map(save,range(4)))
        self.assertTrue(any(results))
        saved=self.store.save_opinion(case['id'],actor='alice',expected_version=1,opinion=synthetic_opinion())
        self.assertEqual(saved['version'],2)
        self.assertEqual(len(saved['events']),2)
        self.assertEqual(saved['status'],'pending')
        self.assertEqual(self.store.capacity(),{'used':1,'limit':100})
        self.assertEqual(self.store.existing('alice','synthetic','f'*64),saved)
        self.assertEqual(self.store.list()['items'][0]['version'],2)

    def test_real_lua_midnight_retains_receipt_then_expiry_allows_new_claim(self):
        first = self.control.reserve('b' * 64, 1)
        snapshot = self.control.snapshot(1)
        yesterday = snapshot['reset_at'] // DAY - 2
        self.store.execute('HSET', self.control.key, 'day', yesterday)
        self.assertEqual(self.control.snapshot(1)['used'], 0)
        self.assertEqual(self.control.reserve('b' * 64, 1)['status'], 'pending')
        field = 'r:' + 'b' * 64
        raw = json.loads(self.store.execute('HGET', self.control.key, field))
        raw['expires_at'] = 1
        self.store.execute('HSET', self.control.key, field, json.dumps(raw))
        second = self.control.reserve('b' * 64, 1)
        self.assertEqual(second['status'], 'reserved')
        self.assertNotEqual(first['claim'], second['claim'])
        with self.assertRaises(CaseUnavailable):
            self.control.finish('b' * 64, first['claim'], {'status': 'available'}, 1)
        self.control.finish('b' * 64, second['claim'], {'status': 'available'}, 1)
        self.control.finish('b' * 64, second['claim'], {'status': 'different'}, 1)
        self.assertEqual(self.control.reserve('b' * 64, 1)['result']['status'], 'available')

    def test_real_lua_release_unsent_is_idempotent_and_claim_bound(self):
        first = self.control.reserve('c' * 64, 2)
        with ThreadPoolExecutor(8) as pool:
            list(pool.map(lambda _: self.control.release_unsent('c' * 64, first['claim'], 2), range(8)))
        self.assertEqual(self.control.snapshot(2)['used'], 0)
        new = self.control.reserve('c' * 64, 2)
        with self.assertRaises(CaseUnavailable):
            self.control.release_unsent('c' * 64, first['claim'], 2)
        self.control.finish('c' * 64, new['claim'], {'status': 'unavailable', 'reason': 'provider_timeout'}, 2)
        with self.assertRaises(CaseUnavailable):
            self.control.release_unsent('c' * 64, new['claim'], 2)
        self.assertEqual(self.control.snapshot(2)['used'], 1)
        self.assertEqual(self.control.reserve('c' * 64, 2)['status'], 'cached')

    def test_real_lua_release_previous_day_does_not_refund_current_day(self):
        first = self.control.reserve('d' * 64, 2)
        field = 'r:' + 'd' * 64
        entry = json.loads(self.store.execute('HGET', self.control.key, field))
        # The receipt was reserved yesterday. Simulate one unrelated attempt today.
        entry['expires_at'] -= DAY
        self.store.execute('HSET', self.control.key, field, json.dumps(entry))
        self.control.release_unsent('d' * 64, first['claim'], 2)
        self.assertEqual(self.control.snapshot(2)['used'], 1)
        self.assertEqual(self.control.reserve('d' * 64, 2)['status'], 'reserved')


if __name__ == '__main__':
    unittest.main()
