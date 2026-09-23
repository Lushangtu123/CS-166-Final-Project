"""Shared history limits reserve forward workflow transitions, including legacy cases."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from test_case_opinions import synthetic_opinion
from case_store import CaseStore, CaseInvalid
from case_cloud import UpstashCaseStore


class HistoryTests(unittest.TestCase):
    def stores(self, tmp, count, status):
        local = CaseStore(Path(tmp)/'case.db')
        record = local.create(actor='alice', request_key='synthetic', input_sha256='f'*64,
            source={'subject':'Synthetic','body':'Synthetic'}, analysis={'risk_level':'low'}, provenance={})
        with local.connection(write=True) as db:
            for _ in range(count-1):
                local._event(db,record['id'],'alice',record['created_at'],'reviewed',{},'Synthetic note')
            db.execute('UPDATE cases SET version=?,status=?,verdict=? WHERE id=?',
                       (count,status,'legitimate',record['id']))
        state = local.get(record['id'])
        cloud = UpstashCaseStore('https://synthetic.upstash.io','synthetic','test-history')
        cloud.get = Mock(side_effect=lambda _:deepcopy(state))
        def execute(*cmd):
            self.assertEqual(cmd[0],'EVAL')
            self.assertEqual(int(cmd[5]),state['version'])
            state.clear(); state.update(json.loads(cmd[6]))
            return ['ok',cmd[6]]
        cloud.execute = Mock(side_effect=execute)
        return record['id'], (local,cloud)

    def test_last_slots_cannot_be_used_for_notes_or_opinions(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_id,stores = self.stores(tmp,198,'pending')
            for store in stores:
                with self.subTest(store=type(store).__name__):
                    with self.assertRaisesRegex(CaseInvalid,'reserved'):
                        store.update(case_id,actor='alice',expected_version=198,status='pending',verdict='legitimate',note='One more note')
                    with self.assertRaisesRegex(CaseInvalid,'reserved'):
                        store.save_opinion(case_id,actor='alice',expected_version=198,opinion=synthetic_opinion())
                    store.update(case_id,actor='alice',expected_version=198,status='in_progress',verdict='legitimate',note='Start')
                    with self.assertRaisesRegex(CaseInvalid,'reserved'):
                        store.save_opinion(case_id,actor='alice',expected_version=199,opinion=synthetic_opinion())
                    closed=store.update(case_id,actor='alice',expected_version=199,status='closed',verdict='legitimate',note='Completed')
                    self.assertEqual(len(closed['events']),200)
                    with self.assertRaises(CaseInvalid):
                        store.update(case_id,actor='alice',expected_version=200,status='in_progress',verdict='legitimate',note='Reopen')

    def test_existing_full_case_can_finish_once_and_archive_round_trip(self):
        from tools.case_archive import validate_archive, restore_local
        from test_case_archive import archive_with, fields
        with tempfile.TemporaryDirectory() as tmp:
            case_id,stores = self.stores(tmp,200,'pending')
            for store in stores:
                with self.subTest(store=type(store).__name__):
                    store.update(case_id,actor='alice',expected_version=200,status='in_progress',verdict='legitimate',note='Start')
                    with self.assertRaises(CaseInvalid):
                        store.update(case_id,actor='alice',expected_version=201,status='in_progress',verdict='legitimate',note='More notes')
                    closed=store.update(case_id,actor='alice',expected_version=201,status='closed',verdict='legitimate',note='Completed')
                    self.assertEqual(len(closed['events']),202)
                    archive = archive_with(fields(closed))
                    self.assertEqual(validate_archive(archive)['case'][0][case_id],closed)
                    destination = Path(tmp) / ('restore-' + type(store).__name__)
                    self.assertEqual(restore_local(archive, destination), {'case':1, 'feedback':0})
                    self.assertEqual(CaseStore(destination / 'case.sqlite3').get(case_id), closed)
                    with self.assertRaises(CaseInvalid):
                        store.update(case_id,actor='alice',expected_version=202,status='in_progress',verdict='legitimate',note='Reopen')
