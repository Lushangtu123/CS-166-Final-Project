"""Shared history limits reserve forward workflow transitions, including legacy cases."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from test_case_opinions import synthetic_opinion
from case_store import CaseStore, CaseInvalid, bounded_record, history_capacity
from case_cloud import UpstashCaseStore


class HistoryTests(unittest.TestCase):
    def test_new_case_cannot_consume_workflow_byte_reserves(self):
        with tempfile.TemporaryDirectory() as tmp:
            local=CaseStore(Path(tmp)/'case.db')
            cloud=UpstashCaseStore('https://synthetic.upstash.io','synthetic','new-case-byte-limit')
            cloud.execute=Mock()
            for store in (local,cloud):
                with self.assertRaisesRegex(CaseInvalid,'reserved'):
                    store.create(actor='alice',request_key='oversized',input_sha256='f'*64,
                        source={'subject':'Synthetic'},analysis={'risk_level':'low','synthetic_evidence':'x'*650000},provenance={})
            self.assertEqual(local.capacity()['used'],0)
            cloud.execute.assert_not_called()

    def test_byte_reserve_keeps_a_full_unicode_closing_note_possible(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_id, stores = self.stores(tmp, 1, 'pending')
            for store in stores:
                with self.subTest(store=type(store).__name__):
                    current=store.update(case_id,actor='a'*64,expected_version=1,status='in_progress',verdict='legitimate',note='Start')
                    while True:
                        try:
                            current=store.update(case_id,actor='a'*64,expected_version=current['version'],status='in_progress',verdict='legitimate',note='🧪'*4000)
                        except CaseInvalid as exc:
                            self.assertIn('reserved',str(exc))
                            break
                    closed=store.update(case_id,actor='a'*64,expected_version=current['version'],status='closed',verdict='legitimate',note='🧪'*4000)
                    self.assertLessEqual(len(bounded_record(closed).encode()),750000)

    def test_legacy_byte_full_records_can_only_advance_and_archive(self):
        from tools.case_archive import validate_archive, restore_local
        from test_case_archive import archive_with, fields
        with tempfile.TemporaryDirectory() as tmp:
            local=CaseStore(Path(tmp)/'legacy.db')
            record=local.create(actor='alice',request_key='legacy',input_sha256='f'*64,
                source={'subject':'Synthetic'},analysis={'risk_level':'low'},provenance={})
            with local.connection(write=True) as db:
                count=1
                while True:
                    current=local._get(db,record['id'])
                    event=dict(actor='alice',happened_at=record['created_at'],action='reviewed',changes={},note='')
                    candidate=deepcopy(current); candidate['events'].append(event); candidate['version']+=1
                    room=750000-len(bounded_record(candidate).encode())
                    length=min(4000,room//12)
                    note='🧪'*length
                    final=room<48000
                    if final: note+='x'*(room%12)
                    local._event(db,record['id'],'alice',record['created_at'],'reviewed',{},note)
                    count+=1; db.execute('UPDATE cases SET version=? WHERE id=?',(count,record['id']))
                    if final: break
            full=local.get(record['id'])
            self.assertEqual(len(bounded_record(full).encode()),750000)
            state=deepcopy(full)
            cloud=UpstashCaseStore('https://synthetic.upstash.io','synthetic','test-bytes')
            cloud.get=Mock(side_effect=lambda _:deepcopy(state))
            def execute(*cmd):
                state.clear(); state.update(json.loads(cmd[6])); return ['ok',cmd[6]]
            cloud.execute=Mock(side_effect=execute)
            for store in (local,cloud):
                with self.subTest(store=type(store).__name__):
                    capacity=history_capacity(store.get(full['id']))
                    self.assertFalse(capacity['can_save_opinion'])
                    self.assertEqual(capacity['review_statuses'],['in_progress'])
                    self.assertEqual(capacity['bytes_remaining'],0)
                    with self.assertRaisesRegex(CaseInvalid,'reserved'):
                        store.update(full['id'],actor='alice',expected_version=full['version'],status='pending',verdict=None,note='More')
                    with self.assertRaises(CaseInvalid):
                        store.save_opinion(full['id'],actor='alice',expected_version=full['version'],opinion=synthetic_opinion())
                    started=store.update(full['id'],actor='a'*64,expected_version=full['version'],status='in_progress',verdict='legitimate',note='🧪'*4000)
                    closed=store.update(full['id'],actor='a'*64,expected_version=started['version'],status='closed',verdict='legitimate',note='🧪'*4000)
                    self.assertLessEqual(len(json.dumps(closed,separators=(',',':'),ensure_ascii=True).encode()),850000)
                    with self.assertRaises(CaseInvalid):
                        store.update(full['id'],actor='alice',expected_version=closed['version'],status='in_progress',verdict='legitimate',note='Reopen')
                    archive=archive_with(fields(closed)); validate_archive(archive)
                    destination=Path(tmp)/('bytes-restore-'+type(store).__name__)
                    restore_local(archive,destination)
                    self.assertEqual(CaseStore(destination/'case.sqlite3').get(full['id']),closed)

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
