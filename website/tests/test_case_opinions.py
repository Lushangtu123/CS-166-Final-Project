"""Cached opinions and explicit retention; no provider or cloud calls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_case_api as cases
from case_api import jev_control
from jev import MODEL, QUESTIONS, QUESTIONS_SHA256, prepare_case_input, input_state, _encoded
from jev_control import DAY, request_identity
from case_store import CaseStore, CaseConflict, CaseInvalid
from case_cloud import UpstashCaseStore, UPDATE_SCRIPT


def synthetic_opinion():
    return {'receipt_id':'a'*64, 'provider':'typesafe', 'model':MODEL,
            'requested_at':'2026-09-22T00:00:00Z', 'questions_sha256':QUESTIONS_SHA256,
            'input_sha256':'b'*64, 'probabilities':{key:0.75 for key in QUESTIONS},
            'evidence_incomplete':False, 'affects_risk':False}


class CaseOpinionTests(unittest.TestCase):
    setUp = cases.CaseAPITests.setUp
    tearDown = cases.CaseAPITests.tearDown
    call = cases.CaseAPITests.call
    create = cases.CaseAPITests.create

    def seed(self):
        _, case, _ = self.create()
        # Source parsing here follows the same injected functions as the live router.
        prepared = prepare_case_input(case['source'], case['analysis'],
            visible_text=cases.app._visible_content_text, mask_inline_data=cases.app._mask_inline_data_payloads)
        control = jev_control(cases.app.app.state.case_service)
        control.clock = lambda: 100 * DAY
        request_id = request_identity('alice', case['id'], prepared)
        claim = control.reserve(request_id, 20)
        result = {'status':'available', 'provider':'typesafe', 'mode':'shadow', 'affects_risk':False,
            'model':MODEL, 'questions_sha256':QUESTIONS_SHA256,
            'input_sha256':hashlib.sha256(_encoded(input_state(**prepared))).hexdigest(),
            'evidence_incomplete':prepared['evidence_incomplete'],
            'probabilities':{key:0.75 for key in QUESTIONS}}
        control.finish(request_id, claim['claim'], result, 20)
        return case, control, request_id

    def test_cached_lookup_and_explicit_save_need_no_provider_and_preserve_verdict(self):
        case, control, request_id = self.seed()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        with patch('case_api.jev_client', side_effect=AssertionError('No provider client')):
            status, found, headers = self.call('GET', path)
            self.assertEqual(status, 200)
            self.assertEqual(found['status'], 'available')
            self.assertEqual(headers[b'cache-control'], b'no-store')
            self.assertEqual(control.snapshot(20)['used'], 1)
            self.assertEqual(self.call('GET', path, token=None)[0], 401)
            save = {'expected_version':1, 'receipt_id':found['receipt_id'], 'confirm_save':True}
            self.assertEqual(self.call('POST', path + '/save', payload={**save,'confirm_save':False})[0], 422)
            self.assertEqual(self.call('POST', path + '/save', payload={**save,'probabilities':{}})[0], 422)
            status, saved, _ = self.call('POST', path + '/save', payload=save)
            self.assertEqual(status, 200)
            self.assertEqual(saved['version'], 2)
            for key in ('risk','status','verdict','source','analysis'):
                self.assertEqual(saved[key], case[key])
            event = saved['events'][-1]
            self.assertEqual(event['action'], 'auxiliary_saved')
            self.assertEqual(event['actor'], 'alice')
            opinion = event['changes']['auxiliary_opinion']['to']
            self.assertEqual(opinion['model'], MODEL)
            self.assertFalse(opinion['affects_risk'])
            self.assertNotIn('body', json.dumps(opinion))
            # Retrying a confirmed write remains safe even after the transient record expired.
            control.clock = lambda: 102 * DAY
            status, again, _ = self.call('POST', path + '/save', payload=save)
            self.assertEqual(status, 200)
            self.assertEqual(again['version'], 2)
            self.assertEqual(len(again['events']), 2)

    def test_missing_expired_wrong_actor_and_stale_revision_cannot_save(self):
        case, control, request_id = self.seed()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        receipt = control.lookup(request_id)
        save = {'expected_version':1,'receipt_id':receipt['receipt_id'],'confirm_save':True}
        bob = 'synthetic-bob-token-at-least-32-characters'
        cases.app.app.state.case_service.analysts['bob'] = hashlib.sha256(bob.encode()).hexdigest()
        with patch('case_api.jev_client', side_effect=AssertionError('No provider client')):
            self.assertEqual(self.call('GET', path, token=bob)[1]['reason'], 'no_cached_opinion')
            self.assertEqual(self.call('POST', path + '/save', token=bob, payload=save)[0], 409)
            self.assertEqual(self.call('POST', path + '/save', payload={**save,'receipt_id':'f'*64})[0], 409)
            self.call('PATCH', '/api/cases/' + case['id'], payload={'expected_version':1,'status':'in_progress'})
            self.assertEqual(self.call('POST', path + '/save', payload=save)[0], 409)
            control.clock = lambda: 102 * DAY
            self.assertEqual(self.call('GET', path)[1]['reason'], 'no_cached_opinion')
            self.assertEqual(self.call('POST', path + '/save', payload={**save,'expected_version':2})[0], 409)

    def test_pending_failure_invalid_result_and_storage_error_never_save(self):
        case, control, request_id = self.seed()
        path = '/api/cases/' + case['id'] + '/auxiliary'
        receipt = control.lookup(request_id)
        save = {'expected_version':1,'receipt_id':receipt['receipt_id'],'confirm_save':True}
        original = cases.app.app.state.case_service.store.get(case['id'])
        for result, expected in [({'status':'unavailable','reason':'provider_timeout'},409),
                                 ({**receipt['result'], 'input_sha256':'c'*64},409),
                                 ({**receipt['result'], 'probabilities':{'phishing_intent':float('nan')}},422)]:
            with patch.object(control,'lookup',return_value={**receipt,'result':result}):
                self.assertEqual(self.call('POST', path+'/save',payload=save)[0],expected)
        with patch.object(control,'lookup',return_value={'status':'pending'}):
            self.assertEqual(self.call('GET',path)[1]['reason'],'request_pending')
            self.assertEqual(self.call('POST',path+'/save',payload=save)[0],409)
        from case_cloud import CaseUnavailable
        with patch.object(control,'lookup',side_effect=CaseUnavailable('private-endpoint')):
            status, result, _ = self.call('GET',path)
            self.assertEqual(status,503)
            self.assertNotIn('private-endpoint',str(result))
        self.assertEqual(cases.app.app.state.case_service.store.get(case['id']),original)


class OpinionStoreTests(unittest.TestCase):
    def test_sqlite_duplicate_conflict_closed_bounds_and_archive_round_trip(self):
        from test_case_archive import archive_with, fields
        from tools.case_archive import restore_local
        with tempfile.TemporaryDirectory() as tmp:
            store = CaseStore(Path(tmp)/'source.db')
            case = store.create(actor='alice',request_key='synthetic',input_sha256='f'*64,
                source={'subject':'Synthetic','body':'Synthetic body'},analysis={'risk_level':'low'},provenance={})
            opinion = synthetic_opinion()
            saved = store.save_opinion(case['id'],actor='alice',expected_version=1,opinion=opinion)
            self.assertEqual(store.save_opinion(case['id'],actor='alice',expected_version=1,opinion=opinion),saved)
            with self.assertRaises(CaseConflict):
                store.save_opinion(case['id'],actor='bob',expected_version=1,opinion=opinion)
            updated = store.update(case['id'],actor='alice',expected_version=2,status='in_progress',verdict='legitimate',note='Reviewed')
            closed = store.update(case['id'],actor='alice',expected_version=3,status='closed',verdict='legitimate',note='Done')
            with self.assertRaises(CaseInvalid):
                store.save_opinion(case['id'],actor='bob',expected_version=4,opinion=opinion)
            restore_local(archive_with(fields(closed)),Path(tmp)/'restored')
            self.assertEqual(CaseStore(Path(tmp)/'restored/case.sqlite3').get(case['id']),closed)
            from case_opinions import opinion_changes
            for changed in ({**opinion,'affects_risk':True},{**opinion,'body':'Must never be copied'},
                            {**opinion,'requested_at':'not-a-date'}):
                with self.assertRaises(CaseInvalid):
                    opinion_changes(case,'alice',1,changed)
            with self.assertRaises(CaseInvalid):
                opinion_changes({**case,'events':[case['events'][0]]*200},'alice',1,opinion)

    def test_cloud_save_is_compare_and_swap_and_does_not_modify_detection(self):
        from unittest.mock import Mock
        from copy import deepcopy
        from test_case_archive import record
        store = UpstashCaseStore('https://synthetic.upstash.io','synthetic','synthetic-workspace')
        case = record(1,status='in_progress')
        store.get = Mock(side_effect=lambda _:deepcopy(case))
        store.execute = Mock(side_effect=lambda *cmd:['ok',cmd[6]])
        saved = store.save_opinion(case['id'],actor='alice',expected_version=2,opinion=synthetic_opinion())
        self.assertEqual(store.execute.call_args.args[:3],('EVAL',UPDATE_SCRIPT,1))
        self.assertEqual(saved['version'],3)
        for key in ('risk','status','verdict','source','analysis'):
            self.assertEqual(saved[key],case[key])
        store.execute.return_value=['conflict']; store.execute.side_effect=None
        with self.assertRaises(CaseConflict):
            store.save_opinion(case['id'],actor='alice',expected_version=2,opinion=synthetic_opinion())
        store.get.return_value=saved; store.get.side_effect=None; store.execute.reset_mock()
        self.assertEqual(store.save_opinion(case['id'],actor='alice',expected_version=2,opinion=synthetic_opinion()),saved)
        store.execute.assert_not_called()
