"""Analyst feedback counts and filters use reviews, never public report claims."""
import json
from unittest.mock import Mock, patch
import unittest

import test_case_api as cases
from case_cloud import UpstashCaseStore, CaseUnavailable


class FeedbackOverviewTests(unittest.TestCase):
    setUp=cases.CaseAPITests.setUp
    tearDown=cases.CaseAPITests.tearDown
    call=cases.CaseAPITests.call

    def seed(self):
        store=cases.app.app.state.case_service.feedback_store
        ids=[]
        for i,(verdict,reason,basis,close) in enumerate([
            ('legitimate','false_alert','retained_message',True),
            ('phishing','missed_threat','external_verification',True),
            ('uncertain','false_alert','report_only',True),
            ('phishing','false_alert','external_verification',True),
            ('legitimate','false_alert','retained_message',False),
            (None,None,None,False)]):
            case=store.create(actor='user_feedback',request_key=str(i),input_sha256='f'*64,
                source={'subject':'Private title','body':'Private original message'},analysis={'risk_level':'high'},
                provenance={'record_kind':'user_feedback','source_consent':True,'report_type':'false_positive'})
            ids.append(case['id'])
            if verdict:
                store.update(case['id'],actor='alice',expected_version=1,status='in_progress',verdict=verdict,
                    note='Private assessment',feedback_reason=reason,evidence_basis=basis)
                if close: store.update(case['id'],actor='alice',expected_version=2,status='closed',verdict=verdict,note='Reviewed')
        return store,ids

    def test_overview_is_private_and_counts_only_supported_closed_findings(self):
        store,ids=self.seed()
        path='/api/cases/feedback-overview'
        self.assertEqual(self.call('GET',path,token=None)[0],401)
        status,result,headers=self.call('GET',path)
        self.assertEqual(status,200)
        self.assertEqual(result,{'status':'available','total':6,'pending':1,'in_progress':1,'closed':4,'false_alerts':1,'missed_threats':1})
        self.assertEqual(headers[b'cache-control'],b'no-store')
        for secret in ('Private',ids[0],'alice','subject','body'):
            self.assertNotIn(secret,json.dumps(result))
        store.update(ids[0],actor='alice',expected_version=3,status='in_progress',verdict='legitimate',note='Reopened')
        self.assertEqual(self.call('GET',path)[1]['false_alerts'],0)
        with patch.object(store,'feedback_overview',side_effect=CaseUnavailable('private storage endpoint')):
            self.assertEqual(self.call('GET',path)[1],{'status':'unavailable'})
        cases.app.app.state.case_service.feedback_store=None
        self.assertEqual(self.call('GET',path)[1],{'status':'disabled'})

    def test_verdict_and_reason_filters_apply_before_count_and_pagination(self):
        store,ids=self.seed()
        url='/api/cases?kind=feedback&verdict=legitimate&feedback_reason=false_alert&limit=1&offset=1'
        status,result,_=self.call('GET',url)
        self.assertEqual(status,200); self.assertEqual(result['total'],2)
        self.assertEqual(len(result['items']),1)
        self.assertEqual(result['items'][0]['verdict'],'legitimate')
        for query in ('verdict=invalid','kind=feedback&feedback_reason=invalid','kind=case&feedback_reason=false_alert','feedback_reason=false_alert'):
            self.assertEqual(self.call('GET','/api/cases?'+query)[0],422)
        for case_id in (ids[0],ids[4]):
            case=store.get(case_id)
            store.update(case_id,actor='alice',expected_version=case['version'],status='in_progress',verdict='legitimate',note='Revised',feedback_reason='no_issue_found')
        self.assertEqual(self.call('GET',url)[1]['total'],0)

    def test_cloud_uses_compact_review_metadata_without_modifying_storage(self):
        cloud=UpstashCaseStore('https://synthetic.upstash.io','synthetic','test-feedback')
        row={'id':'synthetic','title':'Private','created_at':'2026-09-22T00:00:00Z','risk':'high',
             'status':'closed','verdict':'legitimate','feedback_reason':'false_alert',
             'evidence_basis':'retained_message','source_consent':True,'record_kind':'user_feedback'}
        cloud.execute=Mock(return_value=[json.dumps(row)])
        self.assertEqual(cloud.feedback_overview()['false_alerts'],1)
        self.assertEqual(cloud.list(verdict='legitimate',feedback_reason='false_alert')['total'],1)
        self.assertEqual(cloud.list(feedback_reason='missed_threat')['total'],0)
        row['source_consent']=False
        cloud.execute.return_value=[json.dumps(row)]
        self.assertEqual(cloud.feedback_overview()['false_alerts'],0)
        self.assertTrue(all(call.args[0]=='EVAL' for call in cloud.execute.call_args_list))
