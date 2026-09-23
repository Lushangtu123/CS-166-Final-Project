"""Review reasons must agree with definitive labels at every curation boundary."""
from copy import deepcopy
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from case_store import CaseStore, CaseInvalid
from case_cloud import UpstashCaseStore
from test_case_archive import record, fields, archive_with
from tools.export_reviewed_feedback import build_reviewed_draft
from tools.build_private_cohort import build_cohort
from test_build_private_cohort import draft, annotation


class FeedbackConsistencyTests(unittest.TestCase):
    def test_inconsistent_feedback_cannot_close_in_either_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            local=CaseStore(Path(tmp)/'cases.db')
            case=local.create(actor='user_feedback',request_key='synthetic',input_sha256='f'*64,
                source={'subject':'Synthetic'},analysis={'risk_level':'high'},
                provenance={'record_kind':'user_feedback','source_consent':True})
            current=local.update(case['id'],actor='alice',expected_version=1,status='in_progress',verdict='phishing',note='Investigating',feedback_reason='false_alert',evidence_basis='retained_message')
            cloud=UpstashCaseStore('https://synthetic.upstash.io','synthetic','feedback-consistency')
            cloud.get=Mock(side_effect=lambda _:deepcopy(current)); cloud.execute=Mock()
            for store in (local,cloud):
                for verdict,reason in [('phishing','false_alert'),('legitimate','missed_threat'),('uncertain','false_alert'),('phishing','insufficient_evidence')]:
                    with self.subTest(store=type(store).__name__,verdict=verdict,reason=reason):
                        with self.assertRaisesRegex(CaseInvalid,'reason.*verdict|verdict.*reason'):
                            store.update(case['id'],actor='alice',expected_version=2,status='closed',verdict=verdict,note='Review complete',feedback_reason=reason,evidence_basis='retained_message')
            cloud.execute.assert_not_called()
            closed=local.update(case['id'],actor='alice',expected_version=2,status='closed',verdict='phishing',note='Confirmed',feedback_reason='missed_threat')
            self.assertEqual(closed['status'],'closed')

    def test_legacy_contradictions_are_counted_and_excluded_from_draft(self):
        wrong=record(1,feedback=True,verdict='phishing')
        wrong['events'][-1]['changes']['feedback_reason']['to']='false_alert'
        valid=record(2,feedback=True,verdict='legitimate'); valid['source']['body']='Another synthetic email'
        rows,counts=build_reviewed_draft(archive_with(feedback_fields=fields(wrong,valid)))
        self.assertEqual([row['id'] for row in rows],[valid['id']])
        self.assertEqual(counts['inconsistent_review'],1)

    def test_older_draft_cannot_bypass_consistency_by_entering_cohort_directly(self):
        item=draft(1)
        item['review_reason']='missed_threat'
        with self.assertRaisesRegex(ValueError,'reason.*label|inconsistent'):
            build_cohort([item],[annotation(item)])
