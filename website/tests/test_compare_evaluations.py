"""Regression gates must not pass changed cohorts, missing metrics or failures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.compare_evaluations import compare


def report():
    return {'schema_version':1, 'evaluation_scope':'public_corpus_local_serving_pipeline',
        'dataset_sha256':'a'*64, 'manifest_sha256':'b'*64, 'records_sha256':'c'*64,
        'evaluated_cohort_sha256':'e'*64,'scoring_sha256':'f'*64, 'alert_policy':'medium/high/critical', 'exploratory_only':True,
        'overlap_check':{'reference_dataset_sha256':None,'status':'not_verified','template_algorithm':'fixed-v1'},
        'reproducibility':{'configuration':{'observe_sender_history':False}},
        'counts':{'input':20,'evaluated':20,'duplicates':0,'overlap_exact':0,'overlap_template':0,'excluded':0,'failures':0},
        'overall':{'n':20,'phishing_count':10,'legitimate_count':10,
            'phishing_alert_recall':.9,'legitimate_false_alert_rate':.1,'unknown_rate':0,
            'complete_rate':1,'ml_available_rate':1},
        'by_source':{},'by_provider':{},'by_language':{},'by_month':{}}


class ComparisonTests(unittest.TestCase):
    def test_same_cohort_passes_and_new_code_or_model_can_be_compared(self):
        a=report(); b=copy.deepcopy(a); b['model_artifact_sha256']='new model'
        self.assertTrue(compare(a,b)['passed'])

    def test_recall_false_alert_unknown_and_coverage_regressions_fail(self):
        for key,value in [('phishing_alert_recall',.8),('legitimate_false_alert_rate',.2),
                          ('unknown_rate',.1),('complete_rate',.9),('ml_available_rate',.8)]:
            a=report(); b=copy.deepcopy(a); b['overall'][key]=value
            with self.subTest(key=key): self.assertFalse(compare(a,b)['passed'])

    def test_changed_cohort_configuration_and_exclusions_fail(self):
        for field in ['dataset_sha256','manifest_sha256','records_sha256','evaluated_cohort_sha256','scoring_sha256','alert_policy','exploratory_only']:
            a=report(); b=copy.deepcopy(a); b[field]='changed'
            with self.subTest(field=field): self.assertFalse(compare(a,b)['passed'])
        a=report(); b=copy.deepcopy(a); b['counts']['excluded']=1
        self.assertFalse(compare(a,b)['passed'])
        b=copy.deepcopy(a); b['reproducibility']['configuration']={}
        self.assertFalse(compare(a,b)['passed'])

    def test_missing_nonfinite_boolean_and_empty_metrics_fail_closed(self):
        for value in [None,float('nan'),float('inf'),True,-.1,1.1]:
            a=report(); b=copy.deepcopy(a); b['overall']['phishing_alert_recall']=value
            with self.subTest(value=value): self.assertFalse(compare(a,b)['passed'])
        self.assertFalse(compare({}, {})['passed'])
        a=report(); a['overall']['phishing_count']=0
        self.assertFalse(compare(a,a)['passed'])

    def test_failed_run_cannot_be_baseline_or_candidate(self):
        a=report(); a['counts']['failures']=1
        self.assertFalse(compare(a,a)['passed'])

    def test_group_regression_cannot_be_hidden_by_overall_improvement(self):
        a=report(); a['by_language']['en']=copy.deepcopy(a['overall'])
        b=copy.deepcopy(a); b['overall']['phishing_alert_recall']=1
        b['by_language']['en']['phishing_alert_recall']=.8
        self.assertFalse(compare(a,b)['passed'])

    def test_visual_compares_cohort_and_keeps_missing_rows(self):
        a={'schema_version':'phishguard-vision-benchmark/v1','dataset_id':'owned',
            'identity':{'manifest_sha256':'d'*64,'risk_requested':False,'asset_manifest_verified':True,'evaluation_sha256':{'metrics.mjs':'c'*64}},
            'semantics':{'text':'strict'},'records':[{'id':'r','language':'eng','label':'unknown','reference_characters':5,'expected_qr_count':1,'urls_scored':True}],
            'summary':{'count':1,'statuses':{'processed':1,'partial':0,'missing':0},'reference_characters':5,'qr_positive_count':1,'url_scored_count':1,'english_count':1,'risk_labeled_count':0,
                'character_error_rate':0,'text_exact_rate':1,'qr_exact_set_rate':1,'qr_positive_exact_set_rate':1,'qr_payload_recall':1,'qr_extra_payload_count':0,'url_exact_set_rate':1,'unexpected_han_image_rate':0,'empty_reference_false_text_count':0},'by_language':{}}
        self.assertTrue(compare(a,a)['passed'])
        b=copy.deepcopy(a); b['summary']['character_error_rate']=.2
        self.assertFalse(compare(a,b)['passed'])
        b=copy.deepcopy(a); b['summary']['statuses']={'processed':0,'missing':1}
        self.assertFalse(compare(a,b)['passed'])
        b=copy.deepcopy(a); b['identity']['evaluation_sha256']['metrics.mjs']='b'*64
        self.assertFalse(compare(a,b)['passed'])
        b=copy.deepcopy(a); b['identity']['asset_manifest_verified']=False
        self.assertFalse(compare(a,b)['passed'])

if __name__=='__main__': unittest.main()
