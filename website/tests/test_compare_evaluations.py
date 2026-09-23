"""Regression gates must not pass changed cohorts, missing metrics or failures."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.compare_evaluations import compare
from tools.evaluate_serving_pipeline import evaluate_records


PRIVATE_CONFIGURATION = {'trusted_authserv_ids': [], 'observe_sender_history': False,
                         'verification_mode': 'off', 'content_model_enabled': True,
                         'auxiliary_enabled': False}


def private_report(decisions=None):
    rows = [dict(provider=provider, language=language, received_at=month + '-01',
                 label=label, body=f'Synthetic {provider} {language} {month} {label}')
            for provider in ('gmail', 'outlook') for language in ('en', 'zh')
            for month in ('2026-08', '2026-09') for label in ('phishing', 'legitimate')]
    return evaluate_records(rows, lambda row: {
        'risk_level': (decisions or {}).get((row['provider'], row['language'], row['received_at'], row['label']),
                                           'high' if row['label'] == 'phishing' else 'safe'),
        'analysis_complete': True, 'ml_status': 'available'},
        model_sha256='a' * 64, configuration=PRIVATE_CONFIGURATION)


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
    def test_private_comparison_cli_exit_status_matches_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline, candidate = Path(directory) / 'baseline.json', Path(directory) / 'candidate.json'
            baseline.write_text(json.dumps(private_report()))
            candidate.write_text(baseline.read_text())
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/compare_evaluations.py'),
                       '--baseline', str(baseline), '--candidate', str(candidate)]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)['passed'])
            candidate.write_text(json.dumps(private_report({('gmail', 'en', '2026-08-01', 'phishing'): 'safe'})))
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertFalse(json.loads(completed.stdout)['passed'])
            self.assertNotIn('Synthetic', completed.stdout)

    def test_private_reports_compare_same_data_with_new_model_and_source(self):
        a = private_report(); b = copy.deepcopy(a)
        b['model_artifact_sha256'] = 'b' * 64
        b['reproducibility']['source_sha256'] = 'c' * 64
        result = compare(a, b)
        self.assertTrue(result['passed'], result['errors'])
        self.assertTrue(any('by_provider_language_month.' in item['metric'] for item in result['metrics']))

    def test_private_report_identity_configuration_and_inclusion_must_match(self):
        for path in [('schema_version',), ('scoring_sha256',), ('alert_policy',),
                     ('input_integrity', 'dataset_sha256'), ('input_integrity', 'evaluated_cohort_sha256'),
                     ('input_integrity', 'duplicate_policy'), ('input_integrity', 'deduplication'),
                     ('input_integrity', 'fingerprint_schema'), ('input_integrity', 'duplicate_rows'),
                     ('inclusion_policy',), ('reproducibility', 'configuration')]:
            a = private_report(); b = copy.deepcopy(a); target = b
            for key in path[:-1]: target = target[key]
            target[path[-1]] = 'changed'
            with self.subTest(path=path): self.assertFalse(compare(a, b)['passed'])
        a = private_report(); del a['schema_version']
        self.assertTrue(any('regenerate' in item.lower() for item in compare(a, a)['errors']))
        a = private_report(); a['reproducibility']['configuration'] = None
        self.assertFalse(compare(a, a)['passed'])
        a['reproducibility']['configuration'] = {}
        self.assertFalse(compare(a, a)['passed'])

    def test_private_intersection_regression_cannot_hide_in_unchanged_marginals(self):
        # Swap four decisions: each provider and language keeps identical totals.
        a = private_report({('gmail', 'en', '2026-08-01', 'phishing'): 'safe',
                            ('outlook', 'zh', '2026-08-01', 'phishing'): 'safe'})
        b = private_report({('gmail', 'zh', '2026-08-01', 'phishing'): 'safe',
                            ('outlook', 'en', '2026-08-01', 'phishing'): 'safe'})
        self.assertEqual(a['overall'], b['overall'])
        self.assertEqual(a['by_provider'], b['by_provider'])
        self.assertEqual(a['by_language'], b['by_language'])
        self.assertEqual(a['by_month'], b['by_month'])
        result = compare(a, b)
        self.assertFalse(result['passed'])
        self.assertTrue(any('Regression by_provider_language.' in error for error in result['errors']))

    def test_private_missing_malformed_and_inconsistent_groups_fail_closed(self):
        a = private_report()
        for dimension in ('by_provider', 'by_language', 'by_month', 'by_provider_language',
                          'by_provider_month', 'by_language_month', 'by_provider_language_month'):
            b = copy.deepcopy(a); b[dimension] = {}
            with self.subTest(dimension=dimension): self.assertFalse(compare(b, b)['passed'])
        for key, value in [('complete_count', True), ('ml_available_count', -1),
                           ('unknown_count', 1), ('complete_rate', .5),
                           ('phishing_alert_recall', float('nan'))]:
            b = copy.deepcopy(a); b['overall'][key] = value
            with self.subTest(key=key): self.assertFalse(compare(b, b)['passed'])
        b = copy.deepcopy(a); b['by_provider']['gmail']['phishing']['alerted'] -= 1
        self.assertFalse(compare(b, b)['passed'])

    def test_private_exact_counts_detect_changes_hidden_by_rounded_rates(self):
        rows = [dict(provider='gmail', language='en', received_at='2026-08-01',
                     label='phishing' if index < 25_001 else 'legitimate', body=f'Synthetic {index}')
                for index in range(50_002)]
        def evaluate(worse):
            return evaluate_records(rows, lambda row: {
                'risk_level': ('unknown' if worse and row['body'] == 'Synthetic 0' else
                               'medium' if worse and row['body'] == 'Synthetic 25001' else
                               'safe' if row['label'] == 'legitimate' else 'high'),
                'analysis_complete': not (worse and row['body'] == 'Synthetic 0'),
                'ml_status': 'unavailable' if worse and row['body'] == 'Synthetic 0' else 'available'},
                model_sha256='a' * 64, configuration=PRIVATE_CONFIGURATION)
        a, b = evaluate(False), evaluate(True)
        self.assertEqual(a['overall']['phishing_alert_recall'], b['overall']['phishing_alert_recall'])
        self.assertEqual(a['overall']['complete_rate'], b['overall']['complete_rate'])
        self.assertEqual(a['overall']['legitimate_false_alert_rate'], b['overall']['legitimate_false_alert_rate'])
        self.assertEqual(a['overall']['unknown_rate'], b['overall']['unknown_rate'])
        result = compare(a, b)
        self.assertFalse(result['passed'])
        for metric in ('phishing.alerted', 'legitimate.alerted', 'unknown_count', 'complete_count', 'ml_available_count'):
            self.assertIn('Regression overall.' + metric, result['errors'])

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
