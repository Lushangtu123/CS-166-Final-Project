"""Public evaluation contracts: provenance, isolation and denominator integrity."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.evaluation_data import load_corpus
from tools.evaluate_public_corpus import evaluate_corpus


class PublicEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def corpus(self, rows, name='evaluation', source=None):
        records = self.root / (name + '.jsonl')
        records.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        manifest = self.root / (name + '.json')
        manifest.write_text(json.dumps({'schema_version': 1, 'records': records.name,
            'sources': [source or {'id': 'fixture', 'url': 'https://example.org/fixture',
                'revision': 'v1', 'license': 'CC0-1.0', 'label_basis': 'Synthetic regression fixture'}]}))
        return manifest

    def row(self, **changes):
        return {'id': 'r1', 'source_id': 'fixture', 'label': 'legitimate',
                'subject': 'Team meeting', 'body': 'Our meeting is tomorrow. Please bring your project notes.', **changes}

    def evaluate(self, path, analyze=None, reference=None):
        return evaluate_corpus(load_corpus(path), analyze or (lambda row: {'risk_level': 'unknown'}),
            model_sha256='a' * 64, reference=load_corpus(reference) if reference else None)

    def test_unknown_metadata_and_unknown_decisions_remain_in_denominators(self):
        report = self.evaluate(self.corpus([self.row(), self.row(id='r2', label='phishing', body='Send money now')]))
        self.assertEqual(report['counts']['evaluated'], 2)
        self.assertEqual(report['overall']['unknown_rate'], 1)
        self.assertEqual(report['overall']['phishing_alert_recall'], 0)
        self.assertEqual(report['by_provider']['unknown']['n'], 2)
        self.assertEqual(report['training_independence'], 'not_verified')
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertNotIn('Send money', json.dumps(report))

    def test_exact_duplicates_dropped_and_conflicting_labels_rejected(self):
        report = self.evaluate(self.corpus([self.row(), self.row(id='r2')]))
        self.assertEqual(report['counts']['duplicates'], 1)
        self.assertEqual(report['counts']['input'], 2)
        with self.assertRaisesRegex(ValueError, 'conflicting labels'):
            self.evaluate(self.corpus([self.row(), self.row(id='r2', label='phishing')]))

    def test_reference_exact_and_template_overlap_excluded(self):
        body = 'Please review the attached project invoice for account 12345 before Friday and visit https://example.org/a to view the complete details.'
        ref = self.corpus([self.row(body=body)], 'reference')
        candidate = self.corpus([self.row(body=body), self.row(id='r2', body=body.replace('12345', '98765').replace('/a ', '/b ')), self.row(id='r3')])
        report = self.evaluate(candidate, reference=ref)
        self.assertEqual(report['counts']['overlap_exact'], 1)
        self.assertEqual(report['counts']['overlap_template'], 1)
        self.assertEqual(report['counts']['evaluated'], 1)
        self.assertEqual(report['counts']['excluded'], 2)
        self.assertEqual(report['training_independence'], 'not_verified')

    def test_failures_retained_as_undetermined_without_leaking_error(self):
        def fail(row):
            raise RuntimeError('secret message and /private/mail')
        report = self.evaluate(self.corpus([self.row()]), fail)
        self.assertEqual(report['counts']['failures'], 1)
        self.assertEqual(report['counts']['evaluated'], 1)
        self.assertEqual(report['overall']['unknown_rate'], 1)
        self.assertNotIn('secret message', json.dumps(report))

    def test_missing_provenance_invalid_labels_and_missing_files_fail_closed(self):
        for row in (self.row(label='spam'), self.row(label=[]), self.row(source_id={}),
                    self.row(eml_path='missing.eml', subject='', body='')):
            with self.subTest(row=row), self.assertRaises(ValueError):
                load_corpus(self.corpus([row]))
        with self.assertRaises(ValueError):
            load_corpus(self.corpus([self.row()], source={'id': 'fixture'}))

    def test_eml_snapshot_hash_validation_and_path_containment(self):
        raw = b'Subject: Test\n\nA safe synthetic test message.'
        (self.root / 'message.eml').write_bytes(raw)
        row = self.row(eml_path='message.eml', subject='', body='', content_sha256=hashlib.sha256(raw).hexdigest())
        corpus = load_corpus(self.corpus([row]))
        (self.root / 'message.eml').write_bytes(b'changed')
        seen = []
        evaluate_corpus(corpus, lambda row: seen.append(row['_eml_bytes']) or {'risk_level': 'low'}, model_sha256='a'*64)
        self.assertEqual(seen, [raw])
        with self.assertRaisesRegex(ValueError, 'hash'):
            load_corpus(self.corpus([row]))
        for unsafe in ('../outside.eml', '/etc/passwd'):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                load_corpus(self.corpus([self.row(eml_path=unsafe, subject='', body='')]))

    def test_evaluated_cohort_identity_tracks_filtered_records_not_just_counts(self):
        corpus = load_corpus(self.corpus([self.row(), self.row(id='r2', body='Second message'),
                                       self.row(id='r3', body='Third message')]))
        reference = load_corpus(self.corpus([self.row(id='ref', body='Reference message')], 'reference'))
        reference.records[0]['_template_sha256'] = 'matched-template'
        corpus.records[0]['_template_sha256'] = 'matched-template'
        corpus.records[1]['_template_sha256'] = 'other-template'
        analyze = lambda row: {'risk_level': 'unknown'}
        first = evaluate_corpus(corpus, analyze, model_sha256='a'*64, reference=reference)
        corpus.records[0]['_template_sha256'] = 'other-template'
        corpus.records[1]['_template_sha256'] = 'matched-template'
        second = evaluate_corpus(corpus, analyze, model_sha256='a'*64, reference=reference)
        self.assertEqual(first['dataset_sha256'], second['dataset_sha256'])
        self.assertEqual(first['counts'], second['counts'])
        self.assertNotEqual(first['evaluated_cohort_sha256'], second['evaluated_cohort_sha256'])

    def test_inference_failure_does_not_change_evaluated_cohort_and_scoring_hash_tracks_interval_rule(self):
        corpus = load_corpus(self.corpus([self.row()]))
        first = evaluate_corpus(corpus, lambda row: {'risk_level': 'low'}, model_sha256='a'*64)
        second = evaluate_corpus(corpus, lambda row: None, model_sha256='a'*64)
        self.assertEqual(first['evaluated_cohort_sha256'], second['evaluated_cohort_sha256'])
        self.assertEqual(first['scoring_sha256'], second['scoring_sha256'])
        with patch('tools.evaluate_serving_pipeline.WILSON_95_Z', 1.0):
            changed = evaluate_corpus(corpus, lambda row: None, model_sha256='a'*64)
        self.assertNotEqual(first['scoring_sha256'], changed['scoring_sha256'])

    def test_empty_evaluation_after_overlap_is_explicit_and_does_not_analyze(self):
        def never(row):
            self.fail('Excluded overlap must not reach inference')
        reference = self.corpus([self.row()], 'reference')
        report = self.evaluate(self.corpus([self.row()]), never, reference)
        self.assertEqual(report['counts']['evaluated'], 0)
        self.assertEqual(report['counts']['excluded'], 1)
        self.assertIsNone(report['overall']['unknown_rate'])

    def test_size_and_symlink_boundaries(self):
        with self.assertRaises(ValueError):
            load_corpus(self.corpus([self.row(body='x' * 60_001)]))
        outside = self.root.parent / (self.root.name + '-outside.eml')
        outside.write_bytes(b'Subject: private\n\nDo not read outside corpus')
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        (self.root / 'link.eml').symlink_to(outside)
        with self.assertRaises(ValueError):
            load_corpus(self.corpus([self.row(eml_path='link.eml', subject='', body='')]))

    def test_fingerprint_order_independent_but_records_provenance_changes(self):
        one, two = self.row(), self.row(id='r2', body='Different body')
        first = self.evaluate(self.corpus([one, two]))['dataset_sha256']
        second = self.evaluate(self.corpus([two, one]))['dataset_sha256']
        self.assertEqual(first, second)
        changed = self.evaluate(self.corpus([one, {**two, 'label': 'phishing'}]))['dataset_sha256']
        self.assertNotEqual(first, changed)

    def test_cli_with_committed_model_reports_reproducibility(self):
        project = Path(__file__).resolve().parents[2]
        if f'{sys.version_info.major}.{sys.version_info.minor}' != (project / '.python-version').read_text().strip():
            self.skipTest('Committed model requires deployment Python version')
        source = self.corpus([self.row()])
        result = subprocess.run([sys.executable, str(project / 'website/tools/evaluate_public_corpus.py'), '--manifest', str(source)],
            capture_output=True, text=True, cwd=project, env={**os.environ,
                'TRUSTED_AUTHSERV_IDS': 'untrusted.example', 'SENDER_HISTORY_ENABLED': 'true',
                'CASE_MANAGEMENT_ENABLED': 'true', 'EMAIL_VERIFICATION_ENABLED': 'true'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['counts']['input'], 1)
        self.assertTrue(report['reproducibility']['evaluator_sha256'])
        self.assertEqual(report['reproducibility']['configuration']['observe_sender_history'], False)
        self.assertEqual(report['reproducibility']['configuration']['trusted_authserv_ids'], [])


if __name__ == '__main__':
    unittest.main()
