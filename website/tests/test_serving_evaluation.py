import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline


class ServingEvaluationTests(unittest.TestCase):
    def test_eml_bytes_are_parsed_without_loading_version_specific_model(self):
        import app
        from config import load_settings
        for charset, body in (
            ('gb18030', '您的账户存在异常，请立即验证'),
            ('iso-8859-1', 'Please review the regular project meeting notes. Hébergement.'),
        ):
            with self.subTest(charset=charset), tempfile.TemporaryDirectory() as directory:
                email_file = Path(directory) / 'original.eml'
                raw = (f'Content-Type: text/plain; charset={charset}\n'
                       'Content-Transfer-Encoding: 8bit\n\n').encode() + body.encode(charset)
                email_file.write_bytes(raw)
                with patch.object(app, '_content_pipeline', None), \
                        patch.object(app, 'SETTINGS', load_settings({})), \
                        patch.object(app, 'analyze_raw_email', wraps=app.analyze_raw_email) as parse:
                    result = evaluate_serving_pipeline.analyze_record({'eml_path': str(email_file)})
                self.assertEqual(parse.call_args.args[0], raw)
                self.assertEqual(result['message_structure']['parse_warnings'], [])

    def test_cli_ignores_ambient_trust_and_records_explicit_configuration(self):
        project_root = WEBSITE_DIR.parent
        if f'{sys.version_info.major}.{sys.version_info.minor}' != (project_root / '.python-version').read_text().strip():
            self.skipTest('Committed model integration requires its deployment Python version')
        raw = ('From: alice@gmail.com\nTo: bob@outlook.com\nSubject: Project update\n'
               'Authentication-Results: mx.example; dmarc=fail\n\n'
               'Our project meeting is tomorrow at noon in the library. Please bring your notes '
               'so we can review the assignment together. Thanks.')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'synthetic.jsonl'
            source.write_text(json.dumps({'provider': 'gmail', 'received_at': '2026-08-02',
                                          'label': 'legitimate', 'raw_email': raw}) + '\n')
            command = [sys.executable, str(WEBSITE_DIR / 'tools' / 'evaluate_serving_pipeline.py'),
                       '--input', str(source)]
            reports = []
            for ambient, extra in (('', []), ('mx.example', []),
                                   ('', ['--trusted-authserv-id', 'mx.example'])):
                completed = subprocess.run(command + extra, cwd=project_root,
                    env={**os.environ, 'TRUSTED_AUTHSERV_IDS': ambient}, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                reports.append(json.loads(completed.stdout))
            self.assertEqual(reports[0], reports[1])
            self.assertEqual(reports[0]['overall']['legitimate_false_alert_rate'], 0.0)
            self.assertEqual(reports[2]['overall']['legitimate_false_alert_rate'], 1.0)
            for report, trusted in ((reports[0], []), (reports[2], ['mx.example'])):
                metadata = report['reproducibility']
                self.assertEqual(metadata['configuration']['trusted_authserv_ids'], trusted)
                self.assertFalse(metadata['configuration']['observe_sender_history'])
                self.assertRegex(metadata['source_sha256'], r'^[0-9a-f]{64}$')
                self.assertRegex(metadata['git_commit'], r'^[0-9a-f]{40}$')
                self.assertIsInstance(metadata['git_dirty'], bool)
                self.assertIn('scikit-learn', metadata['package_versions'])
                self.assertIn('tldextract', metadata['package_versions'])
                self.assertNotIn('alice@gmail.com', json.dumps(report))

    def test_cli_evaluates_original_eml_bytes(self):
        project_root = WEBSITE_DIR.parent
        deployment_python = (project_root / '.python-version').read_text().strip()
        if f'{sys.version_info.major}.{sys.version_info.minor}' != deployment_python:
            self.skipTest(f'Committed artifact targets Python {deployment_python}')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'consented-fixture.jsonl'
            email_file = Path(directory) / 'private-message.eml'
            email_file.write_bytes(
                b'Subject: Project update\nContent-Type: text/plain; charset=utf-8\n'
                b'Content-Transfer-Encoding: 8bit\n\n'
                b'Our project meeting is tomorrow at noon in the library. '
                b'Please bring your notes so we can review the assignment together. Thanks. \xff'
            )
            source.write_text(json.dumps({
                'provider': 'gmail', 'received_at': '2026-08-02',
                'label': 'legitimate', 'eml_path': str(email_file),
            }) + '\n')
            source.write_text(source.read_text() * 2)
            completed = subprocess.run(
                [sys.executable, str(WEBSITE_DIR / 'tools' / 'evaluate_serving_pipeline.py'),
                 '--input', str(source)], cwd=project_root, capture_output=True, text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            command = [sys.executable, str(WEBSITE_DIR / 'tools' / 'evaluate_serving_pipeline.py'),
                       '--input', str(source)]
            strict = subprocess.run(command + ['--duplicate-policy', 'error'],
                                    cwd=project_root, capture_output=True, text=True)
            self.assertNotEqual(strict.returncode, 0)
            self.assertIn('Row 2: duplicate', strict.stderr)
            self.assertEqual(strict.stdout, '')
            self.assertNotIn(str(email_file), strict.stderr)
            email_file.write_bytes(email_file.read_bytes().replace(b'\xff', b'\xfe'))
            changed = subprocess.run(command, cwd=project_root, capture_output=True, text=True)
            self.assertEqual(changed.returncode, 0, changed.stderr)
            changed_report = json.loads(changed.stdout)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report['overall'], changed_report['overall'])
        self.assertNotEqual(report['input_integrity']['dataset_sha256'],
                            changed_report['input_integrity']['dataset_sha256'])
        self.assertEqual(report['input_integrity']['duplicate_rows'], 1)
        self.assertEqual(report['overall']['n'], 1)
        self.assertEqual(report['overall']['legitimate']['undetermined'], 1)
        self.assertEqual(report['overall']['complete_rate'], 0.0)
        self.assertNotIn('private-message.eml', completed.stdout)

    def test_eml_path_cannot_be_mixed_with_text_input(self):
        row = {
            'provider': 'gmail', 'received_at': '2026-08-02',
            'label': 'legitimate', 'eml_path': '/private/message.eml',
            'body': 'stale manual text',
        }
        with self.assertRaises(ValueError):
            evaluate_serving_pipeline._validated_record(row, 1)

    def test_provider_and_month_metrics_count_abstentions_explicitly(self):
        rows = [
            {'provider': 'gmail', 'received_at': '2026-08-02', 'label': 'phishing',
             'subject': 'secret one', 'body': 'private body'},
            {'provider': 'gmail', 'received_at': '2026-08-03', 'label': 'legitimate',
             'subject': 'secret two', 'body': 'private body'},
            {'provider': 'outlook', 'received_at': '2026-09-01', 'label': 'phishing',
             'subject': 'secret three', 'body': 'private body'},
            {'provider': 'outlook', 'received_at': '2026-09-02', 'label': 'legitimate',
             'subject': 'secret four', 'body': 'private body'},
        ]
        outcomes = {
            'secret one': {'risk_level': 'high', 'analysis_complete': True,
                           'ml_status': 'available'},
            'secret two': {'risk_level': 'safe', 'analysis_complete': True,
                           'ml_status': 'available'},
            'secret three': {'risk_level': 'unknown', 'analysis_complete': False,
                             'ml_status': 'unverified_rendering'},
            'secret four': {'risk_level': 'medium', 'analysis_complete': False,
                            'ml_status': 'insufficient_context'},
        }
        report = evaluate_serving_pipeline.evaluate_records(
            rows, lambda row: outcomes[row['subject']], model_sha256='a' * 64,
        )
        self.assertEqual(report['overall']['phishing']['alerted'], 1)
        self.assertEqual(report['overall']['phishing']['undetermined'], 1)
        self.assertEqual(report['overall']['legitimate']['alerted'], 1)
        self.assertEqual(report['overall']['phishing_alert_recall'], 0.5)
        self.assertEqual(report['overall']['legitimate_false_alert_rate'], 0.5)
        self.assertEqual(report['overall']['phishing_count'], 2)
        self.assertEqual(report['overall']['legitimate_count'], 2)
        self.assertEqual(report['overall']['phishing_alert_recall_95_ci'], [0.0945, 0.9055])
        self.assertEqual(report['overall']['legitimate_false_alert_rate_95_ci'], [0.0945, 0.9055])
        self.assertEqual(report['overall']['complete_rate'], 0.5)
        self.assertEqual(report['overall']['ml_available_rate'], 0.5)
        self.assertEqual(report['by_provider']['gmail']['phishing_alert_recall'], 1.0)
        self.assertEqual(report['by_provider']['gmail']['phishing_alert_recall_95_ci'], [0.2065, 1.0])
        self.assertEqual(report['by_month']['2026-09']['phishing']['undetermined'], 1)
        self.assertEqual(report['by_provider_month']['gmail']['2026-08']['n'], 2)
        self.assertEqual(report['by_provider_month']['outlook']['2026-09']['unknown_rate'], 0.5)
        self.assertEqual(report['temporal_isolation'], 'not_verified')
        serialized = json.dumps(report)
        self.assertNotIn('secret', serialized)
        self.assertNotIn('private body', serialized)

    def test_invalid_labels_dates_and_providers_are_rejected_without_echoing_content(self):
        valid = {'provider': 'gmail', 'received_at': '2026-08-02',
                 'label': 'phishing', 'subject': 'private subject', 'body': 'private body'}
        for altered in (
            {'provider': 'unknown'}, {'received_at': '2026-02-30'},
            {'label': 'safe'}, {'body': None},
        ):
            with self.subTest(altered=altered):
                row = {**valid, **altered}
                with self.assertRaises(ValueError) as caught:
                    evaluate_serving_pipeline.evaluate_records(
                        [row], lambda _row: {}, model_sha256='a' * 64,
                    )
                self.assertNotIn('private', str(caught.exception))

    def evaluation_row(self, **changes):
        return {'provider': 'gmail', 'received_at': '2026-08-02',
                'label': 'phishing', 'subject': 'private subject', 'body': 'private body', **changes}

    def evaluate(self, rows, **options):
        return evaluate_serving_pipeline.evaluate_records(
            rows, lambda _: {'risk_level': 'high', 'analysis_complete': True},
            model_sha256='a' * 64, **options)

    def test_duplicate_samples_do_not_inflate_denominators_or_confidence(self):
        calls = []
        row = self.evaluation_row()
        report = evaluate_serving_pipeline.evaluate_records(
            [row.copy() for _ in range(100)],
            lambda r: calls.append(r) or {'risk_level': 'high', 'analysis_complete': True},
            model_sha256='a' * 64)
        self.assertEqual(report['overall']['n'], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['overall']['phishing_alert_recall_95_ci'], [0.2065, 1.0])
        self.assertEqual(report['input_integrity']['duplicate_rows'], 99)
        self.assertEqual(report['input_integrity']['input_rows'], 100)
        self.assertEqual(report['input_integrity']['evaluated_rows'], 1)
        self.assertTrue(report['input_integrity']['warnings'])
        self.assertNotIn('private', json.dumps(report))

    def test_conflicting_labels_and_group_metadata_are_rejected_privately(self):
        row = self.evaluation_row()
        for changes in ({'label': 'legitimate'}, {'provider': 'outlook'},
                        {'language': 'en'}, {'received_at': '2026-08-03'}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, 'Row 2:') as caught:
                    self.evaluate([row, {**row, **changes}])
                self.assertNotIn('private', str(caught.exception))

    def test_unreadable_or_invalid_eml_is_rejected_without_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-message.eml'
            for data in (None, b'', b'x' * 60001):
                if data is not None:
                    path.write_bytes(data)
                with self.assertRaisesRegex(RuntimeError, 'Row 1:') as caught:
                    self.evaluate([self.evaluation_row(subject='', body='', eml_path=str(path))])
                self.assertNotIn(directory, str(caught.exception))
                self.assertNotIn('private-message', str(caught.exception))

    def test_strict_duplicate_policy_rejects_repeated_rows(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.evaluate([self.evaluation_row()] * 2, duplicate_policy='error')

    def test_fingerprint_tracks_content_labels_metadata_and_multiplicity(self):
        row = self.evaluation_row()
        digest = lambda rows: self.evaluate(rows)['input_integrity']['dataset_sha256']
        original = digest([row])
        self.assertRegex(original, r'^[0-9a-f]{64}$')
        for changes in ({'body': 'changed private body'}, {'label': 'legitimate'},
                        {'provider': 'outlook'}, {'language': 'en'}, {'received_at': '2026-08-03'}):
            self.assertNotEqual(original, digest([{**row, **changes}]))
        self.assertNotEqual(original, digest([row, row]))
        other = {**row, 'subject': 'another message'}
        self.assertEqual(digest([row, other]), digest([other, row]))
        self.assertEqual(original, digest([{**row, 'unused': 'ignored annotation'}]))

    def test_eml_fingerprint_uses_bytes_not_path_and_analyzes_same_snapshot(self):
        import app
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / 'private-a.eml', Path(directory) / 'private-b.eml'
            raw = b'Subject: Notes\n\nOriginal private bytes \xff'
            first.write_bytes(raw)
            second.write_bytes(raw)
            row = self.evaluation_row(subject='', body='', eml_path=str(first), _eml_bytes=b'forged')
            digest = self.evaluate([row])['input_integrity']['dataset_sha256']
            moved = self.evaluate([{**row, 'eml_path': str(second)}])
            self.assertEqual(digest, moved['input_integrity']['dataset_sha256'])
            self.assertEqual(self.evaluate([row, {**row, 'eml_path': str(second)}])['overall']['n'], 1)
            first.write_bytes(raw + b'changed')
            self.assertNotEqual(digest, self.evaluate([row])['input_integrity']['dataset_sha256'])
            first.write_bytes(raw)
            def analyze(prepared):
                first.write_bytes(b'Subject: Changed\n\nFile changed after preparation')
                return evaluate_serving_pipeline.analyze_record(prepared)
            with patch.object(app, '_content_pipeline', None), \
                    patch.object(app, 'analyze_raw_email', wraps=app.analyze_raw_email) as parse:
                report = evaluate_serving_pipeline.evaluate_records([row], analyze, model_sha256='a' * 64)
            self.assertEqual(parse.call_args.args[0], raw)
            self.assertEqual(digest, report['input_integrity']['dataset_sha256'])
            self.assertNotIn(directory, json.dumps(report))

    def test_empty_cohort_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_serving_pipeline.evaluate_records(
                [], lambda _row: {}, model_sha256='a' * 64,
            )

    def test_explicit_language_labels_have_separate_aggregate_metrics(self):
        rows = [
            {'provider': 'gmail', 'received_at': '2026-08-02', 'label': 'phishing',
             'language': 'zh', 'body': 'private Chinese sample'},
            {'provider': 'outlook', 'received_at': '2026-08-03', 'label': 'legitimate',
             'language': 'zh', 'body': 'private legitimate sample'},
            {'provider': 'gmail', 'received_at': '2026-08-04', 'label': 'phishing',
             'language': 'en', 'body': 'private English sample'},
            {'provider': 'gmail', 'received_at': '2026-08-05', 'label': 'legitimate',
             'body': 'private unlabeled sample'},
        ]
        risks = iter(('high', 'medium', 'unknown', 'safe'))
        report = evaluate_serving_pipeline.evaluate_records(
            rows, lambda _row: {'risk_level': next(risks), 'analysis_complete': True},
            model_sha256='a' * 64,
        )
        self.assertEqual(report['by_language']['zh']['phishing_alert_recall'], 1.0)
        self.assertEqual(report['by_language']['zh']['legitimate_false_alert_rate'], 1.0)
        self.assertEqual(report['by_language']['en']['phishing']['undetermined'], 1)
        self.assertEqual(report['by_language']['unlabeled']['n'], 1)
        self.assertEqual(report['by_provider_language']['gmail']['zh']['phishing']['alerted'], 1)
        self.assertEqual(report['by_provider_language']['outlook']['zh']['legitimate']['alerted'], 1)
        self.assertIsNone(report['by_language']['en']['legitimate_false_alert_rate_95_ci'])
        self.assertEqual(report['by_language']['unlabeled']['legitimate_count'], 1)
        self.assertNotIn('private', json.dumps(report))

    def test_language_tags_must_be_short_codes_not_message_content(self):
        row = {'provider': 'gmail', 'received_at': '2026-08-02',
               'label': 'phishing', 'body': 'private body', 'language': 'private body'}
        with self.assertRaises(ValueError) as caught:
            evaluate_serving_pipeline.evaluate_records(
                [row], lambda _row: {'risk_level': 'safe'}, model_sha256='a' * 64,
            )
        self.assertNotIn('private', str(caught.exception))

    def test_cli_uses_committed_artifact_and_only_prints_aggregate_output(self):
        project_root = WEBSITE_DIR.parent
        deployment_python = (project_root / '.python-version').read_text().strip()
        if f'{sys.version_info.major}.{sys.version_info.minor}' != deployment_python:
            self.skipTest(f'Committed artifact targets Python {deployment_python}')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'consented-fixture.jsonl'
            source.write_text(json.dumps({
                'provider': 'gmail', 'received_at': '2026-08-02',
                'label': 'phishing', 'subject': 'Private test subject',
                'body': 'Synthetic fixture with ordinary project meeting notes for tomorrow.',
            }) + '\n')
            completed = subprocess.run(
                [sys.executable, str(WEBSITE_DIR / 'tools' / 'evaluate_serving_pipeline.py'),
                 '--input', str(source)], cwd=project_root, capture_output=True, text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report['overall']['n'], 1)
        self.assertEqual(report['evaluation_scope'], 'local_serving_pipeline')
        self.assertEqual(report['overall']['phishing_count'], 1)
        self.assertIsNone(report['overall']['legitimate_false_alert_rate_95_ci'])
        self.assertNotIn('Private test subject', completed.stdout)
        self.assertNotIn('Synthetic fixture', completed.stdout)


if __name__ == '__main__':
    unittest.main()
