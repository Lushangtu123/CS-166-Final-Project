import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline


class ServingEvaluationTests(unittest.TestCase):
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
