"""No-network checks for exploratory Jev evaluation and cohort integrity."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.evaluation_data import Corpus
from tools.evaluate_jev import evaluate_shadow, validate_live_options, _prepare_input


def row(index, label='phishing', **extra):
    return dict(id=str(index), source_id='fixture', label=label, provider='unknown',
                language='en', received_at=None, subject='PRIVATE SUBJECT',
                body='PRIVATE BODY', _exact_sha256=hashlib.sha256(str(index).encode()).hexdigest(),
                _template_sha256=None, **extra)


def corpus(rows):
    return Corpus(rows, [], 'a'*64, 'b'*64, 'c'*64, True)


def answer(probability=.9, insufficient=.1, **extra):
    return dict(status='available', probabilities=dict(phishing_intent=probability,
        credential_request=.2, payment_redirection=.1, authority_pressure=.3,
        insufficient_evidence=insufficient), model='jev-test', latency_ms=10,
        usage={'input_tokens': 100, 'output_tokens': 0}, input_sha256='d'*64,
        questions_sha256='e'*64, **extra)


class JevEvaluationTests(unittest.TestCase):
    def test_dry_run_never_calls_baseline_preparation_or_client(self):
        calls = Mock(side_effect=AssertionError('must not run'))
        client = Mock(evaluate=calls)
        report = evaluate_shadow(corpus([row(1)]), calls, client=client, prepare_input=calls)
        self.assertEqual(report['mode'], 'dry_run')
        self.assertEqual(report['counts']['eligible'], 1)
        self.assertEqual(report['counts']['attempted'], 0)
        self.assertIsNone(report['overall'])
        calls.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_live_requires_explicit_processing_permission_limit_and_enabled_key(self):
        env = {'PHISHGUARD_JEV_ENABLED': 'true', 'TYPESAFE_API_KEY': 'secret'}
        validate_live_options(live=True, allow_external_processing=True, max_calls=1, env=env)
        for changes in ({'allow_external_processing': False}, {'max_calls': None},
                        {'max_calls': 0}, {'max_calls': 1001}, {'max_calls': True},
                        {'env': {}}, {'env': {**env, 'PHISHGUARD_JEV_ENABLED': 'false'}}):
            args = dict(live=True, allow_external_processing=True, max_calls=1, env=env)
            args.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_live_options(**args)

    def test_conflicting_duplicates_abort_before_any_calls(self):
        rows = [row(1), row(1, 'legitimate')]
        analyze = Mock()
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            evaluate_shadow(corpus(rows), analyze)
        analyze.assert_not_called()

    def test_reference_exclusion_and_duplicate_counts(self):
        rows = [row(1), row(1), row(2), row(3)]
        rows[2]['_template_sha256'] = 'f'*64
        ref = [row(1), row(4)]
        ref[1]['_template_sha256'] = 'f'*64
        report = evaluate_shadow(corpus(rows), Mock(), reference=corpus(ref))
        self.assertEqual(report['counts']['eligible'], 1)
        self.assertEqual(report['counts']['duplicates'], 1)
        self.assertEqual(report['counts']['overlap_exact'], 1)
        self.assertEqual(report['counts']['overlap_template'], 1)

    def run_live(self, rows, answers, risks=None, max_calls=100, prepare_input=None):
        client = Mock(enabled=True)
        client.evaluate.side_effect = answers
        analyze = Mock(side_effect=[{'risk_level': risk, 'analysis_complete': True}
                                    for risk in (risks or ['low']*len(rows))])
        report = evaluate_shadow(corpus(rows), analyze, live=True, max_calls=max_calls,
                                 client=client, prepare_input=prepare_input or
                                 (lambda row, result: {'subject': '', 'body': 'safe fixture'}))
        return report, client

    def test_shadow_never_clears_baseline_alert_and_measures_brier_and_new_alerts(self):
        report, _ = self.run_live([row(1), row(2, 'legitimate'), row(3)],
                                 [answer(.9), answer(.8), answer(.01)], ['low', 'low', 'high'])
        summary = report['overall']
        self.assertEqual(summary['recovered_phishing'], 1)
        self.assertEqual(summary['new_legitimate_alerts'], 1)
        self.assertEqual(summary['shadow']['phishing']['alerted'], 2)
        self.assertAlmostEqual(summary['brier_score'], (.01+.64+.9801)/3)
        self.assertEqual(summary['brier_n'], 3)
        self.assertEqual(report['usage']['input_tokens'], 300)
        self.assertEqual(report['by_language']['en']['n'], 3)
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_failures_skips_budget_and_insufficient_evidence_stay_in_denominators(self):
        report, client = self.run_live([row(i) for i in range(5)],
            [RuntimeError('PRIVATE BODY'), {'status': 'skipped'}, answer(.99, .9), answer(.5)],
            max_calls=4)
        self.assertEqual(client.evaluate.call_count, 4)
        self.assertEqual(report['counts']['attempted'], 4)
        self.assertEqual(report['counts']['budget_skipped'], 1)
        self.assertEqual(report['counts']['auxiliary_failures'], 1)
        self.assertEqual(report['overall']['jev']['n'], 5)
        self.assertEqual(report['overall']['jev']['phishing']['undetermined'], 4)
        self.assertEqual(report['overall']['brier_n'], 2)
        self.assertNotIn('PRIVATE BODY', json.dumps(report))

    def test_malformed_probabilities_fail_closed(self):
        for value in (True, float('nan'), -1, 2, '0.9'):
            with self.subTest(value=value):
                report, _ = self.run_live([row(1)], [answer(value)])
                self.assertEqual(report['counts']['auxiliary_failures'], 1)
                self.assertEqual(report['overall']['brier_n'], 0)

    def test_baseline_and_input_preparation_failure_cannot_send_mail(self):
        client = Mock(enabled=True)
        report = evaluate_shadow(corpus([row(1)]), Mock(side_effect=RuntimeError('secret')),
                                 live=True, max_calls=1, client=client, prepare_input=Mock())
        client.evaluate.assert_not_called()
        self.assertEqual(report['counts']['baseline_failures'], 1)
        report, client = self.run_live([row(1)], [], prepare_input=Mock(side_effect=ValueError('secret')))
        client.evaluate.assert_not_called()
        self.assertEqual(report['counts']['preparation_failures'], 1)

    def test_incomplete_evidence_cannot_become_new_alert(self):
        report, _ = self.run_live([row(1)], [answer(.99, evidence_incomplete=True)])
        self.assertEqual(report['overall']['jev']['phishing']['undetermined'], 1)
        self.assertEqual(report['overall']['recovered_phishing'], 0)
        self.assertEqual(report['overall']['brier_n'], 1)

    def test_eml_preparation_preserves_plain_text_and_only_extracts_html(self):
        app = Mock()
        app.analyze_raw_email.return_value = {'subject': 'fixture', 'content_parts': [
            {'content_type': 'text/plain', 'content': 'plain <literal>'},
            {'content_type': 'text/html', 'content': '<p>visible</p>'}], 'nested_messages': [{}]}
        app._visible_content_text.return_value = 'visible'
        helper = Mock(side_effect=lambda source, analysis: source)
        with patch.dict(sys.modules, {'app': app, 'jev': Mock(prepare_case_input=helper)}):
            prepared = _prepare_input({'_eml_bytes': b'MIME BYTES'}, {'analysis_complete': True})
        self.assertEqual(prepared['body'], 'plain <literal>\nvisible')
        self.assertTrue(prepared['text_truncated'])
        self.assertEqual(prepared['input_mode'], 'prepared_text')
        self.assertNotIn('MIME BYTES', json.dumps(prepared))
        app._visible_content_text.assert_called_once_with('<p>visible</p>')

    def test_cli_default_is_dry_run_even_with_enabled_environment(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run([sys.executable, str(root / 'website/tools/evaluate_jev.py'),
            '--manifest', str(root / 'website/tests/fixtures/evaluation/manifest.json')],
            env={**os.environ, 'TYPESAFE_API_KEY': 'not-a-real-key', 'PHISHGUARD_JEV_ENABLED': 'true'},
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['mode'], 'dry_run')
        self.assertEqual(report['counts']['attempted'], 0)


if __name__ == '__main__':
    unittest.main()
