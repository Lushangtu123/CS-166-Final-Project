"""Exploratory Jev shadow evaluation. Default: local cohort preflight, zero API calls.

Live mode sends prepared email text to TypeSafe and may incur charges. It requires
explicit external-processing consent, a bounded call budget, and server credentials.
The hypothetical OR comparison is not a production policy or a release gate.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))
from tools.evaluation_data import Corpus, load_corpus
from tools.evaluate_serving_pipeline import ALERT_LEVELS, RISK_LEVELS, _json_bytes, _summary

PROBABILITIES = ('phishing_intent', 'credential_request', 'payment_redirection',
                 'authority_pressure', 'insufficient_evidence')


def validate_live_options(*, live, allow_external_processing, max_calls, env):
    if not live:
        return
    if not allow_external_processing:
        raise ValueError('Live evaluation requires --allow-external-processing')
    if type(max_calls) is not int or not 1 <= max_calls <= 1000:
        raise ValueError('Live evaluation requires explicit --max-calls between 1 and 1000')
    if env.get('PHISHGUARD_JEV_ENABLED', '').lower() != 'true' or not env.get('TYPESAFE_API_KEY', '').strip():
        raise ValueError('Live evaluation requires PHISHGUARD_JEV_ENABLED=true and TYPESAFE_API_KEY')


def _cohort(corpus, reference):
    labels = {}
    for row in corpus.records + (reference.records if reference else []):
        digest = row['_exact_sha256']
        if digest in labels and labels[digest] != row['label']:
            raise ValueError('Identical content has conflicting labels')
        labels[digest] = row['label']
    exact = {row['_exact_sha256'] for row in reference.records} if reference else set()
    templates = {row['_template_sha256'] for row in reference.records if row['_template_sha256']} if reference else set()
    seen, retained = set(), []
    counts = dict(input=len(corpus.records), duplicates=0, overlap_exact=0, overlap_template=0)
    for row in corpus.records:
        digest, template = row['_exact_sha256'], row['_template_sha256']
        if digest in seen:
            counts['duplicates'] += 1
            continue
        seen.add(digest)
        if digest in exact:
            counts['overlap_exact'] += 1
        elif template and template in templates:
            counts['overlap_template'] += 1
        else:
            retained.append(row)
    counts['eligible'] = len(retained)
    counts['excluded'] = counts['input'] - counts['eligible']
    return retained, counts


def _decision(risk):
    return 'undetermined' if risk == 'unknown' else 'alerted' if risk in ALERT_LEVELS else 'not_alerted'


def _probabilities(result):
    values = result.get('probabilities')
    if not isinstance(values, dict) or any(type(values.get(key)) not in (int, float)
            or not math.isfinite(values[key]) or not 0 <= values[key] <= 1 for key in PROBABILITIES):
        raise ValueError('Invalid auxiliary probabilities')
    return values


def _aggregate(outcomes):
    report = {'n': len(outcomes)}
    for field in ('baseline', 'jev', 'shadow'):
        report[field] = _summary([dict(label=row['label'], decision=row[field],
            complete=row['complete'] if field == 'baseline' else False,
            ml_available=row['ml_available'] if field == 'baseline' else False) for row in outcomes])
    report['recovered_phishing'] = sum(row['label'] == 'phishing' and row['baseline'] != 'alerted'
                                      and row['shadow'] == 'alerted' for row in outcomes)
    report['new_legitimate_alerts'] = sum(row['label'] == 'legitimate' and row['baseline'] != 'alerted'
                                         and row['shadow'] == 'alerted' for row in outcomes)
    errors = [(row['probability'] - (row['label'] == 'phishing'))**2
              for row in outcomes if row['probability'] is not None]
    report['brier_n'] = len(errors)
    report['brier_score'] = sum(errors) / len(errors) if errors else None
    report['auxiliary_statuses'] = dict(sorted(Counter(row['status'] for row in outcomes).items()))
    return report


def evaluate_shadow(corpus: Corpus, analyze=None, *, client=None, prepare_input=None,
                    live=False, max_calls=None, threshold=.8, reference=None):
    """Pure evaluation orchestration; caller supplies authorized client in live mode.

    Budget-exhausted, failed and skipped rows remain in every cohort denominator.
    Dry runs never invoke the supplied model, client or input preparation function.
    """
    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ValueError('Threshold must be finite and strictly between zero and one')
    rows, counts = _cohort(corpus, reference)
    if live and (type(max_calls) is not int or not 1 <= max_calls <= 1000 or client is None
                 or not client.enabled or analyze is None or prepare_input is None):
        raise ValueError('Live evaluation requires an enabled client, analyzers and bounded call budget')
    counts.update(attempted=0, available=0, auxiliary_failures=0, auxiliary_skipped=0, baseline_failures=0,
                  preparation_failures=0, budget_skipped=0)
    # Include ordering: call-budget allocation depends on record order.
    cohort_hash = hashlib.sha256(b'jev-ordered-cohort-v1\0' + _json_bytes([
        {key: row[key] for key in ('id', 'source_id', 'label', 'language', '_exact_sha256')}
        for row in rows])).hexdigest()
    report = dict(schema_version=1, evaluation_scope='jev_exploratory_shadow', exploratory_only=True,
        release_gate=False, mode='live' if live else 'dry_run', counts=counts,
        dataset_sha256=corpus.dataset_sha256, manifest_sha256=corpus.manifest_sha256,
        records_sha256=corpus.records_sha256, evaluated_cohort_sha256=cohort_hash,
        evaluator_sha256=hashlib.sha256(Path(__file__).read_bytes() +
            (WEBSITE_DIR / 'tools/evaluation_data.py').read_bytes() +
            (WEBSITE_DIR / 'tools/evaluate_serving_pipeline.py').read_bytes()).hexdigest(),
        adapter_sha256=hashlib.sha256((WEBSITE_DIR / 'jev.py').read_bytes()).hexdigest(),
        reference_dataset_sha256=reference.dataset_sha256 if reference else None,
        training_independence='not_verified', temporal_isolation='not_verified',
        max_calls=max_calls, threshold=threshold, insufficient_evidence_threshold=.5,
        overall=None, by_language={}, by_source={},
        policy='Experimental OR: keep baseline alerts; otherwise add Jev alerts only. Never clear a baseline alert.',
        limitations=[
            'Thresholds are exploratory and not validated for deployment.',
            'Typed probabilities do not establish correct decisions or domain calibration.',
            'Brier score covers available outputs only; all failures and skips stay in recall denominators.',
            'Labels and provenance are supplied declarations; independence from training data is unverified.',
            'Reference exclusion uses exact and heuristic template matches; other overlap may remain.',
            'Call budgets select the first eligible rows in corpus order and can bias results.',
            'Incomplete input produces an undetermined Jev decision even when a probability is available.',
            'Semantic analysis does not inspect inaccessible images or attached messages omitted from prepared text.',
        ])
    if not live:
        return report
    outcomes, latencies, models, question_hashes, request_hashes = [], [], set(), set(), []
    usage = {'input_tokens': 0, 'output_tokens': 0, 'reported_calls': 0}
    for row in rows:
        probability, status, jev_decision = None, 'unavailable', 'undetermined'
        try:
            base = analyze(row)
            if not isinstance(base, dict) or base.get('risk_level') not in RISK_LEVELS:
                raise ValueError()
        except Exception:
            counts['baseline_failures'] += 1
            base = {'risk_level': 'unknown'}
            status = 'baseline_failure'
        else:
            if counts['attempted'] >= max_calls:
                status = 'budget_skipped'
                counts['budget_skipped'] += 1
            else:
                try:
                    prepared = prepare_input(row, base)
                    if not isinstance(prepared, dict) or any(not isinstance(prepared.get(key), str)
                                                            for key in ('subject', 'body')):
                        raise ValueError()
                except Exception:
                    counts['preparation_failures'] += 1
                    status = 'preparation_failure'
                else:
                    counts['attempted'] += 1
                    try:
                        result = client.evaluate(**prepared)
                        if not isinstance(result, dict) or result.get('status') not in ('available', 'disabled', 'unavailable', 'skipped'):
                            raise ValueError()
                        status = result['status']
                        if status == 'available':
                            values = _probabilities(result)
                            probability = values['phishing_intent']
                            jev_decision = ('undetermined' if values['insufficient_evidence'] >= .5 or result.get('evidence_incomplete') is True else
                                            'alerted' if probability >= threshold else 'not_alerted')
                            counts['available'] += 1
                        elif status in ('unavailable', 'disabled'):
                            counts['auxiliary_failures'] += 1
                        elif status == 'skipped':
                            counts['auxiliary_skipped'] += 1
                        # Copy only bounded typed metrics. Never copy provider errors, text or paths.
                        timing = result.get('latency_ms')
                        if type(timing) in (int, float) and math.isfinite(timing) and timing >= 0:
                            latencies.append(timing)
                        consumed = result.get('usage')
                        if isinstance(consumed, dict) and all(type(consumed.get(k)) is int and consumed[k] >= 0
                                                             for k in ('input_tokens', 'output_tokens')):
                            usage['reported_calls'] += 1
                            for key in ('input_tokens', 'output_tokens'):
                                usage[key] += consumed[key]
                        for key, bucket in (('questions_sha256', question_hashes), ('input_sha256', request_hashes)):
                            value = result.get(key)
                            if isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value):
                                bucket.add(value) if isinstance(bucket, set) else bucket.append(value)
                        model = result.get('model')
                        if isinstance(model, str) and re.fullmatch(r'jev[-.a-z0-9]{1,40}', model):
                            models.add(model)
                    except Exception:
                        status, probability, jev_decision = 'unavailable', None, 'undetermined'
                        counts['auxiliary_failures'] += 1
        baseline = _decision(base['risk_level'])
        shadow = 'alerted' if 'alerted' in (baseline, jev_decision) else baseline
        outcomes.append(dict(label=row['label'], source=row['source_id'], language=row['language'],
                             baseline=baseline, jev=jev_decision, shadow=shadow, probability=probability,
                             status=status, complete=base.get('analysis_complete') is True,
                             ml_available=base.get('ml_status') == 'available'))
    report['overall'] = _aggregate(outcomes)
    for field in ('language', 'source'):
        groups = defaultdict(list)
        for outcome in outcomes:
            groups[outcome[field]].append(outcome)
        report['by_' + field] = {key: _aggregate(value) for key, value in sorted(groups.items())}
    report.update(usage=usage, models=sorted(models), questions_sha256=sorted(question_hashes),
        request_inputs_sha256=hashlib.sha256(_json_bytes(request_hashes)).hexdigest(),
        latency_ms={'n': len(latencies), 'mean': sum(latencies)/len(latencies) if latencies else None,
                    'max': max(latencies) if latencies else None,
                    'p95': sorted(latencies)[math.ceil(.95 * len(latencies)) - 1] if latencies else None},
        external_processing=True)
    return report


def _prepare_input(row, analysis):
    import app
    from jev import prepare_case_input
    if '_eml_bytes' not in row:
        return prepare_case_input({'subject': row.get('subject', ''), 'body': row.get('body', '')}, analysis)
    structure = app.analyze_raw_email(row['_eml_bytes'], trusted_authserv_ids=())
    parts = structure.get('content_parts', [])
    body = '\n'.join(app._visible_content_text(part['content']) if part.get('content_type') == 'text/html'
                     else part['content'] for part in parts)
    return prepare_case_input({'subject': structure.get('subject', ''), 'body': body,
                               'input_mode': 'prepared_text',
                               'text_truncated': bool(structure.get('nested_messages'))}, analysis)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--reference-manifest', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--allow-external-processing', action='store_true')
    parser.add_argument('--max-calls', type=int)
    parser.add_argument('--threshold', type=float, default=.8)
    args = parser.parse_args(argv)
    try:
        validate_live_options(live=args.live, allow_external_processing=args.allow_external_processing,
                              max_calls=args.max_calls, env=os.environ)
        corpus = load_corpus(args.manifest)
        reference = load_corpus(args.reference_manifest) if args.reference_manifest else None
        # Complete preflight before loading or calling any model.
        report = evaluate_shadow(corpus, reference=reference, threshold=args.threshold, max_calls=args.max_calls)
    except (ValueError, OSError):
        parser.error('Invalid corpus, threshold or live options. Live mode requires explicit processing consent, enabled key and --max-calls 1..1000.')
    if args.live:
        from jev import JevClient
        client = JevClient.from_env(dict(os.environ))
        if not client.enabled:
            parser.error('Jev client is disabled or its credentials are invalid')
        client.max_calls = args.max_calls
        from content_inference import load_content_pipeline_artifact
        from config import load_settings
        from tools.evaluate_serving_pipeline import analyze_record, _evaluation_metadata
        profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text())['env']
        evaluation_env = {**profile, 'TRUSTED_AUTHSERV_IDS': '', 'SENDER_HISTORY_ENABLED': 'false',
                          'EMAIL_VERIFICATION_ENABLED': 'false', 'CASE_MANAGEMENT_ENABLED': 'false',
                          'PHISHGUARD_JEV_ENABLED': 'false'}
        # Retain the explicit client separately; no credentials reach the baseline app.
        with patch.dict(os.environ, evaluation_env, clear=True):
            import app
            settings = load_settings(evaluation_env)
            model_hash = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
            pipeline = load_content_pipeline_artifact(PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_hash)
            with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
                report = evaluate_shadow(corpus, analyze_record, client=client, prepare_input=_prepare_input,
                    live=True, max_calls=args.max_calls, threshold=args.threshold, reference=reference)
        report['model_artifact_sha256'] = model_hash
        report['reproducibility'] = _evaluation_metadata({'trusted_authserv_ids': [],
            'observe_sender_history': False, 'network_services_enabled': False,
            'external_jev_processing': True})
    serialized = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
    if args.output:
        args.output.write_text(serialized, encoding='utf-8')
    else:
        print(serialized, end='')
    if not report['counts']['eligible'] or (args.live and (not report['counts']['available'] or
            any(report['counts'][key] for key in
                ('baseline_failures', 'preparation_failures', 'auxiliary_failures', 'auxiliary_skipped', 'budget_skipped')))):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
