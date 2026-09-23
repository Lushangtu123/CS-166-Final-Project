"""Evaluate the deployed analysis path on locally supplied, consented JSONL.

Reports contain aggregate results and execution metadata, never message content.
This does not fetch inbox messages, train a model, or establish that a cohort is
independent of training data.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from datetime import date
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Callable, Iterable
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROVIDERS = {'gmail', 'outlook'}
LABELS = {'phishing', 'legitimate'}
ALERT_LEVELS = {'medium', 'high', 'critical'}
RISK_LEVELS = ALERT_LEVELS | {'safe', 'low', 'unknown'}
WILSON_95_Z = 1.959963984540054
MAX_EML_BYTES = 60_000
ALERT_POLICY = 'medium/high/critical count as alerts; unknown is undetermined'
INCLUSION_POLICY = 'all valid unique inputs; analysis errors abort without a report; training overlap not verified'


def _validated_record(row: dict, index: int) -> dict:
    if not isinstance(row, dict):
        raise ValueError(f'Row {index}: expected a JSON object')
    provider = row.get('provider')
    label = row.get('label')
    received_at = row.get('received_at')
    if provider not in PROVIDERS:
        raise ValueError(f'Row {index}: provider must be gmail or outlook')
    if label not in LABELS:
        raise ValueError(f'Row {index}: label must be phishing or legitimate')
    if 'language' in row and (not isinstance(row['language'], str)
                              or not re.fullmatch(r'[a-z]{2,3}', row['language'])):
        raise ValueError(f'Row {index}: language must be a lowercase two- or three-letter code')
    if not isinstance(received_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', received_at):
        raise ValueError(f'Row {index}: received_at must be YYYY-MM-DD')
    try:
        date.fromisoformat(received_at)
    except ValueError as exc:
        raise ValueError(f'Row {index}: received_at is not a calendar date') from exc
    for field in ('subject', 'body', 'raw_email'):
        if field in row and not isinstance(row[field], str):
            raise ValueError(f'Row {index}: {field} must be text')
    if 'eml_path' in row:
        if not isinstance(row['eml_path'], str) or not Path(row['eml_path']).is_absolute():
            raise ValueError(f'Row {index}: eml_path must be an absolute path')
        if any(row.get(field) for field in ('subject', 'body', 'raw_email')):
            raise ValueError(f'Row {index}: eml_path cannot be mixed with text input')
    elif not any(row.get(field) for field in ('subject', 'body', 'raw_email')):
        raise ValueError(f'Row {index}: message content is required')
    return row


def _read_eml(path: str) -> bytes:
    with Path(path).open('rb') as source:
        raw = source.read(MAX_EML_BYTES + 1)
    if len(raw) > MAX_EML_BYTES or not raw.strip():
        raise ValueError('Email file must contain 1 to 60,000 bytes')
    return raw


def _json_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode('ascii')


def _prepare_record(row: dict) -> tuple[dict, str]:
    """Snapshot effective input once; paths and ignored annotations are not identity."""
    prepared = dict(row)
    # JSONL must not be able to supply the evaluator's internal byte snapshot.
    prepared.pop('_eml_bytes', None)
    if 'eml_path' in prepared:
        raw = _read_eml(prepared['eml_path'])
        prepared['_eml_bytes'] = raw
        payload = b'eml-bytes\0' + raw
    elif prepared.get('raw_email'):
        payload = b'raw-unicode\0' + _json_bytes(prepared['raw_email'])
    else:
        payload = b'subject-body\0' + _json_bytes([
            prepared.get('subject', ''), prepared.get('body', ''),
        ])
    return prepared, hashlib.sha256(payload).hexdigest()


def _rate_with_interval(successes: int, total: int) -> tuple[float | None, list[float] | None]:
    """Return a rate and two-sided 95% Wilson interval, or null for no data."""
    if total == 0:
        return None, None
    rate = successes / total
    z_squared = WILSON_95_Z ** 2
    denominator = 1 + z_squared / total
    center = (rate + z_squared / (2 * total)) / denominator
    margin = WILSON_95_Z * math.sqrt(
        rate * (1 - rate) / total + z_squared / (4 * total * total)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, center - margin)
    upper = 1.0 if successes == total else min(1.0, center + margin)
    return round(rate, 4), [round(lower, 4), round(upper, 4)]


def _summary(outcomes: list[dict]) -> dict:
    by_label = {label: Counter() for label in sorted(LABELS)}
    for item in outcomes:
        by_label[item['label']][item['decision']] += 1
    phishing = by_label['phishing']
    legitimate = by_label['legitimate']
    phishing_total = sum(phishing.values())
    legitimate_total = sum(legitimate.values())
    total = len(outcomes)
    phishing_recall, phishing_recall_ci = _rate_with_interval(
        phishing['alerted'], phishing_total,
    )
    legitimate_false_alert, legitimate_false_alert_ci = _rate_with_interval(
        legitimate['alerted'], legitimate_total,
    )
    unknown_rate, unknown_ci = _rate_with_interval(
        sum(item['decision'] == 'undetermined' for item in outcomes), total,
    )
    complete_rate, complete_ci = _rate_with_interval(
        sum(item['complete'] for item in outcomes), total,
    )
    ml_available_rate, ml_available_ci = _rate_with_interval(
        sum(item['ml_available'] for item in outcomes), total,
    )
    return {
        'n': total,
        'phishing_count': phishing_total,
        'legitimate_count': legitimate_total,
        'phishing': {key: phishing[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        'legitimate': {key: legitimate[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        # Unknown cases remain in the denominator: they were not detected.
        'phishing_alert_recall': phishing_recall,
        'phishing_alert_recall_95_ci': phishing_recall_ci,
        'legitimate_false_alert_rate': legitimate_false_alert,
        'legitimate_false_alert_rate_95_ci': legitimate_false_alert_ci,
        'unknown_rate': unknown_rate,
        'unknown_rate_95_ci': unknown_ci,
        'complete_rate': complete_rate,
        'complete_rate_95_ci': complete_ci,
        'ml_available_rate': ml_available_rate,
        'ml_available_rate_95_ci': ml_available_ci,
    }


def _private_summary(outcomes: list[dict]) -> dict:
    # Preserve the public evaluator's scoring implementation and baseline hash.
    return {**_summary(outcomes),
            'unknown_count': sum(item['decision'] == 'undetermined' for item in outcomes),
            'complete_count': sum(item['complete'] for item in outcomes),
            'ml_available_count': sum(item['ml_available'] for item in outcomes)}


def _decision(risk: str) -> str:
    return ('undetermined' if risk == 'unknown' else
            'alerted' if risk in ALERT_LEVELS else 'not_alerted')


def _scoring_sha256() -> str:
    payload = [inspect.getsource(function) for function in
               (_summary, _private_summary, _rate_with_interval, _decision)]
    payload.append({'labels': sorted(LABELS), 'alert_levels': sorted(ALERT_LEVELS),
                    'risk_levels': sorted(RISK_LEVELS), 'wilson_95_z': WILSON_95_Z})
    return hashlib.sha256(b'private-serving-scoring-v1\0' + _json_bytes(payload)).hexdigest()


def _validated_configuration(configuration: dict | None) -> dict | None:
    # A supplied analyzer must declare its configuration; do not guess it from
    # the current machine or accidentally serialize arbitrary environment data.
    if configuration is None:
        return None
    keys = {'trusted_authserv_ids', 'observe_sender_history', 'verification_mode',
            'content_model_enabled', 'auxiliary_enabled'}
    if not isinstance(configuration, dict) or set(configuration) != keys:
        raise ValueError('Evaluation configuration is incomplete or unsupported')
    ids = configuration['trusted_authserv_ids']
    if (not isinstance(ids, list) or any(not isinstance(value, str) or
            not re.fullmatch(r'[a-z0-9._-]{1,253}', value) for value in ids)
            or ids != sorted(set(ids))
            or configuration['observe_sender_history'] is not False
            or configuration['verification_mode'] != 'off'
            or type(configuration['content_model_enabled']) is not bool
            or configuration['auxiliary_enabled'] is not False):
        raise ValueError('Evaluation configuration is invalid or uses external state')
    return json.loads(_json_bytes(configuration))


def evaluate_records(
    rows: Iterable[dict],
    analyze: Callable[[dict], dict],
    *,
    model_sha256: str,
    duplicate_policy: str = 'drop',
    configuration: dict | None = None,
) -> dict:
    """Run each row through the supplied serving analyzer and emit aggregates."""
    if not re.fullmatch(r'[0-9a-f]{64}', model_sha256):
        raise ValueError('A full lowercase model SHA-256 is required')
    if duplicate_policy not in {'drop', 'error'}:
        raise ValueError('duplicate_policy must be drop or error')
    configuration = _validated_configuration(configuration)
    outcomes = []
    dates = []
    seen = {}
    input_digests = []
    included_digests = []
    duplicate_rows = 0
    for index, raw_row in enumerate(rows, 1):
        row = _validated_record(raw_row, index)
        try:
            row, content_digest = _prepare_record(row)
        except Exception:
            raise RuntimeError(f'Row {index}: message input could not be read') from None
        metadata = [row['label'], row['provider'], row['received_at'], row.get('language', 'unlabeled')]
        input_digests.append(hashlib.sha256(_json_bytes([content_digest, metadata])).digest())
        if content_digest in seen:
            previous_index, previous_metadata = seen[content_digest]
            if metadata != previous_metadata:
                raise ValueError(f'Row {index}: identical message content has conflicting labels or '
                                 f'group metadata with row {previous_index}')
            if duplicate_policy == 'error':
                raise ValueError(f'Row {index}: duplicate message of row {previous_index}')
            duplicate_rows += 1
            continue
        seen[content_digest] = (index, metadata)
        included_digests.append(input_digests[-1])
        try:
            result = analyze(row)
        except Exception:
            # Never echo a message, sender, URL, or library exception that may
            # contain one of those values.
            raise RuntimeError(f'Row {index}: analysis failed') from None
        risk = result.get('risk_level') if isinstance(result, dict) else None
        if risk not in RISK_LEVELS:
            raise ValueError(f'Row {index}: analyzer returned an invalid risk level')
        outcomes.append({
            'provider': row['provider'],
            'language': row.get('language', 'unlabeled'),
            'month': row['received_at'][:7],
            'label': row['label'],
            'decision': _decision(risk),
            'complete': result.get('analysis_complete') is True,
            'ml_available': result.get('ml_status') == 'available',
        })
        dates.append(row['received_at'])
    if not outcomes:
        raise ValueError('No evaluation rows were supplied')

    def grouped(items, dimensions):
        if not dimensions:
            return _private_summary(items)
        buckets = defaultdict(list)
        for item in items:
            buckets[item[dimensions[0]]].append(item)
        return {key: grouped(values, dimensions[1:]) for key, values in sorted(buckets.items())}

    return {
        'schema_version': 1,
        'evaluation_scope': 'local_serving_pipeline',
        'scoring_sha256': _scoring_sha256(),
        'inclusion_policy': INCLUSION_POLICY,
        'reproducibility': {'configuration': configuration},
        'input_integrity': {
            'input_rows': len(input_digests),
            'evaluated_rows': len(outcomes),
            'duplicate_rows': duplicate_rows,
            'duplicate_policy': duplicate_policy,
            'deduplication': 'exact effective message input; conflicting labels or group metadata rejected',
            'fingerprint_schema': 'phishguard-evaluation-input-v1',
            # Fixed-length record digests form an order-independent multiset.
            # Include omitted repeats so changes to the supplied cohort remain visible.
            'dataset_sha256': hashlib.sha256(
                b'phishguard-evaluation-input-v1\0' + b''.join(sorted(input_digests))
            ).hexdigest(),
            'evaluated_cohort_sha256': hashlib.sha256(
                b'phishguard-evaluation-cohort-v1\0' + b''.join(sorted(included_digests))
            ).hexdigest(),
            'warnings': ([f'{duplicate_rows} duplicate rows were excluded from all metrics.']
                         if duplicate_rows else []),
        },
        'alert_policy': ALERT_POLICY,
        'confidence_intervals': 'two-sided 95% Wilson score intervals',
        'temporal_isolation': 'not_verified',
        'model_artifact_sha256': model_sha256,
        'first_received_at': min(dates),
        'last_received_at': max(dates),
        'overall': _private_summary(outcomes),
        **{'by_' + '_'.join(dimensions): grouped(outcomes, dimensions) for dimensions in (
            ('provider',), ('language',), ('month',), ('provider', 'language'),
            ('provider', 'month'), ('language', 'month'), ('provider', 'language', 'month'))},
    }


def _jsonl_records(path: Path):
    with path.open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f'Line {line_number}: invalid JSON') from None


def analyze_record(row: dict) -> dict:
    """Analyze one validated row using the configured local app, without history writes."""
    import app

    structure = None
    if 'eml_path' in row:
        raw = row['_eml_bytes'] if '_eml_bytes' in row else _read_eml(row['eml_path'])
        structure = app.analyze_raw_email(
            raw, trusted_authserv_ids=app.SETTINGS.trusted_authserv_ids,
        )
        request = app.ContentRequest()
    else:
        request = app.ContentRequest(
            subject=row.get('subject', ''), body=row.get('body', ''),
            raw_email=row.get('raw_email', ''),
        )
    return json.loads(asyncio.run(app._analyze_content(
        request, structure, observe_sender_history=False,
    )).body)


def _evaluation_metadata(configuration: dict) -> dict:
    from model_environment import RUNTIME_PACKAGE_NAMES, package_versions

    # Include local edits and the registries, without publishing source or mail.
    sources = sorted(WEBSITE_DIR.glob('*.py')) + sorted((WEBSITE_DIR / 'data').glob('*.json'))
    sources += [Path(__file__).resolve(), PROJECT_ROOT / 'app.py']
    source_digest = hashlib.sha256()
    for path in sources:
        source_digest.update(path.relative_to(PROJECT_ROOT).as_posix().encode() + b'\0')
        source_digest.update(hashlib.sha256(path.read_bytes()).digest())
    commit = dirty = None
    try:
        commit = subprocess.run(
            ['git', 'rev-parse', 'HEAD'], cwd=PROJECT_ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ['git', 'status', '--porcelain'], cwd=PROJECT_ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        'git_commit': commit,
        'git_dirty': dirty,
        'source_sha256': source_digest.hexdigest(),
        'deployment_profile_sha256': hashlib.sha256((PROJECT_ROOT / 'vercel.json').read_bytes()).hexdigest(),
        'python_version': platform.python_version(),
        'platform': {'system': platform.system(), 'machine': platform.machine()},
        'package_versions': package_versions((*RUNTIME_PACKAGE_NAMES, 'fastapi', 'pydantic', 'tldextract')),
        'configuration': configuration,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path,
                        help='Local JSONL file with consented, labeled messages')
    parser.add_argument('--trusted-authserv-id', action='append', default=[],
                        help='Explicit trusted authentication service ID; repeat for multiple IDs (default: none)')
    parser.add_argument('--duplicate-policy', choices=('drop', 'error'), default='drop',
                        help='Drop exact duplicates (default), or reject them; metadata conflicts always fail')
    args = parser.parse_args()
    trusted_ids = sorted({value.strip().lower() for value in args.trusted_authserv_id})
    if any(not re.fullmatch(r'[a-z0-9._-]{1,253}', value) for value in trusted_ids):
        parser.error('Trusted authentication service IDs must contain only ASCII letters, digits, dots, underscores or hyphens')

    sys.path.insert(0, str(WEBSITE_DIR))
    from content_inference import load_content_pipeline_artifact
    from config import load_settings

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    evaluation_env = {**profile, 'TRUSTED_AUTHSERV_IDS': ','.join(trusted_ids),
                      'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
                      'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false'}
    # Import-time settings must not inherit the invoking shell's trust or services.
    with patch.dict(os.environ, evaluation_env, clear=True):
        import app
    settings = load_settings(evaluation_env)
    configuration = {'trusted_authserv_ids': sorted(settings.trusted_authserv_ids),
                     'observe_sender_history': False, 'verification_mode': settings.effective_verification_mode,
                     'content_model_enabled': settings.content_model_enabled, 'auxiliary_enabled': False}
    model_sha256 = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
    pipeline = load_content_pipeline_artifact(
        PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_sha256,
    )

    with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
        report = evaluate_records(_jsonl_records(args.input), analyze_record,
                                  model_sha256=model_sha256, duplicate_policy=args.duplicate_policy,
                                  configuration=configuration)
    report['reproducibility'] = _evaluation_metadata(configuration)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
