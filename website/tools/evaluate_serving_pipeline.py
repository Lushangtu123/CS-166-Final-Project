"""Evaluate the deployed analysis path on locally supplied, consented JSONL.

Only aggregate counts leave this process. This does not fetch inbox messages,
train a model, or establish that a cohort is independent of training data.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import re
import sys
from typing import Callable, Iterable
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROVIDERS = {'gmail', 'outlook'}
LABELS = {'phishing', 'legitimate'}
ALERT_LEVELS = {'medium', 'high', 'critical'}
RISK_LEVELS = ALERT_LEVELS | {'safe', 'low', 'unknown'}


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
    if not isinstance(received_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', received_at):
        raise ValueError(f'Row {index}: received_at must be YYYY-MM-DD')
    try:
        date.fromisoformat(received_at)
    except ValueError as exc:
        raise ValueError(f'Row {index}: received_at is not a calendar date') from exc
    for field in ('subject', 'body', 'raw_email'):
        if field in row and not isinstance(row[field], str):
            raise ValueError(f'Row {index}: {field} must be text')
    if not any(row.get(field) for field in ('subject', 'body', 'raw_email')):
        raise ValueError(f'Row {index}: message content is required')
    return row


def _summary(outcomes: list[dict]) -> dict:
    by_label = {label: Counter() for label in sorted(LABELS)}
    for item in outcomes:
        by_label[item['label']][item['decision']] += 1
    phishing = by_label['phishing']
    legitimate = by_label['legitimate']
    phishing_total = sum(phishing.values())
    legitimate_total = sum(legitimate.values())
    total = len(outcomes)
    return {
        'n': total,
        'phishing': {key: phishing[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        'legitimate': {key: legitimate[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        # Unknown cases remain in the denominator: they were not detected.
        'phishing_alert_recall': round(phishing['alerted'] / phishing_total, 4) if phishing_total else None,
        'legitimate_false_alert_rate': round(legitimate['alerted'] / legitimate_total, 4)
        if legitimate_total else None,
        'unknown_rate': round(sum(item['decision'] == 'undetermined' for item in outcomes) / total, 4),
        'complete_rate': round(sum(item['complete'] for item in outcomes) / total, 4),
        'ml_available_rate': round(sum(item['ml_available'] for item in outcomes) / total, 4),
    }


def evaluate_records(
    rows: Iterable[dict],
    analyze: Callable[[dict], dict],
    *,
    model_sha256: str,
) -> dict:
    """Run each row through the supplied serving analyzer and emit aggregates."""
    if not re.fullmatch(r'[0-9a-f]{64}', model_sha256):
        raise ValueError('A full lowercase model SHA-256 is required')
    outcomes = []
    dates = []
    for index, raw_row in enumerate(rows, 1):
        row = _validated_record(raw_row, index)
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
            'month': row['received_at'][:7],
            'label': row['label'],
            'decision': ('undetermined' if risk == 'unknown' else
                         'alerted' if risk in ALERT_LEVELS else 'not_alerted'),
            'complete': result.get('analysis_complete') is True,
            'ml_available': result.get('ml_status') == 'available',
        })
        dates.append(row['received_at'])
    if not outcomes:
        raise ValueError('No evaluation rows were supplied')

    by_provider = defaultdict(list)
    by_month = defaultdict(list)
    by_provider_month = defaultdict(lambda: defaultdict(list))
    for item in outcomes:
        by_provider[item['provider']].append(item)
        by_month[item['month']].append(item)
        by_provider_month[item['provider']][item['month']].append(item)
    return {
        'evaluation_scope': 'local_serving_pipeline',
        'alert_policy': 'medium/high/critical count as alerts; unknown is undetermined',
        'temporal_isolation': 'not_verified',
        'model_artifact_sha256': model_sha256,
        'first_received_at': min(dates),
        'last_received_at': max(dates),
        'overall': _summary(outcomes),
        'by_provider': {key: _summary(values) for key, values in sorted(by_provider.items())},
        'by_month': {key: _summary(values) for key, values in sorted(by_month.items())},
        'by_provider_month': {
            provider: {month: _summary(values) for month, values in sorted(months.items())}
            for provider, months in sorted(by_provider_month.items())
        },
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path,
                        help='Local JSONL file with consented, labeled messages')
    args = parser.parse_args()

    sys.path.insert(0, str(WEBSITE_DIR))
    from content_inference import load_content_pipeline_artifact
    import app

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    model_sha256 = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
    pipeline = load_content_pipeline_artifact(
        PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_sha256,
    )

    def analyze(row: dict) -> dict:
        request = app.ContentRequest(
            subject=row.get('subject', ''), body=row.get('body', ''),
            raw_email=row.get('raw_email', ''),
        )
        return json.loads(asyncio.run(app._analyze_content(
            request, observe_sender_history=False,
        )).body)

    with patch.object(app, '_content_pipeline', pipeline):
        report = evaluate_records(_jsonl_records(args.input), analyze,
                                  model_sha256=model_sha256)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
