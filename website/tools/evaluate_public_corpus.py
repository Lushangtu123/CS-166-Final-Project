"""Evaluate a versioned public email corpus locally; emit no message bodies or paths.

Reference matches are conservatively excluded. Absence of a reference match does
not establish training independence. No network or inbox access is needed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import inspect
import json
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
from tools import evaluate_serving_pipeline as serving
from tools.evaluate_serving_pipeline import (
    ALERT_LEVELS, RISK_LEVELS, _summary, _json_bytes, analyze_record, _evaluation_metadata,
)


def _scoring_sha256() -> str:
    # Include the summary implementation, its interval calculation, and their
    # constants. Serving rules/model hashes can change independently of scoring.
    payload = [inspect.getsource(_summary), inspect.getsource(serving._rate_with_interval),
               {'labels': sorted(serving.LABELS), 'wilson_95_z': serving.WILSON_95_Z,
                'alert_levels': sorted(ALERT_LEVELS), 'risk_levels': sorted(RISK_LEVELS)}]
    return hashlib.sha256(b'public-scoring-v1\0' + _json_bytes(payload)).hexdigest()


def evaluate_corpus(corpus: Corpus, analyze, *, model_sha256: str, reference: Corpus | None = None) -> dict:
    if not isinstance(model_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', model_sha256):
        raise ValueError('A full model SHA-256 is required')
    # Preflight all duplicate labels before any analysis; no partial reports on invalid cohorts.
    labels = {}
    for row in corpus.records + (reference.records if reference else []):
        digest = row['_exact_sha256']
        if digest in labels and labels[digest] != row['label']:
            raise ValueError('Identical content has conflicting labels')
        labels[digest] = row['label']
    ref_exact = {row['_exact_sha256'] for row in reference.records} if reference else set()
    ref_template = {row['_template_sha256'] for row in reference.records if row['_template_sha256']} if reference else set()
    counts = dict(input=len(corpus.records), evaluated=0, duplicates=0, overlap_exact=0,
                  overlap_template=0, excluded=0, failures=0)
    seen, seen_template, outcomes = set(), set(), []
    template_repeats = 0
    attempted_fingerprints = []
    for row in corpus.records:
        digest, template = row['_exact_sha256'], row['_template_sha256']
        if digest in seen:
            counts['duplicates'] += 1
            continue
        seen.add(digest)
        if digest in ref_exact:
            counts['overlap_exact'] += 1
            continue
        if template and template in ref_template:
            counts['overlap_template'] += 1
            continue
        if template and template in seen_template:
            template_repeats += 1
        if template:
            seen_template.add(template)
        # Attempted rows remain part of cohort identity even if inference fails.
        attempted_fingerprints.append(hashlib.sha256(_json_bytes({key: row[key] for key in (
            'id', 'source_id', 'label', 'provider', 'language', 'received_at', '_exact_sha256')})).digest())
        try:
            result = analyze(row)
            if not isinstance(result, dict) or result.get('risk_level') not in RISK_LEVELS:
                raise ValueError('Invalid analyzer result')
        except Exception:
            counts['failures'] += 1
            result = {'risk_level': 'unknown'}
        risk = result['risk_level']
        outcomes.append({
            'label': row['label'], 'source': row['source_id'], 'provider': row['provider'],
            'language': row['language'], 'month': row['received_at'][:7] if row['received_at'] else 'unknown',
            'decision': 'undetermined' if risk == 'unknown' else 'alerted' if risk in ALERT_LEVELS else 'not_alerted',
            'complete': result.get('analysis_complete') is True,
            'ml_available': result.get('ml_status') == 'available',
        })
    counts['evaluated'] = len(outcomes)
    counts['excluded'] = counts['duplicates'] + counts['overlap_exact'] + counts['overlap_template']
    grouped = {}
    for field in ('source', 'provider', 'language', 'month'):
        buckets = defaultdict(list)
        for outcome in outcomes:
            buckets[outcome[field]].append(outcome)
        grouped['by_' + field] = {key: _summary(rows) for key, rows in sorted(buckets.items())}
    return {
        'schema_version': 1, 'evaluation_scope': 'public_corpus_local_serving_pipeline',
        'exploratory_only': corpus.exploratory_only,
        'dataset_sha256': corpus.dataset_sha256,
        'evaluated_cohort_sha256': hashlib.sha256(
            b'public-evaluated-cohort-v1\0' + b''.join(sorted(attempted_fingerprints))).hexdigest(),
        'scoring_sha256': _scoring_sha256(),
        'manifest_sha256': corpus.manifest_sha256, 'records_sha256': corpus.records_sha256,
        'sources': corpus.sources, 'model_artifact_sha256': model_sha256,
        'counts': counts, 'overall': _summary(outcomes), **grouped,
        'training_independence': 'not_verified', 'temporal_isolation': 'not_verified',
        'overlap_check': {
            'status': 'checked_against_supplied_reference' if reference else 'not_verified',
            'reference_dataset_sha256': reference.dataset_sha256 if reference else None,
            'reference_rows': len(reference.records) if reference else 0,
            'template_algorithm': 'casefold, normalize whitespace, mask URLs/emails/digits; minimum 80 characters and 12 words',
            'template_repeats_within_evaluation': template_repeats,
            'limitation': 'Heuristic matching against the supplied reference only; complete training corpus coverage is not verified.',
        },
        'alert_policy': 'medium/high/critical count as alerts; unknown and inference failures remain undetermined in denominators',
        'confidence_intervals': 'two-sided 95% Wilson score intervals; correlated templates may reduce effective sample size',
        'limitations': [
            'Source metadata and labels are supplied declarations and have not been independently verified by this tool.',
            'Public corpus results do not establish accuracy on real user inboxes or enterprise traffic.',
            'Temporal isolation and full model training independence are not established.',
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--reference-manifest', type=Path)
    parser.add_argument('--output', type=Path, help='Aggregate JSON report; defaults to stdout')
    args = parser.parse_args()
    try:
        corpus = load_corpus(args.manifest)
        reference = load_corpus(args.reference_manifest) if args.reference_manifest else None
    except (ValueError, OSError):
        parser.error('Invalid corpus: check manifest provenance, labels, local relative paths, size bounds and content hashes')
    from content_inference import load_content_pipeline_artifact
    from config import load_settings
    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text())['env']
    evaluation_env = {**profile, 'TRUSTED_AUTHSERV_IDS': '', 'SENDER_HISTORY_ENABLED': 'false',
                      'EMAIL_VERIFICATION_ENABLED': 'false', 'CASE_MANAGEMENT_ENABLED': 'false'}
    with patch.dict(os.environ, evaluation_env, clear=True):
        import app
    settings = load_settings(evaluation_env)
    model_hash = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
    pipeline = load_content_pipeline_artifact(PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_hash)
    try:
        with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
            report = evaluate_corpus(corpus, analyze_record, model_sha256=model_hash, reference=reference)
    except ValueError:
        parser.error('Corpus failed duplicate-label or model-integrity validation')
    metadata = _evaluation_metadata({'trusted_authserv_ids': [], 'observe_sender_history': False,
                                    'network_services_enabled': False})
    metadata['evaluator_sha256'] = hashlib.sha256(Path(__file__).read_bytes() +
        (WEBSITE_DIR / 'tools/evaluation_data.py').read_bytes()).hexdigest()
    report['reproducibility'] = metadata
    serialized = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(serialized, encoding='utf-8')
    else:
        print(serialized, end='')
    if report['counts']['failures'] or not report['counts']['evaluated']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
