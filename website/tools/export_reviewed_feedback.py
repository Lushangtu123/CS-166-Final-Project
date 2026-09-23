"""Make a private curation draft from separately consented, closed feedback.

This is not an independent evaluation cohort. Provider, message arrival date,
label provenance, campaign separation, and training overlap need human review.
"""

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import sys

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools.case_archive import read_archive, validate_archive, write_private_bytes, _canonical
from case_store import feedback_review_fields, ambiguous_feedback_subject, feedback_review_consistent


def _source_row(record):
    source = record['source']
    mode = record['provenance'].get('input_mode')
    if mode == 'content':
        subject, body = source.get('subject', ''), source.get('body', '')
        if not isinstance(subject, str) or not isinstance(body, str) or not (subject + body).strip():
            raise ValueError('Missing retained content text.')
        content = {'subject': subject, 'body': body}
        content_bytes = _canonical(content)
    elif mode == 'eml':
        encoded = source.get('eml_base64')
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (TypeError, binascii.Error):
            raise ValueError('Missing retained original EML.') from None
        if not 0 < len(raw) <= 60_000:
            raise ValueError('Retained EML exceeds evaluation limits.')
        content = {'eml_base64': encoded}
        content_bytes = raw
    else:
        raise ValueError('Only content and original EML feedback are eligible.')
    fingerprint = hashlib.sha256(mode.encode() + b'\0' + content_bytes).hexdigest()
    row = {
        'schema': 'reviewed-feedback-draft-v1',
        'id': record['id'],
        'label': record['verdict'],
        'input_mode': mode,
        'source_schema': record['provenance'].get('source_schema', 1),
        'content_sha256': fingerprint,
        'reported_at': record['created_at'],
        'reviewed_at': record['updated_at'],
        'report_type': record['provenance'].get('report_type'),
        'reported_risk': record['analysis'].get('risk_level'),
        'model_id': record['analysis'].get('model_id'),
        'review_reason': feedback_review_fields(record)['feedback_reason'],
        'evidence_basis': feedback_review_fields(record)['evidence_basis'],
        'reviewed_by': record['events'][-1]['actor'],
        'case_reviewer_ids': sorted({event['actor'] for event in record['events']
                                     if event.get('action') in {'reviewed', 'reopened'}}),
        'source_consent': True,
        'evaluation_consent': True,
        **content,
    }
    return row


def build_reviewed_draft(archive):
    records, _requests = validate_archive(archive)['feedback']
    counts = {'total': len(records), 'no_evaluation_consent': 0, 'not_closed_or_labeled': 0,
              'unstructured_review': 0, 'invalid_source': 0, 'duplicates': 0,
              'conflicting_labels': 0, 'ambiguous_legacy_subject': 0, 'inconsistent_review': 0}
    groups = {}
    for record in records.values():
        provenance = record['provenance']
        if provenance.get('record_kind') != 'user_feedback' or \
                provenance.get('evaluation_consent') is not True or \
                provenance.get('source_consent') is not True:
            counts['no_evaluation_consent'] += 1
            continue
        if record['status'] != 'closed' or record['verdict'] not in {'phishing', 'legitimate'}:
            counts['not_closed_or_labeled'] += 1
            continue
        review = feedback_review_fields(record)
        if not feedback_review_consistent(record['verdict'], review['feedback_reason']):
            counts['inconsistent_review'] += 1
            continue
        if not review['feedback_reason'] or review['evidence_basis'] not in {
                'retained_message', 'external_verification'}:
            counts['unstructured_review'] += 1
            continue
        if provenance.get('input_mode') == 'content' and ambiguous_feedback_subject(
                record['source'].get('subject'), provenance.get('source_schema')):
            counts['ambiguous_legacy_subject'] += 1
            continue
        try:
            row = _source_row(record)
        except ValueError:
            counts['invalid_source'] += 1
            continue
        groups.setdefault((row['input_mode'], row['content_sha256']), []).append(row)
    result = []
    for rows in groups.values():
        if len({row['label'] for row in rows}) != 1:
            counts['conflicting_labels'] += len(rows)
            continue
        selected = dict(min(rows, key=lambda row: row['id']))
        selected['case_reviewer_ids'] = sorted({actor for row in rows for actor in row['case_reviewer_ids']})
        selected['source_case_ids'] = sorted(row['id'] for row in rows)
        result.append(selected)
        counts['duplicates'] += len(rows) - 1
    result.sort(key=lambda row: row['id'])
    counts['exported'] = len(result)
    return result, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        rows, counts = build_reviewed_draft(read_archive(args.archive))
        if not rows:
            raise ValueError('No separately consented, closed and labeled feedback is eligible.')
        path = write_private_bytes(args.output, b''.join(_canonical(row) + b'\n' for row in rows))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc)) from None
    print(f'Private curation draft saved: {path}. Counts: {json.dumps(counts, sort_keys=True)}')
    print('Review labels, consent, provider, arrival date, family overlap and training overlap before evaluation.')


if __name__ == '__main__':
    main()
