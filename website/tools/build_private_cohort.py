"""Prepare a private evaluation JSONL from reviewed feedback and separate annotations.

The annotation file must be prepared by an authorized independent reviewer.
Reviewer identity and label evidence are self-attested; this tool checks structure
and family separation, not the truth of the labels or training-set overlap.
"""

import argparse
import base64
import binascii
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools.case_archive import PROJECT_ROOT, _canonical, write_private_bytes
from case_store import FEEDBACK_REASONS


MAX_INPUT_BYTES = 160_000_000
IDENTIFIER = re.compile(r'[A-Za-z0-9_.-]{1,80}')


def read_private_jsonl(path, *, with_digest=False):
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Input must be a private regular file (mode 0600).')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('Private input exceeds the local size limit.')
    raw = path.read_bytes()
    rows = []
    for line_number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(f'Line {line_number}: invalid JSON.') from None
        if not isinstance(row, dict):
            raise ValueError(f'Line {line_number}: expected a JSON object.')
        rows.append(row)
    return (rows, hashlib.sha256(raw).hexdigest()) if with_digest else rows


def _message(row):
    mode = row.get('input_mode')
    if mode == 'content':
        subject, body = row.get('subject'), row.get('body')
        if not isinstance(subject, str) or not isinstance(body, str) or not (subject + body).strip():
            raise ValueError('Draft content is incomplete.')
        raw = _canonical({'subject': subject, 'body': body})
        content = {'subject': subject, 'body': body}
    elif mode == 'eml':
        try:
            encoded = row.get('eml_base64')
            raw = base64.b64decode(encoded, validate=True)
        except (TypeError, binascii.Error):
            raise ValueError('Draft EML is invalid.') from None
        if not 0 < len(raw) <= 60_000:
            raise ValueError('Draft EML exceeds the 60 KB limit.')
        content = {'_eml_bytes': raw}
    else:
        raise ValueError('Draft input mode is not eligible.')
    if hashlib.sha256(mode.encode() + b'\0' + raw).hexdigest() != row.get('content_sha256'):
        raise ValueError('Draft message fingerprint does not match.')
    return content


def build_cohort(draft, annotations):
    if not draft or not annotations:
        raise ValueError('A nonempty draft and annotation set are required.')
    by_id = {}
    fingerprints = set()
    for row in draft:
        case_id = row.get('id')
        try:
            if not isinstance(case_id, str) or str(UUID(case_id)) != case_id:
                raise ValueError()
        except ValueError:
            raise ValueError('Draft contains an invalid record ID.') from None
        if case_id in by_id or row.get('schema') != 'reviewed-feedback-draft-v1' or \
                row.get('label') not in {'phishing', 'legitimate'} or \
                row.get('source_consent') is not True or \
                row.get('evaluation_consent') is not True or \
                row.get('evidence_basis') not in {'retained_message', 'external_verification'} or \
                not isinstance(row.get('review_reason'), str) or \
                row['review_reason'] not in FEEDBACK_REASONS or \
                not isinstance(row.get('reviewed_by'), str) or \
                not isinstance(row.get('case_reviewer_ids'), list) or \
                not row['case_reviewer_ids'] or \
                any(not isinstance(actor, str) or not IDENTIFIER.fullmatch(actor)
                    for actor in row['case_reviewer_ids']) or \
                row['reviewed_by'] not in row['case_reviewer_ids']:
            raise ValueError('Draft contains a duplicate or unreviewed record.')
        fingerprint = row.get('content_sha256')
        if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint) or \
                fingerprint in fingerprints:
            raise ValueError('Draft contains duplicate or invalid message fingerprints.')
        fingerprints.add(fingerprint)
        by_id[case_id] = row
    output = {'development': [], 'holdout': []}
    family_role = {}
    seen = set()
    for row in annotations:
        case_id = row.get('id')
        if case_id not in by_id or case_id in seen:
            raise ValueError('Annotation ID is unknown or duplicated.')
        seen.add(case_id)
        source = by_id[case_id]
        reviewer, family = row.get('independent_reviewer'), row.get('family_id')
        if not isinstance(reviewer, str) or not IDENTIFIER.fullmatch(reviewer) or \
                reviewer in source['case_reviewer_ids'] or \
                not isinstance(family, str) or not IDENTIFIER.fullmatch(family):
            raise ValueError('An independent reviewer and stable family ID are required.')
        provider, language, received_at = row.get('provider'), row.get('language'), row.get('received_at')
        if provider not in {'gmail', 'outlook'} or \
                not isinstance(language, str) or not re.fullmatch(r'[a-z]{2,3}', language) or \
                not isinstance(received_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', received_at):
            raise ValueError('Provider, language or received date is invalid.')
        try:
            date.fromisoformat(received_at)
        except ValueError:
            raise ValueError('Received date is not a calendar date.') from None
        role = row.get('cohort_role')
        if role not in output:
            raise ValueError('Cohort role must be development or holdout.')
        if family in family_role and family_role[family] != role:
            raise ValueError('A message family cannot occur in both cohort roles.')
        family_role[family] = role
        if row.get('label') != source['label']:
            raise ValueError('Independent label disagrees with the case verdict; resolve it before evaluation.')
        content = _message(source)
        output[role].append({'id': case_id, 'label': row['label'], 'provider': provider,
                             'language': language, 'received_at': received_at,
                             'family_id': family, **content})
    for role in output:
        output[role].sort(key=lambda row: row['id'])
    return output


def write_cohort(output_dir, cohort, *, draft_sha256, annotations_sha256):
    output_dir = Path(output_dir).expanduser().resolve()
    if output_dir.is_relative_to(PROJECT_ROOT):
        raise ValueError('Save private cohort output outside the Git repository.')
    output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    counts = {}
    for role, rows in cohort.items():
        serialized = []
        for row in rows:
            prepared = dict(row)
            if '_eml_bytes' in prepared:
                raw = prepared.pop('_eml_bytes')
                path = write_private_bytes(output_dir / (prepared['id'] + '.eml'), raw)
                prepared['eml_path'] = str(path)
            serialized.append(_canonical(prepared) + b'\n')
        write_private_bytes(output_dir / (role + '.jsonl'), b''.join(serialized))
        counts[role] = len(rows)
    write_private_bytes(output_dir / 'lineage.json', _canonical({
        'schema': 'private-cohort-lineage-v1', 'draft_sha256': draft_sha256,
        'annotations_sha256': annotations_sha256, 'counts': counts,
        'independence': 'self_attested_not_verified',
    }) + b'\n')
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--draft', required=True, type=Path)
    parser.add_argument('--annotations', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        draft, draft_digest = read_private_jsonl(args.draft, with_digest=True)
        annotations, annotation_digest = read_private_jsonl(args.annotations, with_digest=True)
        cohort = build_cohort(draft, annotations)
        counts = write_cohort(args.output_dir, cohort,
                              draft_sha256=draft_digest,
                              annotations_sha256=annotation_digest)
    except (ValueError, OSError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise SystemExit(str(exc)) from None
    print(f'Private development and holdout inputs created: {counts}.')
    print('Independent labels are self-attested; review consent, sampling and training overlap before use.')


if __name__ == '__main__':
    main()
