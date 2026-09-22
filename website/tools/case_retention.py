"""Plan retention and optionally purge one archived, unchanged cloud record.

This is an operator tool, not an API. It never schedules deletion. Keep the
private archive until the operator's retention policy says it can be destroyed.
"""

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from case_cloud import CaseUnavailable, UpstashCaseStore, feedback_workspace_name
from tools.case_archive import read_archive, validate_archive


PURGE_SCRIPT = '''
local key = KEYS[1]
for i = 1, 3 do
  if redis.call('HGET', key, ARGV[i]) ~= ARGV[i + 3] then return 'changed' end
end
if redis.call('HDEL', key, ARGV[1], ARGV[2], ARGV[3]) ~= 3 then return 'changed' end
return 'deleted'
'''


def retention_candidates(archive, kind, before):
    if kind not in {'case', 'feedback'}:
        raise ValueError('Choose the case or feedback namespace.')
    records, _ = validate_archive(archive)[kind]
    if not isinstance(before, date):
        raise ValueError('Before must be a calendar date.')
    candidates = []
    for case_id, record in records.items():
        try:
            updated = date.fromisoformat(record['updated_at'][:10])
        except ValueError:
            raise ValueError('Archive has an invalid record timestamp.') from None
        if record['status'] == 'closed' and updated < before:
            candidates.append(case_id)
    return sorted(candidates)


def purge_one(store, archive, *, kind, case_id, before):
    if kind not in {'case', 'feedback'}:
        raise ValueError('Choose the case or feedback namespace.')
    try:
        if str(UUID(case_id)) != case_id:
            raise ValueError()
    except ValueError:
        raise ValueError('Record ID must be a canonical UUID.') from None
    retention_candidates(archive, kind, before)
    if store.key != archive['source_keys'][kind]:
        raise ValueError('Cloud workspace does not match the private archive.')
    if case_id not in retention_candidates(archive, kind, before):
        raise ValueError('Record is absent, open, or not older than the cutoff date.')
    fields = archive['namespaces'][kind]
    names = ['r:' + case_id, 's:' + case_id]
    names.extend(name for name, raw in fields.items()
                 if name.startswith('q:') and json.loads(raw)['id'] == case_id)
    if len(names) != 3:
        raise ValueError('Archive creation index is incomplete.')
    result = store.execute('EVAL', PURGE_SCRIPT, 1, store.key,
                           *names, *(fields[name] for name in names))
    if result == 'changed':
        raise ValueError('Cloud record changed after archiving; make a new archive before retrying.')
    if result != 'deleted':
        raise CaseUnavailable('Cloud deletion result is uncertain; inspect the record before retrying.')
    for name in names:
        if store.execute('HGET', store.key, name) is not None:
            raise CaseUnavailable('Cloud deletion verification failed; inspect the record before retrying.')
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--kind', choices=('case', 'feedback'), required=True)
    parser.add_argument('--before', required=True, help='Only records last updated before YYYY-MM-DD')
    parser.add_argument('--record-id', help='Canonical UUID; omit for read-only inventory')
    parser.add_argument('--case-workspace', help='Required when deleting from Upstash')
    parser.add_argument('--feedback-workspace', help='Only if the feedback namespace is overridden')
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', args.before):
            raise ValueError('Before must be YYYY-MM-DD.')
        before = date.fromisoformat(args.before)
        archive = read_archive(args.archive)
        candidates = retention_candidates(archive, args.kind, before)
        if args.record_id is None:
            print(f'{args.kind}: {len(candidates)} closed records last updated before {before}.')
            print('Candidate IDs: ' + (', '.join(candidates) if candidates else '(none)'))
            return
        if not args.case_workspace:
            raise ValueError('--case-workspace is required for cloud deletion.')
        if args.record_id not in candidates:
            raise ValueError('This record is not eligible for the requested cutoff.')
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError('Run cloud deletion in your own interactive terminal.')
        workspace = (args.case_workspace if args.kind == 'case' else
                     args.feedback_workspace or feedback_workspace_name(args.case_workspace))
        url = os.environ.get('CASE_REDIS_REST_URL') or os.environ.get('UPSTASH_REDIS_REST_URL', '')
        token = os.environ.get('CASE_REDIS_REST_TOKEN') or os.environ.get('UPSTASH_REDIS_REST_TOKEN', '')
        store = UpstashCaseStore(url, token, workspace)
        if store.key != archive['source_keys'][args.kind]:
            raise ValueError('Cloud workspace does not match the private archive.')
        print(f'Permanently delete {args.kind} {args.record_id} and its two indexes from {store.key}.')
        print('The archive and other exported copies will still contain the record.')
        if input(f'Type DELETE {args.record_id} to continue: ').strip() != f'DELETE {args.record_id}':
            raise ValueError('Deletion cancelled.')
        purge_one(store, archive, kind=args.kind, case_id=args.record_id, before=before)
        print('Cloud record and indexes deleted and verified.')
    except (CaseUnavailable, ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == '__main__':
    main()
