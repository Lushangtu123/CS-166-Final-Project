"""Export both private Upstash case namespaces and rehearse recovery locally.

Archives contain original mail and analyst notes. Keep them on encrypted private
storage; this tool never sends an archive to a third party or writes to Redis.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
sys.path.insert(0, str(WEBSITE_DIR))

from case_cloud import CaseUnavailable, UpstashCaseStore, SUMMARY_FIELDS, feedback_workspace_name
from case_store import CaseStore, RISKS, STATUSES, VERDICTS, HISTORY_RECOVERY_LIMIT, RECORD_RECOVERY_BYTE_LIMIT


FORMAT = 'phishguard-case-archive-v1'
MAX_ARCHIVE_BYTES = 160_000_000
FIELD = re.compile(r'(?:[rs]:[0-9a-f-]{36}|q:[0-9a-f]{64})')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def validate_namespace(fields):
    if not isinstance(fields, dict) or len(fields) > 300:
        raise ValueError('Archive namespace must contain at most 300 fields.')
    records, summaries, requests = {}, {}, {}
    for field, raw in fields.items():
        if not isinstance(field, str) or not FIELD.fullmatch(field) or not isinstance(raw, str):
            raise ValueError('Archive contains an invalid field.')
        if len(raw.encode()) > RECORD_RECOVERY_BYTE_LIMIT:
            raise ValueError('Archive contains an oversized field.')
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError('Archive contains invalid JSON.') from None
        if field.startswith('r:'):
            case_id = field[2:]
            try:
                if str(UUID(case_id)) != case_id:
                    raise ValueError()
            except ValueError:
                raise ValueError('Archive contains an invalid record ID.') from None
            if not isinstance(value, dict) or value.get('id') != case_id or \
                    not isinstance(value.get('risk'), str) or value['risk'] not in RISKS or \
                    not isinstance(value.get('status'), str) or value['status'] not in STATUSES or \
                    (value.get('verdict') is not None and
                     (not isinstance(value['verdict'], str) or value['verdict'] not in VERDICTS)) or \
                    type(value.get('version')) is not int or not 1 <= value['version'] <= HISTORY_RECOVERY_LIMIT or \
                    not isinstance(value.get('events'), list) or not 1 <= len(value['events']) <= HISTORY_RECOVERY_LIMIT or \
                    any(not isinstance(value.get(key), str) for key in
                        ('title', 'created_at', 'updated_at', 'created_by', 'input_sha256')) or \
                    any(not isinstance(value.get(key), dict) for key in ('source', 'analysis', 'provenance')):
                raise ValueError('Archive contains an invalid record.')
            if value['version'] != len(value['events']) or \
                    value['analysis'].get('risk_level') != value['risk'] or \
                    not re.fullmatch(r'[0-9a-f]{64}', value['input_sha256']) or \
                    any(not isinstance(event, dict) or
                        any(not isinstance(event.get(key), str) for key in
                            ('actor', 'happened_at', 'action', 'note')) or
                        not isinstance(event.get('changes'), dict)
                        for event in value['events']):
                raise ValueError('Archive contains invalid record history.')
            records[case_id] = value
        elif field.startswith('s:'):
            summaries[field[2:]] = value
        else:
            if not isinstance(value, dict) or not isinstance(value.get('id'), str) or \
                    not isinstance(value.get('digest'), str):
                raise ValueError('Archive contains an invalid request mapping.')
            if value['id'] in requests:
                raise ValueError('Archive contains duplicate request mappings.')
            requests[value['id']] = value
    if len(records) > 100 or records.keys() != summaries.keys() or records.keys() != requests.keys():
        raise ValueError('Archive records, summaries, and creation keys do not match.')
    for case_id, record in records.items():
        if summaries[case_id] != {key: record[key] for key in SUMMARY_FIELDS} or \
                requests[case_id]['digest'] != record['input_sha256']:
            raise ValueError('Archive record and index contents do not match.')
    return records, requests


def capture_namespace(store):
    names = store.execute('HKEYS', store.key)
    if not isinstance(names, list) or len(names) > 300 or \
            any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        raise ValueError('Cloud namespace has invalid or excess fields.')
    fields = {}
    for name in sorted(names):
        raw = store.execute('HGET', store.key, name)
        if raw is None:
            raise ValueError('Cloud namespace changed during export; retry while writes are paused.')
        fields[name] = raw
    final_names = store.execute('HKEYS', store.key)
    if not isinstance(final_names, list) or len(final_names) != len(names) or \
            any(not isinstance(name, str) for name in final_names) or set(final_names) != set(names):
        raise ValueError('Cloud namespace changed during export; retry while writes are paused.')
    validate_namespace(fields)
    return fields


def create_archive(case_store, feedback_store, *, created_at=None):
    if case_store.key == feedback_store.key:
        raise ValueError('Case and feedback namespaces must differ.')
    body = {
        'format': FORMAT,
        'created_at': created_at or datetime.now(timezone.utc).isoformat(),
        'source_keys': {'case': case_store.key, 'feedback': feedback_store.key},
        'namespaces': {'case': capture_namespace(case_store),
                       'feedback': capture_namespace(feedback_store)},
    }
    body['sha256'] = hashlib.sha256(_canonical(body)).hexdigest()
    return body


def validate_archive(archive):
    if not isinstance(archive, dict) or set(archive) != {'format', 'created_at', 'source_keys', 'namespaces', 'sha256'} or \
            archive['format'] != FORMAT or not isinstance(archive['created_at'], str) or \
            not isinstance(archive['source_keys'], dict) or set(archive['source_keys']) != {'case', 'feedback'} or \
            not isinstance(archive['namespaces'], dict) or set(archive['namespaces']) != {'case', 'feedback'}:
        raise ValueError('Invalid case archive format.')
    keys = archive['source_keys']
    if any(not isinstance(key, str) or not key.startswith('phishguard:cases:v1:') for key in keys.values()) or \
            keys['case'] == keys['feedback']:
        raise ValueError('Invalid case archive source namespaces.')
    expected = hashlib.sha256(_canonical({key: value for key, value in archive.items() if key != 'sha256'})).hexdigest()
    if archive['sha256'] != expected:
        raise ValueError('Case archive checksum mismatch.')
    return {kind: validate_namespace(archive['namespaces'][kind]) for kind in ('case', 'feedback')}


def write_private_bytes(path, payload):
    path = Path(path).expanduser()
    path = path.parent.resolve() / path.name
    if path.is_relative_to(PROJECT_ROOT):
        raise ValueError('Save private output outside the Git repository.')
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError('Private output exceeds the local size limit.')
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def write_archive(path, archive):
    validate_archive(archive)
    return write_private_bytes(path, _canonical(archive) + b'\n')


def read_archive(path):
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Archive must be a private regular file (mode 0600).')
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('Case archive exceeds the local size limit.')
    try:
        archive = json.loads(path.read_bytes())
    except (OSError, ValueError, UnicodeDecodeError):
        raise ValueError('Cannot read the case archive.') from None
    validate_archive(archive)
    return archive


def restore_local(archive, output_dir):
    """Rebuild isolated SQLite copies; never mutate the Upstash database."""
    decoded = validate_archive(archive)
    output_dir = Path(output_dir).expanduser().resolve()
    if output_dir.is_relative_to(PROJECT_ROOT):
        raise ValueError('Save private restored databases outside the Git repository.')
    output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    counts = {}
    for kind in ('case', 'feedback'):
        records, _requests = decoded[kind]
        store = CaseStore(output_dir / f'{kind}.sqlite3')
        with store.connection(write=True) as db:
            for case_id, record in sorted(records.items()):
                request_key = next(field for field, raw in archive['namespaces'][kind].items()
                                   if field.startswith('q:') and json.loads(raw).get('id') == case_id)
                db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                    case_id, record['title'], record['risk'], record['status'], record['verdict'],
                    record['version'], record['created_at'], record['updated_at'], record['created_by'],
                    request_key, record['input_sha256'], json.dumps(record['source']),
                    json.dumps(record['analysis']), json.dumps(record['provenance'])))
                for event in record['events']:
                    db.execute('INSERT INTO case_events(case_id,actor,happened_at,action,changes,note) '
                               'VALUES (?,?,?,?,?,?)', (
                                   case_id, event['actor'], event['happened_at'], event['action'],
                                   json.dumps(event['changes']), event['note']))
        for case_id, record in records.items():
            if store.get(case_id) != record:
                raise ValueError('Local restored record does not match the archive.')
        counts[kind] = len(records)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    export = sub.add_parser('export', help='Read private Upstash namespaces into a new local 0600 archive')
    export.add_argument('--case-workspace', required=True)
    export.add_argument('--feedback-workspace')
    export.add_argument('--output', required=True, type=Path)
    verify = sub.add_parser('verify', help='Validate an existing archive without network access')
    verify.add_argument('--archive', required=True, type=Path)
    restore = sub.add_parser('restore-local', help='Rehearse recovery into new local SQLite databases')
    restore.add_argument('--archive', required=True, type=Path)
    restore.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'export':
            url = os.environ.get('CASE_REDIS_REST_URL') or os.environ.get('UPSTASH_REDIS_REST_URL', '')
            token = os.environ.get('CASE_REDIS_REST_TOKEN') or os.environ.get('UPSTASH_REDIS_REST_TOKEN', '')
            cases = UpstashCaseStore(url, token, args.case_workspace)
            feedback = UpstashCaseStore(url, token,
                args.feedback_workspace or feedback_workspace_name(args.case_workspace))
            archive = create_archive(cases, feedback)
            path = write_archive(args.output, archive)
            print(f'Private archive saved: {path} (case={len(archive["namespaces"]["case"]) // 3}, '
                  f'feedback={len(archive["namespaces"]["feedback"]) // 3}).')
        elif args.action == 'verify':
            archive = read_archive(args.archive)
            print(f'Archive verified: case={len(archive["namespaces"]["case"]) // 3}, '
                  f'feedback={len(archive["namespaces"]["feedback"]) // 3}.')
        else:
            archive = read_archive(args.archive)
            counts = restore_local(archive, args.output_dir)
            print(f'Isolated local restore verified: case={counts["case"]}, feedback={counts["feedback"]}.')
    except (CaseUnavailable, ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == '__main__':
    main()
