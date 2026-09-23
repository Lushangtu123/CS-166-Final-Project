"""Transactional case records for a single-organization, persistent-host pilot."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid


class CaseConflict(Exception):
    pass


class CaseInvalid(Exception):
    pass


class CaseNotFound(Exception):
    pass


STATUSES = {'pending', 'in_progress', 'closed'}
VERDICTS = {'phishing', 'legitimate', 'uncertain'}
RISKS = {'safe', 'low', 'medium', 'high', 'critical', 'unknown'}
FEEDBACK_REASONS = {'false_alert', 'missed_threat', 'risk_level', 'evidence_error',
                    'no_issue_found', 'insufficient_evidence', 'other'}
EVIDENCE_BASES = {'retained_message', 'external_verification', 'report_only'}


def case_title(source, provenance):
    title = source.get('subject', '').strip()
    if not title and provenance.get('record_kind') == 'user_feedback':
        title = 'User feedback · ' + provenance.get('report_type', 'other')
    return (title or 'Untitled message')[:200]


def ambiguous_feedback_subject(subject, source_schema):
    """Old feedback sometimes mixed a display title into original message text.

    Do not strip it: it may have been a real subject. Recheck the original source.
    New source schema 2 separates display titles from explicitly supplied subjects.
    """
    return not (type(source_schema) is int and source_schema == 2) and subject in (
        'User feedback · false_positive', 'User feedback · false_negative',
        'User feedback · incorrect_risk', 'User feedback · incorrect_evidence', 'User feedback · other')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class CaseStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise CaseInvalid('Unsupported case database schema')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, risk TEXT NOT NULL,
                    status TEXT NOT NULL, verdict TEXT, version INTEGER NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    created_by TEXT NOT NULL, request_key TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL, source TEXT NOT NULL,
                    analysis TEXT NOT NULL, provenance TEXT NOT NULL,
                    UNIQUE(created_by, request_key)
                );
                CREATE TABLE IF NOT EXISTS case_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL REFERENCES cases(id),
                    actor TEXT NOT NULL, happened_at TEXT NOT NULL,
                    action TEXT NOT NULL, changes TEXT NOT NULL, note TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS case_filter ON cases(status, risk, created_at);
                CREATE INDEX IF NOT EXISTS case_time ON cases(created_at, id);
                CREATE INDEX IF NOT EXISTS event_case ON case_events(case_id, sequence);
                PRAGMA user_version=1;
            ''')
        self.path.chmod(0o600)

    @contextmanager
    def connection(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            else:
                db.execute('BEGIN')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _get(self, db, case_id):
        row = db.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
        if row is None:
            raise CaseNotFound('Case not found')
        result = dict(row)
        result.pop('request_key')
        for key in ('source', 'analysis', 'provenance'):
            result[key] = json.loads(result[key])
        result['events'] = []
        for event in db.execute('SELECT actor,happened_at,action,changes,note FROM case_events '
                                'WHERE case_id=? ORDER BY sequence', (case_id,)):
            event = dict(event)
            event['changes'] = json.loads(event['changes'])
            result['events'].append(event)
        return result

    def get(self, case_id):
        with self.connection() as db:
            return self._get(db, case_id)

    def capacity(self):
        with self.connection() as db:
            used = db.execute('SELECT count(*) FROM cases').fetchone()[0]
        return {'used': used, 'limit': None}

    def existing(self, actor, request_key, input_sha256):
        with self.connection() as db:
            return self._existing(db, actor, request_key, input_sha256)

    def _existing(self, db, actor, request_key, digest):
        row = db.execute('SELECT id,input_sha256 FROM cases WHERE created_by=? AND request_key=?',
                         (actor, request_key)).fetchone()
        if row:
            if row['input_sha256'] != digest:
                raise CaseConflict('Creation key was already used for different input')
            return self._get(db, row['id'])
        return None

    def create(self, *, actor, request_key, input_sha256, source, analysis, provenance):
        if analysis.get('risk_level') not in RISKS:
            raise CaseInvalid('Invalid analysis risk')
        with self.connection(write=True) as db:
            existing = self._existing(db, actor, request_key, input_sha256)
            if existing:
                return existing
            case_id, timestamp = str(uuid.uuid4()), now()
            title = case_title(source, provenance)
            db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                case_id, title, analysis['risk_level'], 'pending', None, 1,
                timestamp, timestamp, actor, request_key, input_sha256,
                json.dumps(source), json.dumps(analysis), json.dumps(provenance)))
            self._event(db, case_id, actor, timestamp, 'created', {'status': {'from': None, 'to': 'pending'}}, '')
            return self._get(db, case_id)

    def _event(self, db, case_id, actor, timestamp, action, changes, note):
        db.execute('INSERT INTO case_events(case_id,actor,happened_at,action,changes,note) '
                   'VALUES (?,?,?,?,?,?)', (case_id, actor, timestamp, action, json.dumps(changes), note))

    def update(self, case_id, *, actor, expected_version, status, verdict, note,
               feedback_reason=None, evidence_basis=None):
        with self.connection(write=True) as db:
            current = self._get(db, case_id)
            changes = validate_review(current, expected_version, status, verdict, note,
                                      feedback_reason, evidence_basis)
            timestamp = now()
            db.execute('UPDATE cases SET status=?,verdict=?,version=version+1,updated_at=? WHERE id=?',
                       (status, verdict, timestamp, case_id))
            self._event(db, case_id, actor, timestamp,
                        'reopened' if current['status'] == 'closed' else 'reviewed', changes, note.strip())
            return self._get(db, case_id)

    def list(self, *, status=None, risk=None, created_from=None, created_to=None, limit=25, offset=0):
        clauses, params = [], []
        for column, value in (('status', status), ('risk', risk)):
            if value:
                clauses.append(column + '=?')
                params.append(value)
        if created_from:
            clauses.append('created_at>=?')
            params.append(created_from + 'T00:00:00')
        if created_to:
            clauses.append('created_at<=?')
            params.append(created_to + 'T23:59:59.999999Z')
        where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
        with self.connection() as db:
            count = db.execute('SELECT count(*) FROM cases' + where, params).fetchone()[0]
            rows = db.execute('SELECT id,title,risk,status,verdict,version,created_at,updated_at,created_by '
                              'FROM cases' + where + ' ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?',
                              [*params, min(100, max(1, limit)), max(0, offset)]).fetchall()
            return {'items': [dict(row) for row in rows], 'total': count}

    def save_opinion(self, case_id, *, actor, expected_version, opinion):
        from case_opinions import opinion_changes
        with self.connection(write=True) as db:
            current = self._get(db, case_id)
            changes = opinion_changes(current, actor, expected_version, opinion)
            if changes is None:
                return current
            timestamp = now()
            self._event(db, case_id, actor, timestamp, 'auxiliary_saved', changes, '')
            db.execute('UPDATE cases SET version=version+1,updated_at=? WHERE id=?', (timestamp, case_id))
            result = self._get(db, case_id)
            if len(json.dumps(result, separators=(',', ':'), ensure_ascii=True).encode()) > 750_000:
                raise CaseInvalid('Case exceeds the 750 KB storage limit')
            return result


def feedback_review_fields(case):
    fields = {'feedback_reason': None, 'evidence_basis': None}
    for event in case.get('events', []):
        for key in fields:
            change = event.get('changes', {}).get(key)
            if isinstance(change, dict):
                fields[key] = change.get('to')
    return fields


def validate_review(current, expected_version, status, verdict, note,
                    feedback_reason=None, evidence_basis=None):
    """Shared domain rules; adapters enforce the version again atomically."""
    if status not in STATUSES or verdict is not None and verdict not in VERDICTS:
        raise CaseInvalid('Invalid status or verdict')
    if len(note) > 4000:
        raise CaseInvalid('Note exceeds 4,000 characters')
    if current['version'] != expected_version:
        raise CaseConflict('Case changed; reload before submitting your review')
    transitions = {'pending': {'pending', 'in_progress'},
                   'in_progress': {'in_progress', 'closed'}, 'closed': {'in_progress'}}
    if status not in transitions[current['status']]:
        raise CaseInvalid('Start work before closing, or reopen a closed case')
    if status == 'closed' and verdict is None:
        raise CaseInvalid('A human verdict is required to close a case')
    feedback = current.get('provenance', {}).get('record_kind') == 'user_feedback'
    if feedback:
        previous = feedback_review_fields(current)
        reason = (feedback_reason or None) if feedback_reason is not None else previous['feedback_reason']
        basis = (evidence_basis or None) if evidence_basis is not None else previous['evidence_basis']
        if reason is not None and reason not in FEEDBACK_REASONS or \
                basis is not None and basis not in EVIDENCE_BASES:
            raise CaseInvalid('Invalid feedback review reason or evidence basis')
        if status == 'closed' and (reason is None or basis is None):
            raise CaseInvalid('Choose a feedback reason and evidence basis before closing')
        if status == 'closed' and not note.strip():
            raise CaseInvalid('Explain the feedback verdict in a review note before closing')
        if status == 'closed' and basis == 'report_only' and verdict != 'uncertain':
            raise CaseInvalid('Reporter-only evidence cannot support a definite verdict')
        if status == 'closed' and basis == 'retained_message' and \
                current['provenance'].get('source_consent') is not True:
            raise CaseInvalid('The original message was not retained for review')
    elif feedback_reason is not None or evidence_basis is not None:
        raise CaseInvalid('Feedback review fields are only valid for user feedback')
    changes = {key: {'from': current[key], 'to': value}
               for key, value in (('status', status), ('verdict', verdict)) if current[key] != value}
    if feedback:
        for key, value in (('feedback_reason', reason), ('evidence_basis', basis)):
            if value != previous[key]:
                changes[key] = {'from': previous[key], 'to': value}
    if not changes and not note.strip():
        raise CaseInvalid('Provide a change or a note')
    if verdict != current['verdict'] and not note.strip():
        raise CaseInvalid('Explain the verdict change in a note')
    return changes
