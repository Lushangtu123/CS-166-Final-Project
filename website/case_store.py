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
            title = (source.get('subject', '').strip() or 'Untitled message')[:200]
            db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                case_id, title, analysis['risk_level'], 'pending', None, 1,
                timestamp, timestamp, actor, request_key, input_sha256,
                json.dumps(source), json.dumps(analysis), json.dumps(provenance)))
            self._event(db, case_id, actor, timestamp, 'created', {'status': {'from': None, 'to': 'pending'}}, '')
            return self._get(db, case_id)

    def _event(self, db, case_id, actor, timestamp, action, changes, note):
        db.execute('INSERT INTO case_events(case_id,actor,happened_at,action,changes,note) '
                   'VALUES (?,?,?,?,?,?)', (case_id, actor, timestamp, action, json.dumps(changes), note))

    def update(self, case_id, *, actor, expected_version, status, verdict, note):
        with self.connection(write=True) as db:
            current = self._get(db, case_id)
            changes = validate_review(current, expected_version, status, verdict, note)
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


def validate_review(current, expected_version, status, verdict, note):
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
    changes = {key: {'from': current[key], 'to': value}
               for key, value in (('status', status), ('verdict', verdict)) if current[key] != value}
    if not changes and not note.strip():
        raise CaseInvalid('Provide a change or a note')
    if verdict != current['verdict'] and not note.strip():
        raise CaseInvalid('Explain the verdict change in a note')
    return changes
