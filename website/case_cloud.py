"""Bounded single-organization case storage over Upstash REST.

One Redis hash, one atomic HSET per mutation: records, summaries and request
keys cannot become partially updated. Never expire or evict this namespace.
"""
import hashlib
import json
import re
import uuid
from urllib.request import Request, build_opener, HTTPRedirectHandler

from case_store import CaseConflict, CaseInvalid, CaseNotFound, RISKS, now, validate_review, case_title


class CaseUnavailable(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


CREATE_SCRIPT = '''
local prior = redis.call('HGET', KEYS[1], 'q:' .. ARGV[1])
if prior then
  local entry = cjson.decode(prior)
  if entry.digest ~= ARGV[2] then return {'conflict'} end
  return {'ok', redis.call('HGET', KEYS[1], 'r:' .. entry.id)}
end
if redis.call('HLEN', KEYS[1]) >= 300 then return {'capacity'} end
redis.call('HSET', KEYS[1], 'r:' .. ARGV[3], ARGV[4],
  's:' .. ARGV[3], ARGV[5], 'q:' .. ARGV[1], ARGV[6])
return {'ok', ARGV[4]}
'''
UPDATE_SCRIPT = '''
local raw = redis.call('HGET', KEYS[1], 'r:' .. ARGV[1])
if not raw then return {'missing'} end
if cjson.decode(raw).version ~= tonumber(ARGV[2]) then return {'conflict'} end
redis.call('HSET', KEYS[1], 'r:' .. ARGV[1], ARGV[3], 's:' .. ARGV[1], ARGV[4])
return {'ok', ARGV[3]}
'''
LIST_SCRIPT = '''
local result = {}
for _, field in ipairs(redis.call('HKEYS', KEYS[1])) do
  if string.sub(field, 1, 2) == 's:' then
    table.insert(result, redis.call('HGET', KEYS[1], field))
  end
end
return result
'''
SUMMARY_FIELDS = ('id', 'title', 'risk', 'status', 'verdict', 'version',
                  'created_at', 'updated_at', 'created_by')


def feedback_workspace_name(workspace):
    if len(workspace) <= 55:
        return workspace + '-feedback'
    return workspace[:43].rstrip('-') + '-' + hashlib.sha256(workspace.encode()).hexdigest()[:8] + '-feedback'


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def summary(case):
    return encoded({field: case[field] for field in SUMMARY_FIELDS})


class UpstashCaseStore:
    def __init__(self, url, token, workspace, *, opener=None):
        if not re.fullmatch(r'https://[a-zA-Z0-9-]+\.upstash\.io', url):
            raise ValueError('CASE_REDIS_REST_URL must be an Upstash HTTPS endpoint')
        if not token or '\n' in token or '\r' in token:
            raise ValueError('CASE_REDIS_REST_TOKEN is required')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}', workspace):
            raise ValueError('CASE_WORKSPACE must be 3–64 lowercase letters, digits or hyphens')
        self.url, self._token = url, token
        self.key = 'phishguard:cases:v1:' + workspace
        self._open = opener or build_opener(NoRedirect()).open

    def execute(self, *command):
        request = Request(self.url, data=encoded(command).encode(), method='POST', headers={
            'Authorization': 'Bearer ' + self._token, 'Content-Type': 'application/json'})
        try:
            with self._open(request, timeout=5) as response:
                raw = response.read(4_000_001)
            if len(raw) > 4_000_000:
                raise ValueError('Response too large')
            result = json.loads(raw)
            if not isinstance(result, dict) or 'error' in result or 'result' not in result:
                raise ValueError('Invalid response')
            return result['result']
        except Exception:
            raise CaseUnavailable('Case storage is unavailable; reload to check whether the operation completed') from None

    def _decode(self, raw):
        try:
            case = json.loads(raw)
            if not isinstance(case, dict) or not isinstance(case['events'], list) or case['version'] < 1:
                raise ValueError()
            return case
        except (ValueError, TypeError, KeyError):
            raise CaseUnavailable('Invalid stored case') from None

    def get(self, case_id):
        raw = self.execute('HGET', self.key, 'r:' + case_id)
        if raw is None:
            raise CaseNotFound('Case not found')
        return self._decode(raw)

    def existing(self, actor, request_key, input_sha256):
        raw = self.execute('HGET', self.key, 'q:' + self.request_id(actor, request_key))
        if raw is None:
            return None
        try:
            entry = json.loads(raw)
            if entry['digest'] != input_sha256:
                raise CaseConflict('Creation key was already used for different input')
            return self.get(entry['id'])
        except (ValueError, TypeError, KeyError, CaseNotFound):
            raise CaseUnavailable('Invalid creation record') from None

    @staticmethod
    def request_id(actor, key):
        return hashlib.sha256((actor + '\0' + key).encode()).hexdigest()

    def _result(self, result):
        if not isinstance(result, list) or not result:
            raise CaseUnavailable('Invalid storage response')
        if result[0] == 'conflict':
            raise CaseConflict('Case or creation key changed; reload before retrying')
        if result[0] == 'missing':
            raise CaseNotFound('Case not found')
        if result[0] == 'capacity':
            raise CaseInvalid('Workspace reached its 100-case limit; contact the administrator')
        if result[0] != 'ok' or len(result) != 2:
            raise CaseUnavailable('Invalid storage response')
        return self._decode(result[1])

    def create(self, *, actor, request_key, input_sha256, source, analysis, provenance):
        if analysis.get('risk_level') not in RISKS:
            raise CaseInvalid('Invalid analysis risk')
        timestamp, case_id = now(), str(uuid.uuid4())
        case = dict(id=case_id, title=case_title(source, provenance),
                    risk=analysis['risk_level'], status='pending', verdict=None, version=1,
                    created_at=timestamp, updated_at=timestamp, created_by=actor,
                    input_sha256=input_sha256, source=source, analysis=analysis, provenance=provenance,
                    events=[dict(actor=actor, happened_at=timestamp, action='created',
                                 changes={'status': {'from': None, 'to': 'pending'}}, note='')])
        return self._result(self.execute('EVAL', CREATE_SCRIPT, 1, self.key,
            self.request_id(actor, request_key), input_sha256, case_id, self._bounded(case),
            summary(case), encoded({'id': case_id, 'digest': input_sha256})))

    def _bounded(self, case):
        raw = encoded(case)
        if len(raw.encode()) > 750_000:
            raise CaseInvalid('Case exceeds the 750 KB storage limit')
        return raw

    def update(self, case_id, *, actor, expected_version, status, verdict, note,
               feedback_reason=None, evidence_basis=None):
        case = self.get(case_id)
        changes = validate_review(case, expected_version, status, verdict, note,
                                  feedback_reason, evidence_basis)
        if len(case['events']) >= 200:
            raise CaseInvalid('Case reached its 200-event limit; contact the administrator')
        timestamp = now()
        case['events'].append(dict(actor=actor, happened_at=timestamp,
            action='reopened' if case['status'] == 'closed' else 'reviewed', changes=changes, note=note.strip()))
        case.update(status=status, verdict=verdict, updated_at=timestamp, version=expected_version + 1)
        return self._result(self.execute('EVAL', UPDATE_SCRIPT, 1, self.key, case_id,
            expected_version, self._bounded(case), summary(case)))

    def list(self, *, status=None, risk=None, created_from=None, created_to=None, limit=25, offset=0):
        values = self.execute('EVAL', LIST_SCRIPT, 1, self.key)
        try:
            items = [json.loads(value) for value in values]
            items = [item for item in items if
                     (not status or item['status'] == status) and
                     (not risk or item['risk'] == risk) and
                     (not created_from or item['created_at'][:10] >= created_from) and
                     (not created_to or item['created_at'][:10] <= created_to)]
            items.sort(key=lambda item: (item['created_at'], item['id']), reverse=True)
            return {'items': items[offset:offset + limit], 'total': len(items)}
        except (ValueError, KeyError, TypeError):
            raise CaseUnavailable('Invalid case list') from None
