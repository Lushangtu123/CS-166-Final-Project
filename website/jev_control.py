"""Shared daily attempt budget and 24-hour receipts. No message text is stored.

Reserve before contacting TypeSafe; ambiguous operations stay reserved. Redis
uses one separate, expiring hash per workspace/environment and atomic Lua.
SQLite uses the same transaction boundary on persistent local installations.
"""
import hashlib
import json
import re
import time
from uuid import uuid4

from case_cloud import UpstashCaseStore, CaseUnavailable
from jev import MODEL, QUESTIONS_SHA256, input_state, _encoded

DAY = 86400


def request_identity(actor, case_id, prepared):
    return hashlib.sha256(_encoded([actor, case_id, MODEL, QUESTIONS_SHA256,
                                   input_state(**prepared)])).hexdigest()


SCRIPT = '''
local now = tonumber(redis.call('TIME')[1])
local day = math.floor(now / 86400)
local reset = (day + 1) * 86400
local used = 0
if tonumber(redis.call('HGET', KEYS[1], 'day')) == day then
  used = tonumber(redis.call('HGET', KEYS[1], 'count')) or 0
end
local limit = tonumber(ARGV[2])
local result = {used=used, daily_limit=limit, reset_at=reset}
if ARGV[1] == 'snapshot' then return cjson.encode(result) end
local field = 'r:' .. ARGV[3]
local raw = redis.call('HGET', KEYS[1], field)
local entry = raw and cjson.decode(raw) or nil
if ARGV[1] == 'finish' then
  if not entry or entry.expires_at <= now or entry.claim ~= ARGV[4] then
    return cjson.encode({status='lost'})
  end
  if not entry.result then
    entry.result = cjson.decode(ARGV[5])
    redis.call('HSET', KEYS[1], field, cjson.encode(entry))
  end
  return cjson.encode({status='saved'})
end
if entry and entry.expires_at > now then
  result.status = entry.result and 'cached' or 'pending'
  result.result = entry.result
  result.expires_at = entry.expires_at
  return cjson.encode(result)
end
if used >= limit then result.status='quota_exhausted'; return cjson.encode(result) end
for _, key in ipairs(redis.call('HKEYS', KEYS[1])) do
  if string.sub(key, 1, 2) == 'r:' then
    local old = cjson.decode(redis.call('HGET', KEYS[1], key))
    if old.expires_at <= now then redis.call('HDEL', KEYS[1], key) end
  end
end
entry = {expires_at=now+86400, claim=ARGV[4]}
redis.call('HSET', KEYS[1], 'day', day, 'count', used+1, field, cjson.encode(entry))
redis.call('EXPIRE', KEYS[1], 172800)
result.status='reserved'; result.used=used+1; result.expires_at=entry.expires_at
return cjson.encode(result)
'''


class JevControl:
    def __init__(self, store, environment='local', *, clock=time.time):
        self.store, self.scope, self.clock = store, environment, clock
        if isinstance(store, UpstashCaseStore):
            self.key = store.key.replace('phishguard:cases:v1:', 'phishguard:jev:v1:', 1) + ':' + environment
        else:
            with store.connection(write=True) as db:
                db.execute('CREATE TABLE IF NOT EXISTS jev_budget (scope TEXT PRIMARY KEY, day INTEGER, used INTEGER)')
                db.execute('CREATE TABLE IF NOT EXISTS jev_receipts (scope TEXT, request_id TEXT, expires_at INTEGER, claim TEXT, result TEXT, PRIMARY KEY(scope, request_id))')

    def _run(self, operation, limit, request_id='', claim='', result=''):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('Invalid daily limit')
        if operation != 'snapshot' and not re.fullmatch(r'[0-9a-f]{64}', request_id):
            raise ValueError('Invalid request identity')
        if isinstance(self.store, UpstashCaseStore):
            try:
                value = json.loads(self.store.execute('EVAL', SCRIPT, 1, self.key,
                                                     operation, limit, request_id, claim, result))
                if not isinstance(value, dict):
                    raise ValueError()
                if operation == 'finish':
                    if value.get('status') not in {'saved', 'lost'}:
                        raise ValueError()
                else:
                    if any(type(value.get(k)) is not int or value[k] < 0
                           for k in ('used', 'daily_limit', 'reset_at')):
                        raise ValueError()
                    if value['daily_limit'] != limit:
                        raise ValueError()
                    if operation != 'snapshot' and value.get('status') not in {'reserved', 'cached', 'pending', 'quota_exhausted'}:
                        raise ValueError()
                    if value.get('status') in {'reserved', 'cached', 'pending'} and (
                            type(value.get('expires_at')) is not int or value['expires_at'] <= 0):
                        raise ValueError()
                    if value.get('status') == 'cached' and not isinstance(value.get('result'), dict):
                        raise ValueError()
                return value
            except (ValueError, TypeError, KeyError):
                raise CaseUnavailable('Invalid auxiliary control response') from None
        now = int(self.clock())
        day = now // DAY
        with self.store.connection(write=operation != 'snapshot') as db:
            row = db.execute('SELECT day, used FROM jev_budget WHERE scope=?', (self.scope,)).fetchone()
            used = row['used'] if row and row['day'] == day else 0
            value = {'used': used, 'daily_limit': limit, 'reset_at': (day + 1) * DAY}
            if operation == 'snapshot':
                return value
            entry = db.execute('SELECT * FROM jev_receipts WHERE scope=? AND request_id=?',
                               (self.scope, request_id)).fetchone()
            if operation == 'finish':
                if not entry or entry['expires_at'] <= now or entry['claim'] != claim:
                    return {'status': 'lost'}
                if entry['result'] is None:
                    db.execute('UPDATE jev_receipts SET result=? WHERE scope=? AND request_id=?',
                               (result, self.scope, request_id))
                return {'status': 'saved'}
            if entry and entry['expires_at'] > now:
                return {**value, 'status': 'cached' if entry['result'] else 'pending',
                        'result': json.loads(entry['result']) if entry['result'] else None,
                        'expires_at': entry['expires_at']}
            if used >= limit:
                return {**value, 'status': 'quota_exhausted'}
            db.execute('DELETE FROM jev_receipts WHERE expires_at<=?', (now,))
            db.execute('INSERT OR REPLACE INTO jev_budget VALUES (?, ?, ?)', (self.scope, day, used + 1))
            db.execute('INSERT OR REPLACE INTO jev_receipts VALUES (?, ?, ?, ?, NULL)',
                       (self.scope, request_id, now + DAY, claim))
            return {**value, 'used': used + 1, 'status': 'reserved', 'expires_at': now + DAY}

    def snapshot(self, limit):
        return self._run('snapshot', limit)

    def reserve(self, request_id, limit):
        claim = uuid4().hex
        result = self._run('reserve', limit, request_id, claim)
        if result['status'] == 'reserved':
            result['claim'] = claim
        return result

    def finish(self, request_id, claim, result, limit):
        encoded = _encoded(result).decode()
        if len(encoded) > 16000:
            raise CaseUnavailable('Auxiliary receipt exceeds limit')
        if self._run('finish', limit, request_id, claim, encoded)['status'] != 'saved':
            raise CaseUnavailable('Auxiliary reservation expired')
