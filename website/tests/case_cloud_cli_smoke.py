"""Print a Redis CLI smoke command for an isolated, expiring synthetic namespace.

Run the printed command manually in the provider console. It exercises the
actual production Lua scripts without requiring a local credential. No real
case records are read or changed. Expected result: CASE_LUA_SMOKE_OK.
"""
import json
from pathlib import Path
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from case_cloud import CREATE_SCRIPT, UPDATE_SCRIPT, LIST_SCRIPT

script = '''
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 'ALREADY_RUN' end
local function create(ARGV)
''' + CREATE_SCRIPT + '''
end
local function update(ARGV)
''' + UPDATE_SCRIPT + '''
end
local function list()
''' + LIST_SCRIPT + '''
end
local record = cjson.encode({id='synthetic',version=1,events={{actor='alice'}}})
local args = {'request','digest','synthetic',record,cjson.encode({id='synthetic'}),cjson.encode({id='synthetic',digest='digest'})}
assert(create(args)[1] == 'ok')
redis.call('EXPIRE', KEYS[1], 3600)
assert(create(args)[2] == record)
args[2] = 'different'
assert(create(args)[1] == 'conflict')
local changed = cjson.encode({id='synthetic',version=2,events={{actor='alice'},{actor='bob'}}})
assert(update({'synthetic','1',changed,cjson.encode({id='synthetic'})})[1] == 'ok')
assert(update({'synthetic','1',changed,'{}'})[1] == 'conflict')
assert(update({'missing','1',changed,'{}'})[1] == 'missing')
assert(#list() == 1)
local stored = cjson.decode(redis.call('HGET', KEYS[1], 'r:synthetic'))
assert(stored.version == 2 and #stored.events == 2 and stored.events[2].actor == 'bob')
return 'CASE_LUA_SMOKE_OK'
'''
# This command contains synthetic data only. A unique key makes retries isolated.
print('EVAL ' + json.dumps(' '.join(script.splitlines())) + ' 1 phishguard:cases:smoke:' + uuid.uuid4().hex)
