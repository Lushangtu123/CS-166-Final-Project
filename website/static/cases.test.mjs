import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.className = ''; this.hidden = false; this.disabled = false; this.open = false; this.dataset = {}; this.listeners = {}; this.children = []; this.files = []; this.attrs = {}; this.classList = {add(){},remove(){}}; }
  set innerHTML(_) { throw new Error('Untrusted content must never use HTML'); }
  setAttribute(key, value) { this.attrs[key] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  reset() {}
  showModal() { this.open = true; }
  close() { this.open = false; this.dispatchEvent({type: 'close'}); }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  dispatchEvent(event) { this.listeners[event.type]?.(event); }
  contains(target) { return target === this; }
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const caseValue = () => ({id: 'case-1', title: '<img src=x onerror=alert(1)>', risk: 'high', status: 'pending', verdict: null, version: 1,
  created_by: 'alice', created_at: '2026-09-20T00:00:00Z', source: {subject: 'Synthetic', body: '<script>bad()</script>'},
  analysis: {extra_indicators: ['<iframe src=x>']}, provenance: {}, events: [{actor: 'alice', action: 'created', happened_at: '2026-09-20T00:00:00Z', changes: {}, note: '<svg onload=bad()>'}]});
function setup(handler, vision = {cancel() {}, render() {}}) {
  const elements = new Map(), calls = [], windowEvents = {};
  const el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const source = readFileSync(new URL('./cases.js', import.meta.url), 'utf8');
  class DataTransfer { constructor(){this.files=[];this.items={add:file=>this.files.push(file)};} }
  const window = {addEventListener(name, callback) { windowEvents[name] = callback; }, confirm: () => true, PhishGuardVision: vision};
  const context=vm.createContext({document: {getElementById: el, createElement: () => new Element(), addEventListener() {}}, window,
    DataTransfer, Event, URLSearchParams, crypto: {randomUUID: () => 'synthetic-uuid'}, fetch: async (url, options) => { calls.push({url, options}); const result = await handler(url, options); return {ok: result.status < 400, status: result.status, json: async () => result.data}; }});
  vm.runInContext(readFileSync(new URL('./file-intake.js',import.meta.url),'utf8'),context);
  vm.runInContext(source,context);
  const fire = async (id, name = 'click') => { el(id).listeners[name]({preventDefault() {}, submitter: el(id + '-submit'), currentTarget: el(id)}); await tick(); };
  const login = async () => { el('token').value = 'synthetic-access-token-at-least-32-characters'; await fire('login-form', 'submit'); };
  return {el, fire, login, calls, window, windowEvents};
}
const standard = async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [caseValue()], total: 1} : caseValue()});

test('a detail read started before a save cannot replace the saved revision', async () => {
  let releaseSave, releaseRead, delayRead = false;
  const ui = setup(async (url, options) => options.method === 'PATCH'
    ? await new Promise(resolve => { releaseSave = resolve; })
    : url.split('?')[0].endsWith('/case-1') && delayRead
      ? await new Promise(resolve => { releaseRead = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'Saved note';
  await ui.fire('review-form', 'submit');
  delayRead = true; await ui.fire('reload-case');
  releaseSave({status:200, data:{...caseValue(),version:2,status:'in_progress'}}); await tick();
  ui.el('note').value = 'New draft after save';
  releaseRead({status:200, data:caseValue()}); await tick();
  assert.equal(ui.el('review-status').value, 'in_progress');
  assert.equal(ui.el('note').value, 'New draft after save');
  assert.match(ui.el('case-meta').textContent, /2/);
});

test('partial queues identify unavailable sources and carry record kind to detail and review', async () => {
  const feedback = {...caseValue(),kind:'feedback'};
  let partial = true;
  const ui = setup(async (url, options) => url.startsWith('/api/cases?')
    ? {status:200,data:{items:[feedback],total:1,partial,sources:{case:partial?'unavailable':'available',feedback:'available'}}}
    : options.method === 'PATCH' || url.split('?')[0].endsWith('/case-1')
      ? {status:200,data:feedback} : standard(url));
  await ui.login();
  assert.match(ui.el('queue-warning').textContent, /case.*unavailable/i);
  assert.match(ui.el('count').textContent, /available sources/i);
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert(ui.calls.some(c=>c.url==='/api/cases/case-1?kind=feedback'));
  await ui.fire('review-form','submit');
  assert(ui.calls.some(c=>c.options.method==='PATCH' && c.url==='/api/cases/case-1?kind=feedback'));
  partial=false; await ui.fire('refresh');
  assert.equal(ui.el('queue-warning').textContent,'');
});

test('cached Jev lookup uses GET while disabled; explicit save retains history and current review draft', async () => {
  const receipt = 'a'.repeat(64);
  const opinion = {receipt_id:receipt,model:'jev-1.13.0',requested_at:'2026-09-22T00:00:00Z',
    probabilities:{phishing_intent:0.75},affects_risk:false};
  const saved = {...caseValue(),version:2,auxiliary_save:{outcome:'saved',base_version:1,receipt_id:receipt},events:[...caseValue().events,{actor:'alice',action:'auxiliary_saved',
    happened_at:'2026-09-22T00:00:01Z',changes:{auxiliary_opinion:{from:null,to:opinion}},note:''}]};
  const ui = setup(async (url, options) => url.endsWith('/auxiliary/save') ? {status:200,data:saved}
    : url.endsWith('/auxiliary') ? {status:200,data:{...opinion,status:'available',case_id:'case-1',case_version:1,reused:true}}
    : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-read').disabled,false);
  assert.equal(ui.el('jev-run').disabled,true);
  ui.el('note').value='Unsaved human review'; await ui.fire('jev-read');
  assert.equal(ui.calls.find(c=>c.url.endsWith('/auxiliary')).options.method, 'GET');
  assert.equal(ui.el('jev-save').hidden,false);
  ui.window.confirm=()=>false; await ui.fire('jev-save');
  assert(!ui.calls.some(c=>c.url.endsWith('/auxiliary/save')));
  ui.window.confirm=()=>true; await ui.fire('jev-save');
  const sent=JSON.parse(ui.calls.find(c=>c.url.endsWith('/auxiliary/save')).options.body);
  assert.deepEqual(sent,{expected_version:1,receipt_id:receipt,confirm_save:true});
  assert.equal(ui.el('note').value,'Unsaved human review');
  assert.equal(ui.el('draft-rebase').hidden,true);
  assert.match(ui.el('case-meta').textContent,/Revision 2/);
  const text = element => element.textContent + element.children.map(text).join(' ');
  assert.match(text(ui.el('history')), /75\.0%/);
  assert.match(text(ui.el('history')), /jev-1\.13\.0/);
  assert.doesNotMatch(text(ui.el('history')), /\[object Object\]/);
});

test('repeated opinion save keeps a conflict when another review advanced the case', async () => {
const opinion={receipt_id:'a'.repeat(64),model:'jev-1.13.0',requested_at:'2026-09-22T00:00:00Z',probabilities:{phishing_intent:.75},affects_risk:false};
const original={...caseValue(),version:2,status:'in_progress',events:[...caseValue().events,{actor:'alice',action:'auxiliary_saved',happened_at:'2026-09-22T00:00:01Z',changes:{auxiliary_opinion:{from:null,to:opinion}},note:''}]};
const changed={...original,version:3,auxiliary_save:{outcome:'already_saved',base_version:2,receipt_id:opinion.receipt_id},verdict:'phishing',events:[...original.events,{actor:'alice',action:'reviewed',happened_at:'2026-09-22T00:00:02Z',changes:{verdict:{from:null,to:'phishing'}},note:'Updated in another tab'}]};
const ui=setup(async url=>url.endsWith('/me') ? {status:200,data:{actor:'alice'}}
 :url.startsWith('/api/cases?') ? {status:200,data:{items:[original],total:1}}
 :url.endsWith('/auxiliary/save') ? {status:200,data:changed}
 :url.endsWith('/auxiliary') ? {status:200,data:{...opinion,status:'available',case_id:'case-1',case_version:2,reused:true}}
 : {status:200,data:original});
await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
ui.el('verdict').value='legitimate'; ui.el('note').value='Unsaved competing verdict'; await ui.fire('review-form','input');
await ui.fire('jev-read'); await ui.fire('jev-save');
assert.equal(ui.el('draft-rebase').hidden,false);
assert.equal(ui.el('save-review').disabled,true);
assert.equal(ui.el('verdict').value,'legitimate');
assert.match(ui.el('notice').textContent,/already saved/i);
});

test('late cached lookup is cleared at signout and never posts to the model route', async () => {
  let release;
  const ui=setup(async url=>url.endsWith('/auxiliary') ? await new Promise(resolve=>{release=resolve;}) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('jev-read'); await ui.fire('logout');
  release({status:200,data:{status:'available',receipt_id:'b'.repeat(64),case_id:'case-1',case_version:1}}); await tick();
  assert.equal(ui.el('jev-save').hidden,true);
  assert.equal(ui.el('jev-results').children.length,0);
  assert(!ui.calls.some(c=>c.url.endsWith('/auxiliary')&&c.options.method==='POST'));
});

test('saving one opinion cannot release a different case lookup in flight', async () => {
  let releaseSave, releaseRead;
  const second={...caseValue(),id:'case-2'};
  const ui=setup(async (url, options) => {
    if(url.endsWith('/auxiliary/save')) return await new Promise(resolve=>{releaseSave=resolve;});
    if(url.endsWith('/case-1/auxiliary')) return {status:200,data:{status:'available',receipt_id:'a'.repeat(64),case_id:'case-1',case_version:1}};
    if(url.endsWith('/case-2/auxiliary')) return await new Promise(resolve=>{releaseRead=resolve;});
    if(url.startsWith('/api/cases?')) return {status:200,data:{items:[caseValue(),second],total:2}};
    if(url.startsWith('/api/cases/case-2?')) return {status:200,data:second};
    return standard(url);
  });
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('jev-read'); await ui.fire('jev-save');
  ui.el('case-list').children[1].listeners.click(); await tick();
  await ui.fire('jev-read');
  releaseSave({status:200,data:{...caseValue(),version:2}}); await tick();
  assert.equal(ui.el('jev-read').disabled,true);
  await ui.fire('jev-read');
  assert.equal(ui.calls.filter(c=>c.url.endsWith('/case-2/auxiliary')).length,1);
  releaseRead({status:200,data:{status:'skipped',reason:'no_cached_opinion',case_id:'case-2',case_version:1}}); await tick();
  assert.equal(ui.el('jev-read').disabled,false);
});

test('capacity shows both unfiltered queues, warns near full and recovers after an unavailable refresh', async () => {
  let capacity = {cases:{status:'available',used:80,limit:100},feedback:{status:'available',used:100,limit:100}};
  const ui = setup(async url => url.endsWith('/capacity') ? {status:200,data:capacity} : standard(url));
  await ui.login();
  assert.match(ui.el('case-capacity').textContent, /80 \/ 100/);
  assert.match(ui.el('feedback-capacity').textContent, /100 \/ 100/);
  assert.match(ui.el('capacity-warning').textContent, /full/i);
  ui.el('filter-status').value = 'closed'; await ui.fire('filters','submit');
  assert.match(ui.el('case-capacity').textContent, /80 \/ 100/);
  capacity = {cases:{status:'unavailable'},feedback:{status:'available',used:5,limit:null}};
  await ui.fire('refresh');
  assert.match(ui.el('case-capacity').textContent, /unavailable/i);
  assert.doesNotMatch(ui.el('case-capacity').textContent, /80|0 \/ 100/);
  assert.match(ui.el('feedback-capacity').textContent, /5/);
  assert.doesNotMatch(ui.el('feedback-capacity').textContent, /100|unlimited/i);
  assert.equal(ui.el('case-list').children.length, 1);
  capacity = {cases:{status:'available',used:20,limit:100},feedback:{status:'available',used:5,limit:100}};
  await ui.fire('refresh');
  assert.match(ui.el('case-capacity').textContent, /20 \/ 100/);
  assert.equal(ui.el('capacity-warning').textContent, '');
});

test('late capacity responses cannot restore information after signout', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/capacity') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); await ui.fire('logout');
  release?.({status:200,data:{cases:{status:'available',used:80,limit:100}}}); await tick();
  assert.equal(ui.el('case-capacity').textContent, '');
  assert.equal(ui.el('workspace').hidden, true);
});

test('review drafts survive switching and reload without being silently rebased', async () => {
  let revision = 1;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? {status: 200, data: {...caseValue(), version: revision + 1, status: 'in_progress'}}
    : url.split('?')[0].endsWith('/case-1') ? {status: 200, data: {...caseValue(), version: revision}}
    : url.split('?')[0].endsWith('/case-2') ? {status: 200, data: {...caseValue(), id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200, data:{items:[caseValue(), {...caseValue(), id:'case-2'}],total:2}}
    : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Keep this review'; ui.el('verdict').value = 'uncertain';
  ui.el('case-list').children[1].listeners.click(); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, 'Keep this review');
  assert.equal(ui.el('verdict').value, 'uncertain');
  revision = 2; await ui.fire('reload-case');
  assert.equal(ui.el('note').value, 'Keep this review');
  await ui.fire('review-form', 'submit');
  assert.equal(ui.calls.filter(c => c.options.method === 'PATCH').length, 0);
  assert.equal(ui.el('draft-rebase').hidden, false);
  await ui.fire('draft-rebase'); await ui.fire('review-form', 'submit');
  const sent = JSON.parse(ui.calls.find(c => c.options.method === 'PATCH').options.body);
  assert.equal(sent.expected_version, 2); assert.equal(sent.note, 'Keep this review');
  assert.equal(ui.el('note').value, '');
});

test('drafts warn before leaving, support discard, and are cleared at signout', async () => {
  const ui = setup(standard); await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Private draft';
  let prevented = false;
  ui.windowEvents.beforeunload?.({preventDefault(){prevented=true;}});
  assert.equal(prevented, true);
  ui.window.confirm = () => false; await ui.fire('logout');
  assert.equal(ui.el('workspace').hidden, false); assert.equal(ui.el('note').value, 'Private draft');
  await ui.fire('draft-discard'); assert.equal(ui.el('note').value, '');
  prevented = false; ui.windowEvents.beforeunload({preventDefault(){prevented=true;}});
  assert.equal(prevented, false);
  ui.el('note').value = 'Another private draft'; ui.window.confirm = () => true;
  await ui.fire('logout'); await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, '');
});

test('a review saved after switching cases does not reappear as an unsaved note', async () => {
  let release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Submitted note'; await ui.fire('review-form','submit');
  ui.el('note').value = 'Later unsaved note';
  ui.el('case-list').children[1].listeners.click(); await tick();
  saved = {...caseValue(),version:2}; release({status:200,data:saved}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, 'Later unsaved note');
  assert.equal(ui.el('draft-rebase').hidden, true);
});

test('saving a review preserves later edits and the next save uses the new revision', async () => {
  let release;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'First note';
  await ui.fire('review-form', 'submit');
  ui.el('note').value = 'New note typed while saving';
  ui.el('verdict').value = 'uncertain';
  release({status: 200, data: {...caseValue(), version: 2, status: 'in_progress'}}); await tick();
  assert.equal(ui.el('note').value, 'New note typed while saving');
  assert.equal(ui.el('verdict').value, 'uncertain');
  assert.match(ui.el('notice').textContent, /unsaved/i);
  await ui.fire('review-form', 'submit');
  const sent = ui.calls.filter(c => c.options.method === 'PATCH').map(c => JSON.parse(c.options.body));
  assert.equal(sent[1].expected_version, 2);
  assert.equal(sent[1].note, 'New note typed while saving');
  release({status: 200, data: {...caseValue(), version: 3, status: 'in_progress', verdict: 'uncertain'}}); await tick();
  assert.equal(ui.el('note').value, '');
  assert.equal(ui.el('notice').textContent, 'Review saved.');
});

test('reverting to the previous status during a pending save remains a newer edit after switching away', async () => {
  let release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; await ui.fire('review-form','submit');
  ui.el('review-status').value = 'pending';
  ui.el('case-list').children[1].listeners.click(); await tick();
  saved = {...caseValue(),version:2,status:'in_progress'};
  release({status:200,data:saved}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('review-status').value, 'pending');
  await ui.fire('review-form','submit');
  assert.equal(ui.calls.filter(c=>c.options.method==='PATCH').length,1);
});

test('a completed save stays clean when switching during a slow capacity refresh', async () => {
  let holdCapacity = false, release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? {status:200,data:(saved={...caseValue(),version:2})}
    : url.endsWith('/capacity') && holdCapacity ? await new Promise(resolve=>{release=resolve;})
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value='Saved note'; holdCapacity=true;
  await ui.fire('review-form','submit');
  ui.el('case-list').children[1].listeners.click(); await tick();
  holdCapacity=false; release({status:200,data:{}}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value,''); assert.equal(ui.el('draft-status').textContent,'');
});

test('authenticated analysts can open and close the create-case drawer without losing the draft', async () => {
  const ui = setup(standard); await ui.login();
  assert.equal(typeof ui.el('open-compose').listeners.click, 'function');
  assert.equal(typeof ui.el('close-compose').listeners.click, 'function');
  ui.el('subject').value = 'Keep this draft';
  await ui.fire('open-compose');
  assert.equal(ui.el('compose-dialog').open, true);
  await ui.fire('close-compose');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, 'Keep this draft');
});

test('queue rows expose the dashboard columns while keeping untrusted titles as text', async () => {
  const ui = setup(standard); await ui.login();
  const row = ui.el('case-list').children[0];
  assert.deepEqual(row.children.map(child => child.className),
    ['case-cell risk-cell', 'case-cell title-cell', 'case-cell status-cell',
      'case-cell verdict-cell', 'case-cell date-cell']);
  assert.equal(row.children[1].children[0].textContent, '<img src=x onerror=alert(1)>');
});

test('signout closes and clears the create-case drawer', async () => {
  const ui = setup(standard); await ui.login();
  ui.el('subject').value = 'Private draft';
  await ui.fire('open-compose');
  await ui.fire('logout');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, '');
});

test('successful creation closes the drawer and keeps the saved case selected', async () => {
  const ui = setup(standard); await ui.login();
  await ui.fire('open-compose');
  ui.el('subject').value = 'Synthetic case';
  await ui.fire('create-form', 'submit');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, '');
  assert.equal(ui.el('case-title').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'true');
});

test('Jev failure shows actionable safe guidance without retrying or changing risk', async () => {
  for (const [reason, message] of [['provider_authentication', /API key/], ['provider_timeout', /timed out/],
                                  ['provider_request_invalid', /request format/], ['private-secret', /unavailable or skipped/]]) {
    const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
      url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: 1, status: 'unavailable', reason}} : standard(url));
    await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
    const original = ui.el('analysis-summary').textContent;
    ui.el('jev-consent').checked = true; await ui.fire('jev-run');
    assert.match(ui.el('jev-status').textContent, message);
    assert(!ui.el('jev-status').textContent.includes('private-secret'));
    assert.equal(ui.el('analysis-summary').textContent, original);
    assert.equal(ui.calls.filter(call => call.url.endsWith('/auxiliary')).length, 1);
  }
});

test('protected Preview login preserves the gateway session and still requires the analyst token', async () => {
  for (const accepted of [true, false]) {
    const ui = setup(async (url, options) => {
      // The deployment gateway redirects cookieless requests to external SSO,
      // which the application's same-origin CSP correctly blocks.
      if (!['same-origin', 'include'].includes(options.credentials)) throw new TypeError('Failed to fetch');
      if (!accepted || options.headers.Authorization !== 'Bearer synthetic-access-token-at-least-32-characters') {
        return {status: 401, data: {detail: 'A valid analyst access token is required'}};
      }
      return standard(url);
    });
    await ui.login();
    if (accepted) {
      assert.equal(ui.el('notice').textContent, '');
      assert.equal(ui.el('login-panel').hidden, true);
      assert.equal(ui.el('case-list').children.length, 1);
    } else {
      assert.equal(ui.el('workspace').hidden, true);
      assert.equal(ui.el('token').value, '');
      assert.match(ui.el('notice').textContent, /valid analyst access token/);
    }
  }
});

test('Jev is opt-in, independent of case risk, and rendered as text', async () => {
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: caseValue().version,
      status: 'available', model: '<img src=x onerror=bad()>', evidence_incomplete: true,
      probabilities: {phishing_intent: .95, insufficient_evidence: .7}}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-panel').hidden, false);
  await ui.fire('jev-run');
  assert(!ui.calls.some(call => call.url.endsWith('/auxiliary')));
  assert.match(ui.el('jev-status').textContent, /permission/);
  const original = ui.el('analysis-summary').textContent;
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  const request = ui.calls.find(call => call.url.endsWith('/auxiliary'));
  assert.deepEqual(JSON.parse(request.options.body), {allow_external_processing: true});
  assert.match(ui.el('jev-status').textContent, /<img src=x onerror=bad\(\)>/);
  assert.match(ui.el('jev-status').textContent, /evidence is incomplete/);
  assert.equal(ui.el('jev-results').children[0].children.length, 2);
  assert.equal(ui.el('analysis-summary').textContent, original);
  assert.equal(ui.el('jev-consent').checked, false);
  await ui.fire('logout');
  assert.equal(ui.el('jev-panel').hidden, true);
  assert.equal(ui.el('jev-results').children.length, 0);
});

test('late Jev results cannot reappear after switching case or signing out', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  await ui.fire('logout');
  release({status: 200, data: {status: 'available', model: 'jev', probabilities: {phishing_intent: 1}}}); await tick();
  assert.equal(ui.el('jev-results').children.length, 0);
  assert.equal(ui.el('jev-status').textContent, '');
});

test('Jev panel explains unavailable configuration and refreshes without losing notes', async () => {
  let enabled = false;
  const handler = async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice',
    jev_available: enabled, jev: {status: enabled ? 'available' : 'configuration_error', daily_limit: 20, used: 0}}} : standard(url);
  const ui = setup(handler); await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-panel').hidden, false);
  assert.equal(ui.el('jev-run').disabled, true);
  assert.match(ui.el('jev-availability').textContent, /configuration/i);
  ui.el('note').value = 'Unsaved review';
  enabled = true; await ui.fire('refresh');
  assert.equal(ui.el('jev-run').disabled, false);
  assert.equal(ui.el('note').value, 'Unsaved review');
  assert(!ui.calls.some(call => call.url.endsWith('/auxiliary')));
});

test('dropped and pasted case files use existing recognition and require explicit submission',async()=>{
  for(const kind of ['drop','paste']){
    let recognized;
    const ui=setup(standard,{cancel(){},render(){},async recognize(file){recognized=file;return {observations:[],warnings:[]};}});
    await ui.login();
    const file={name:'clipboard.png',type:'image/png',size:100};
    ui.el('case-file-dropzone').listeners[kind]({preventDefault(){},stopPropagation(){},
      [kind==='drop'?'dataTransfer':'clipboardData']:{files:[file],types:['Files']}});
    assert.equal(ui.el('body').disabled,true);assert.match(ui.el('case-file-status').textContent,/clipboard.png loaded/);
    assert(!ui.calls.some(call=>call.options.method==='POST'));
    await ui.fire('create-form','submit');
    assert.equal(recognized,file);assert(ui.calls.some(call=>call.url==='/api/cases/visual'));
    assert.equal(ui.el('case-file-status').textContent,'');
  }
});

test('token is sent only in auth header and untrusted evidence is rendered as text', async () => {
  const ui = setup(standard); await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('source').textContent, 'Synthetic\n\n<script>bad()</script>');
  assert.equal(ui.el('case-title').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(ui.el('history').children[0].children.at(-1).textContent, '<svg onload=bad()>');
  assert.equal(ui.el('token').value, '');
  assert(ui.calls.every(call => !call.url.includes('token') && call.options.headers.Authorization.startsWith('Bearer ') && call.options.cache === 'no-store'));
  assert.equal(ui.el('next').disabled, true);
});

test('signout clears saved content and late responses cannot restore it', async () => {
  let release;
  const ui = setup(async url => url.split('?')[0].endsWith('/case-1') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('logout'); release({status: 200, data: caseValue()}); await tick();
  assert.equal(ui.el('source').textContent, ''); assert.equal(ui.el('workspace').hidden, true);
  assert.equal(ui.el('case-list').children.length, 0);
});

test('failed creation retries with same idempotency key and input', async () => {
  const ui = setup(async (url, opts) => opts.method === 'POST' ? {status: 503, data: {detail: 'Storage unavailable'}} : standard(url));
  await ui.login(); ui.el('subject').value = 'Synthetic';
  await ui.fire('create-form', 'submit'); await ui.fire('create-form', 'submit');
  const posts = ui.calls.filter(call => call.options.method === 'POST');
  assert.equal(posts.length, 2); assert.equal(posts[0].options.headers['Idempotency-Key'], posts[1].options.headers['Idempotency-Key']);
  assert.equal(posts[0].options.body, posts[1].options.body);
  assert.equal(ui.el('subject').value, 'Synthetic');
});

test('a stale review preserves the analyst note and requests reload', async () => {
  const ui = setup(async (url, opts) => opts.method === 'PATCH' ? {status: 409, data: {detail: 'Conflict'}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Do not lose this note'; ui.el('review-status').value = 'in_progress';
  await ui.fire('review-form', 'submit');
  assert.equal(ui.el('note').value, 'Do not lose this note');
  assert.match(ui.el('notice').textContent, /Another analyst/);
  const patch = JSON.parse(ui.calls.find(call => call.options.method === 'PATCH').options.body);
  assert.equal(patch.expected_version, 1); assert.equal(patch.actor, undefined);
});

test('feedback review sends structured reason and evidence basis without changing case reviews', async () => {
  const feedback = {...caseValue(), id: 'feedback-1', kind: 'feedback', provenance: {record_kind: 'user_feedback', source_consent: true},
    events: [...caseValue().events, {actor: 'alice', action: 'reviewed', happened_at: '2026-09-21T00:00:00Z',
      changes: {feedback_reason: {from: null, to: 'false_alert'}, evidence_basis: {from: null, to: 'retained_message'}}, note: ''}]};
  const ui = setup(async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} :
    url.startsWith('/api/cases?') ? {items: [feedback], total: 1} : feedback}));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('feedback-review-fields').hidden, false);
  assert.equal(ui.el('feedback-reason').value, 'false_alert');
  assert.equal(ui.el('evidence-basis').value, 'retained_message');
  await ui.fire('review-form', 'submit');
  const patch = JSON.parse(ui.calls.find(call => call.options.method === 'PATCH').options.body);
  assert.equal(patch.feedback_reason, 'false_alert');
  assert.equal(patch.evidence_basis, 'retained_message');
});

test('selected case stays visibly selected after switching cases and refreshing the queue', async () => {
  const first = caseValue(), second = {...caseValue(), id: 'case-2', title: 'Second message', risk: 'safe'};
  const ui = setup(async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [first, second], total: 2} : url.split('?')[0].endsWith('/case-2') ? second : first}));
  await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'true');
  ui.el('case-list').children[1].listeners.click(); await tick();
  assert.equal(ui.el('case-title').textContent, 'Second message');
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'false');
  assert.equal(ui.el('case-list').children[1].attrs['aria-pressed'], 'true');
  await ui.fire('refresh');
  assert.equal(ui.el('case-list').children[1].attrs['aria-pressed'], 'true');
});


test('image case retry reuses extracted evidence and its idempotency key', async () => {
  let scans=0;
  const vision={cancel(){},render(){},async recognize(){scans++;return {observations:[{ocr_text:'Synthetic OCR'}],warnings:[]};}};
  const ui=setup(async(url,opts)=>opts.method==='POST'?{status:503,data:{detail:'Unavailable'}}:standard(url),vision);
  await ui.login(); ui.el('eml').files=[{name:'synthetic.png',size:100}];
  await ui.fire('create-form','submit'); await ui.fire('create-form','submit');
  const posts=ui.calls.filter(c=>c.options.method==='POST');
  assert.equal(scans,1);assert.equal(posts.length,2);assert.equal(posts[0].url,'/api/cases/visual');
  assert.equal(posts[0].options.body,posts[1].options.body);
  assert.equal(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
});
test('signout during OCR prevents late extraction from posting a case', async()=>{
  let release,cancelled=false;
  const ui=setup(standard,{render(){},cancel(){cancelled=true;},recognize:()=>new Promise(resolve=>{release=resolve;})});
  await ui.login();ui.el('eml').files=[{name:'synthetic.png',size:100}];
  await ui.fire('create-form','submit');await ui.fire('logout');
  release({observations:[],warnings:[]});await tick();
  assert.equal(cancelled,true);assert.equal(ui.el('workspace').hidden,true);
  assert.equal(ui.calls.filter(c=>c.options.method==='POST').length,0);
});

test('case OCR forwards language and invalidates in-flight output when it changes',async()=>{
  let release, selectedLanguage;
  const ui=setup(standard,{cancel(){},render(){},async recognize(_file,_progress,language){
    selectedLanguage=language;return new Promise(resolve=>{release=resolve;});
  }});
  await ui.login();ui.el('eml').files=[{name:'test.png',size:1}];
  ui.el('case-ocr-language').value='eng+chi_sim';
  await ui.fire('create-form','submit');assert.equal(selectedLanguage,'eng+chi_sim');
  ui.el('case-ocr-language').value='eng';await ui.fire('case-ocr-language','change');
  release({observations:[],warnings:[]});await tick();
  assert(!ui.calls.some(call=>call.options.method==='POST'));
});

test('quota exhausted still retrieves a prior receipt and never changes risk', async () => {
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true,
    jev: {status: 'quota_exhausted', daily_limit: 20, used: 20, reset_at: 1790121600}}} :
    url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: 1,
      status: 'available', model: 'jev', reused: true, probabilities: {phishing_intent: .2}}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.match(ui.el('jev-availability').textContent, /daily allowance is exhausted/);
  assert.equal(ui.el('jev-run').disabled, false);
  const risk = ui.el('analysis-summary').textContent;
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  assert.match(ui.el('jev-status').textContent, /no new provider call/);
  assert.equal(ui.el('analysis-summary').textContent, risk);
});

test('refresh during Jev request keeps it busy and cannot send duplicate calls', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('jev-consent').checked = true; await ui.fire('jev-run'); await ui.fire('refresh');
  assert.equal(ui.el('jev-run').disabled, true);
  await ui.fire('jev-run');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/auxiliary')).length, 1);
  release({status: 200, data: {case_id: 'case-1', case_version: 1, status: 'skipped', reason: 'request_pending', receipt_expires_at: 1790121600}});
  await tick();
  assert.match(ui.el('jev-status').textContent, /outcome is unknown/);
  assert.match(ui.el('jev-status').textContent, /will not start another provider call/);
  assert.equal(ui.el('jev-run').disabled, false);
});

test('failed status refresh disables Jev without clearing unsaved notes', async () => {
  let failed = false;
  const ui = setup(async url => url.endsWith('/me') ? {status: failed ? 503 : 200,
    data: {actor: 'alice', jev_available: true, detail: 'Storage unavailable'}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Keep this note'; failed = true; await ui.fire('refresh');
  assert.equal(ui.el('note').value, 'Keep this note');
  assert.equal(ui.el('jev-run').disabled, true);
  assert.match(ui.el('jev-availability').textContent, /controls are unavailable/);
});

test('review edits made during a failed save survive without a success notice', async () => {
  let release;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Submitted';
  await ui.fire('review-form', 'submit'); ui.el('note').value = 'Unsaved after request';
  release({status: 503, data: {detail: 'Storage unavailable'}}); await tick();
  assert.equal(ui.el('note').value, 'Unsaved after request');
  assert.equal(ui.el('notice').textContent, 'Storage unavailable');
});

test('new feedback choices survive saving and unavailable status requires a new choice', async () => {
  let release;
  const feedback = {...caseValue(), kind: 'feedback', status: 'in_progress'};
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : {status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [feedback], total: 1} : feedback});
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'closed'; ui.el('note').value = 'Closing';
  await ui.fire('review-form', 'submit');
  ui.el('feedback-reason').value = 'missed_threat';
  ui.el('evidence-basis').value = 'external_verification';
  ui.el('review-status').value = 'pending'; // A no-longer-valid draft cannot silently change the saved state.
  release({status: 200, data: {...feedback, status: 'closed', version: 2}}); await tick();
  assert.equal(ui.el('note').value, ''); // The submitted note was saved, not a new draft.
  assert.equal(ui.el('feedback-reason').value, 'missed_threat');
  assert.equal(ui.el('evidence-basis').value, 'external_verification');
  assert.equal(ui.el('review-status').value, 'pending');
  await ui.fire('review-form', 'submit');
  assert.match(ui.el('notice').textContent, /Choose an available status/);
  assert.equal(ui.calls.filter(c => c.options.method === 'PATCH').length, 1);
});

test('history capacity protects reserved slots while allowing a final close', async () => {
  const full = {...caseValue(), status:'in_progress', version:199,
    history_capacity:{used:199,limit:200,recovery_limit:202,remaining:0,review_statuses:['closed'],can_save_opinion:false}};
  const ui=setup(async url=>url.endsWith('/auxiliary')
    ? {status:200,data:{status:'available',case_id:full.id,case_version:199,receipt_id:'a'.repeat(64)}}
    : url.endsWith('/me') ? {status:200,data:{actor:'alice'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[full],total:1}}
    : {status:200,data:full});
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.match(ui.el('history-capacity').textContent,/199/);
  assert.match(ui.el('history-capacity').textContent,/reserved/i);
  assert.equal(ui.el('save-review').disabled,true);
  await ui.fire('jev-read'); assert.equal(ui.el('jev-save').disabled,true);
  ui.el('review-status').value='closed'; await ui.fire('review-form','change');
  assert.equal(ui.el('save-review').disabled,false);
});

test('feedback overview uses all retained reports and clears counts when storage fails', async () => {
  let overview={status:'available',total:7,pending:2,in_progress:1,closed:4,false_alerts:1,missed_threats:2};
  const ui=setup(async url=>url.endsWith('/feedback-overview') ? {status:200,data:overview} : standard(url));
  await ui.login();
  assert.equal(ui.el('feedback-open-count').textContent,'3');
  assert.equal(ui.el('feedback-closed-count').textContent,'4');
  assert.equal(ui.el('feedback-false-alerts-count').textContent,'1');
  assert.equal(ui.el('feedback-missed-threats-count').textContent,'2');
  ui.el('filter-kind').value='feedback'; ui.el('filter-verdict').value='legitimate';
  ui.el('filter-feedback-reason').value='false_alert'; await ui.fire('filters','submit');
  const url=ui.calls.filter(c=>c.url.startsWith('/api/cases?')).at(-1).url;
  assert.match(url,/verdict=legitimate/); assert.match(url,/feedback_reason=false_alert/);
  assert.match(ui.el('feedback-overview-status').textContent,/not.*model/i);
  assert.equal(ui.el('feedback-open-count').textContent,'3');
  overview={status:'unavailable'}; await ui.fire('refresh');
  assert.equal(ui.el('feedback-open-count').textContent,'—');
  assert.match(ui.el('feedback-overview-status').textContent,/unavailable/i);
  ui.el('filter-kind').value='case'; await ui.fire('filter-kind','change');
  assert.equal(ui.el('filter-feedback-reason').value,'');
  assert.equal(ui.el('filter-feedback-reason').disabled,true);
  await ui.fire('logout'); assert.equal(ui.el('feedback-overview-status').textContent,'');
});

test('an old feedback overview cannot overwrite a newer refresh or a signed-out screen', async () => {
  let release;
  const ui=setup(async url=>url.endsWith('/feedback-overview') ? await new Promise(resolve=>{release=resolve;}) : standard(url));
  await ui.login(); const old=release; await ui.fire('refresh');
  release({status:200,data:{status:'available',total:1,pending:0,in_progress:0,closed:1,false_alerts:1,missed_threats:0}}); await tick();
  old({status:200,data:{status:'available',total:2,pending:2,in_progress:0,closed:0,false_alerts:0,missed_threats:0}}); await tick();
  assert.equal(ui.el('feedback-open-count').textContent,'0');
  await ui.fire('refresh'); await ui.fire('logout');
  release({status:200,data:{status:'available',total:9,pending:9,in_progress:0,closed:0,false_alerts:0,missed_threats:0}}); await tick();
  assert.equal(ui.el('feedback-overview-status').textContent,'');
  assert.equal(ui.el('feedback-open-count').textContent,'—');
});
