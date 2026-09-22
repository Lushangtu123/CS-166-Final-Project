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
  const elements = new Map(), calls = [];
  const el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const source = readFileSync(new URL('./cases.js', import.meta.url), 'utf8');
  class DataTransfer { constructor(){this.files=[];this.items={add:file=>this.files.push(file)};} }
  const context=vm.createContext({document: {getElementById: el, createElement: () => new Element(), addEventListener() {}}, window: {addEventListener() {}, PhishGuardVision: vision},
    DataTransfer, Event, URLSearchParams, crypto: {randomUUID: () => 'synthetic-uuid'}, fetch: async (url, options) => { calls.push({url, options}); const result = await handler(url, options); return {ok: result.status < 400, status: result.status, json: async () => result.data}; }});
  vm.runInContext(readFileSync(new URL('./file-intake.js',import.meta.url),'utf8'),context);
  vm.runInContext(source,context);
  const fire = async (id, name = 'click') => { el(id).listeners[name]({preventDefault() {}, submitter: el(id + '-submit'), currentTarget: el(id)}); await tick(); };
  const login = async () => { el('token').value = 'synthetic-access-token-at-least-32-characters'; await fire('login-form', 'submit'); };
  return {el, fire, login, calls};
}
const standard = async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.includes('?') ? {items: [caseValue()], total: 1} : caseValue()});

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
  assert.equal(ui.el('jev-results').children.length, 2);
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
  const ui = setup(async url => url.endsWith('/case-1') ? await new Promise(resolve => { release = resolve; }) : standard(url));
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
    url.includes('?') ? {items: [feedback], total: 1} : feedback}));
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
  const ui = setup(async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.includes('?') ? {items: [first, second], total: 2} : url.endsWith('/case-2') ? second : first}));
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
    : {status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.includes('?') ? {items: [feedback], total: 1} : feedback});
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
