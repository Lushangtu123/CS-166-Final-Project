import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.dataset = {}; this.listeners = {}; this.children = []; this.files = []; this.attrs = {}; this.classList = {add(){},remove(){}}; }
  set innerHTML(_) { throw new Error('Untrusted content must never use HTML'); }
  setAttribute(key, value) { this.attrs[key] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  reset() {}
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
