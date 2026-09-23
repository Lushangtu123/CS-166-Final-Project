import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';

function setup(handler, cryptoOverride = {}) {
  const items = new Map(), requests = [];
  const element = id => {
    if (!items.has(id)) {
      const classes = new Set(['hidden']);
      items.set(id, {value: '', checked: false, hidden: false, disabled: false,
        textContent: '', listeners: {}, classList: {
          add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
          contains(name) { return classes.has(name); }},
        addEventListener(name, callback) { this.listeners[name] = callback; },
        reset() {}, focus() {}, showModal() { this.open = true; },
        close() { this.open = false; this.listeners.close?.(); }});
    }
    return items.get(id);
  };
  const document = {getElementById: element, addEventListener(_name, callback) { this.ready = callback; }};
  const window = {confirm: () => true};
  let sequence = 0;
  const crypto = {subtle: webcrypto.subtle, randomUUID: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`, ...cryptoOverride};
  const context = vm.createContext({document, window, crypto, TextEncoder, Uint8Array,
    fetch: async (url, options) => { requests.push({url, options}); return handler(url, options); }});
  vm.runInContext(readFileSync(new URL('./feedback.js', import.meta.url), 'utf8'), context);
  document.ready();
  element('feedback-type').value = 'false_positive';
  const submit = async () => { await element('feedback-form').listeners.submit({preventDefault(){}}); };
  return {element, submit, requests, feedback: window.PhishGuardFeedback, window};
}
const ok = async () => ({ok:true, json: async () => ({id:'report-1'})});
const context = buildSource => ({inputMode:'content', fingerprintInput:'Private email text',
  analysis:{risk_level:'high', risk_score:78, evidence_codes:['high']}, buildSource});

test('editing a sent report cannot hide its receipt or create a second report', async () => {
  let finish;
  const ui = setup(() => new Promise(resolve => { finish = resolve; }));
  ui.feedback.set('content', context(() => ({body:'Synthetic'}))); ui.feedback.open('content');
  ui.element('feedback-note').value = 'Submitted note';
  const pending = ui.submit(); while (!finish) await new Promise(setImmediate);
  ui.element('feedback-note').value = 'Later draft'; ui.element('feedback-form').listeners.input();
  finish({ok:true, json:async()=>({id:'accepted'})}); await pending;
  assert.match(ui.element('feedback-success').textContent, /accepted/);
  assert.match(ui.element('feedback-success').textContent, /edits.*not.*sent/i);
  assert.equal(ui.element('feedback-note').value, 'Later draft');
  assert.equal(ui.element('feedback-fields').hidden, false);
  await ui.submit(); assert.equal(ui.requests.length, 1);
});

test('unknown outcome keeps the sent body and key despite edits and requires retry confirmation', async () => {
  let finish, attempts = 0;
  const ui = setup(() => ++attempts === 1 ? new Promise(resolve => { finish = resolve; })
    : {ok:true,json:async()=>({id:'accepted'})});
  ui.feedback.set('content', context(() => ({body:'Synthetic retained input'}))); ui.feedback.open('content');
  ui.element('feedback-consent').checked = true;
  const first = ui.submit(); while (!finish) await new Promise(setImmediate);
  ui.element('feedback-consent').checked = false; ui.element('feedback-form').listeners.change();
  finish({ok:false,status:503,json:async()=>({detail:'Storage unavailable'})}); await first;
  ui.window.confirm = () => false; await ui.submit(); assert.equal(ui.requests.length, 1);
  let prompt; ui.window.confirm = message => { prompt = message; return true; };
  await ui.submit();
  assert.match(prompt, /original input/i);
  assert.equal(ui.requests[0].options.body, ui.requests[1].options.body);
  assert.equal(ui.requests[0].options.headers['Idempotency-Key'], ui.requests[1].options.headers['Idempotency-Key']);
  assert.match(ui.element('feedback-success').textContent, /accepted/);
});

test('a definite validation rejection allows a corrected report with a new key', async () => {
  let attempts = 0;
  const ui = setup(async () => ++attempts === 1
    ? {ok:false,status:422,json:async()=>({detail:'Note is too long'})} : ok());
  ui.feedback.set('content', context(() => ({body:'Synthetic'}))); ui.feedback.open('content');
  ui.element('feedback-note').value = 'Rejected'; await ui.submit();
  ui.element('feedback-note').value = 'Corrected'; ui.element('feedback-form').listeners.input();
  await ui.submit();
  assert.equal(JSON.parse(ui.requests[1].options.body).note, 'Corrected');
  assert.notEqual(ui.requests[0].options.headers['Idempotency-Key'], ui.requests[1].options.headers['Idempotency-Key']);
});

test('a rate-limited retry does not forget an earlier unconfirmed submission', async () => {
  let attempts = 0;
  const ui = setup(async () => ++attempts === 1
    ? {ok:false,status:503,json:async()=>({detail:'Unconfirmed'})}
    : attempts === 2 ? {ok:false,status:429,json:async()=>({detail:'Wait before retrying'})} : ok());
  ui.feedback.set('content', context(() => ({body:'Synthetic'}))); ui.feedback.open('content');
  await ui.submit(); await ui.submit();
  ui.element('feedback-note').value = 'Later edit'; ui.element('feedback-form').listeners.input();
  await ui.submit();
  assert.equal(ui.requests.length, 3);
  assert.equal(ui.requests[2].options.body, ui.requests[0].options.body);
  assert.equal(ui.requests[2].options.headers['Idempotency-Key'], ui.requests[0].options.headers['Idempotency-Key']);
});

test('editing during hashing invalidates only unsent work', async () => {
  let finish;
  const ui = setup(ok, {subtle:{digest:()=>new Promise(resolve=>{finish=resolve;})}});
  ui.feedback.set('content', context(() => ({body:'Synthetic'}))); ui.feedback.open('content');
  const pending = ui.submit();
  ui.element('feedback-note').value = 'New draft'; ui.element('feedback-form').listeners.input();
  finish(new Uint8Array(32).buffer); await pending;
  assert.equal(ui.requests.length, 0);
  assert.equal(ui.element('feedback-submit').disabled, false);
});

test('closing during hashing prevents the old report from being sent or reused by a new dialog', async () => {
  let finishHash, reads = 0, hashes = 0;
  const ui = setup(ok, {subtle: {digest: (...args) => ++hashes === 1
    ? new Promise(resolve => { finishHash = resolve; }) : webcrypto.subtle.digest(...args)}});
  ui.feedback.set('content', context(() => { reads++; return {body:'Message A'}; }));
  ui.feedback.open('content'); ui.element('feedback-consent').checked = true;
  ui.element('feedback-note').value = 'Report A';
  const old = ui.submit();
  ui.element('feedback-cancel').listeners.click();
  ui.feedback.set('content', context(() => ({body:'Message B'})));
  ui.feedback.open('content'); ui.element('feedback-consent').checked = false;
  ui.element('feedback-note').value = 'Report B';
  finishHash(new Uint8Array(32).buffer); await old;
  assert.equal(ui.requests.length, 0); assert.equal(reads, 0);
  await ui.submit();
  const sent = JSON.parse(ui.requests[0].options.body);
  assert.equal(sent.note, 'Report B'); assert.equal(sent.source, null);
});

test('an old response cannot release a new submission or replace its retry', async () => {
  const releases = [];
  const ui = setup(() => new Promise(resolve => releases.push(resolve)));
  ui.feedback.set('content', context(() => ({body:'A'}))); ui.feedback.open('content');
  const first = ui.submit();
  while (releases.length < 1) await new Promise(setImmediate);
  ui.element('feedback-cancel').listeners.click();
  ui.feedback.open('content'); ui.element('feedback-note').value = 'New report';
  const second = ui.submit();
  while (releases.length < 2) await new Promise(setImmediate);
  releases[0]({ok:true, json:async()=>({id:'old'})}); await first;
  assert.equal(ui.element('feedback-submit').disabled, true);
  await ui.submit(); assert.equal(ui.requests.length, 2);
  releases[1]({ok:false, json:async()=>({detail:'Storage unavailable'})}); await second;
  const retry = ui.submit();
  while (releases.length < 3) await new Promise(setImmediate);
  assert.equal(ui.requests[1].options.body, ui.requests[2].options.body);
  assert.equal(ui.requests[1].options.headers['Idempotency-Key'], ui.requests[2].options.headers['Idempotency-Key']);
  assert.notEqual(ui.requests[0].options.headers['Idempotency-Key'], ui.requests[1].options.headers['Idempotency-Key']);
  releases[2]({ok:true,json:async()=>({id:'new'})}); await retry;
  assert.match(ui.element('feedback-success').textContent, /new/);
});

test('clearing another analyzer does not invalidate an active report', async () => {
  let release;
  const ui = setup(() => new Promise(resolve => { release = resolve; }));
  ui.feedback.set('content', context(() => ({body:'A'}))); ui.feedback.open('content');
  const pending = ui.submit();
  while (!release) await new Promise(setImmediate);
  ui.feedback.clear('sender');
  release({ok:true,json:async()=>({id:'accepted'})}); await pending;
  assert.match(ui.element('feedback-success').textContent, /accepted/);
});

test('default report stores only a fingerprint and bounded analysis', async () => {
  let reads = 0;
  const ui = setup(ok);
  ui.feedback.set('content', context(() => { reads++; return {body:'Private email text'}; }));
  ui.feedback.open('content'); await ui.submit();
  assert.equal(reads, 0);
  assert.equal(ui.requests.length, 1);
  const body = JSON.parse(ui.requests[0].options.body);
  assert.equal(body.source, null);
  assert.equal(body.include_source, false);
  assert.equal(body.evaluation_consent, false);
  assert.match(body.input_fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(body.note, '');
  assert.match(ui.element('feedback-success').textContent, /report-1/);
  assert.equal(ui.element('feedback-fields').hidden, true);
  assert.equal(ui.element('feedback-cancel').textContent, 'Close');
  await ui.submit();
  assert.equal(ui.requests.length, 1);
});

test('consent is required before source builder runs', async () => {
  let reads = 0;
  const ui = setup(ok);
  ui.feedback.set('sender', {inputMode:'sender', fingerprintInput:'user@example.com',
    analysis:{risk_level:'low'}, buildSource: () => { reads++; return {email:'user@example.com'}; }});
  ui.feedback.open('sender');
  assert.equal(reads, 0);
  ui.element('feedback-consent').checked = true;
  await ui.submit();
  assert.equal(reads, 1);
  const body = JSON.parse(ui.requests[0].options.body);
  assert.equal(body.source.email, 'user@example.com');
  assert.equal(body.evaluation_consent, false);
  assert.equal(ui.element('feedback-evaluation-consent-row').hidden, true);
});

test('private evaluation requires separate consent and original email input', async () => {
  const ui = setup(ok);
  ui.feedback.set('content', context(() => ({subject:'Synthetic mail', body:'Private email text'})));
  ui.feedback.open('content');
  assert.equal(ui.element('feedback-evaluation-consent').disabled, true);
  ui.element('feedback-consent').checked = true;
  ui.element('feedback-consent').listeners.change();
  assert.equal(ui.element('feedback-evaluation-consent').disabled, false);
  ui.element('feedback-evaluation-consent').checked = true;
  await ui.submit();
  const body = JSON.parse(ui.requests[0].options.body);
  assert.equal(body.include_source, true);
  assert.equal(body.evaluation_consent, true);
});

test('failed report retries the exact body and key; invalidated context cannot submit', async () => {
  let attempts = 0;
  const ui = setup(async () => ++attempts === 1
    ? {ok:false, json: async () => ({detail:'Storage unavailable'})}
    : {ok:true, json: async () => ({id:'report-2'})});
  ui.feedback.set('content', context(() => ({body:'Private email text'})));
  ui.feedback.open('content');
  ui.element('feedback-note').value = 'Please review';
  await ui.submit();
  assert.match(ui.element('feedback-error').textContent, /Storage unavailable/);
  await ui.submit();
  assert.equal(ui.requests.length, 2);
  assert.equal(ui.requests[0].options.body, ui.requests[1].options.body);
  assert.equal(ui.requests[0].options.headers['Idempotency-Key'],
               ui.requests[1].options.headers['Idempotency-Key']);
  ui.feedback.clear('content');
  ui.feedback.open('content');
  await ui.submit();
  assert.equal(ui.requests.length, 2);
});

test('oversized email and image without extracted evidence offer source-free reporting', async () => {
  const ui = setup(ok);
  const oversized = new Uint8Array(60001).buffer;
  ui.feedback.set('content', {inputMode:'eml', fingerprintInput:oversized,
    analysis:{risk_level:'unknown'}, buildSource:() => { throw new Error('Source builder must not run'); }});
  ui.feedback.open('content');
  ui.element('feedback-consent').checked = true;
  await ui.submit();
  assert.match(ui.element('feedback-error').textContent, /60 KB/);
  assert.equal(ui.requests.length, 0);

  ui.feedback.set('content', {inputMode:'image', fingerprintInput:oversized,
    analysis:{risk_level:'unknown'}, buildSource:() => ({ocr_text:'', qr_text:''})});
  ui.feedback.open('content');
  ui.element('feedback-consent').checked = true;
  await ui.submit();
  assert.match(ui.element('feedback-error').textContent, /No text or QR evidence/);
  assert.equal(ui.requests.length, 0);
  ui.feedback.set('content', context(() => ({subject:'', body:'中'.repeat(17000)})));
  ui.feedback.open('content');
  ui.element('feedback-consent').checked = true;
  await ui.submit();
  assert.match(ui.element('feedback-error').textContent, /exceeds report limits/);
  assert.equal(ui.requests.length, 0);
  ui.element('feedback-consent').checked = false;
  await ui.submit();
  assert.equal(ui.requests.length, 1);
  assert.equal(JSON.parse(ui.requests[0].options.body).source, null);
});
