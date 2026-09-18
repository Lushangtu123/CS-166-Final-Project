import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

class FakeElement {
  constructor() {
    const classes = new Set();
    this.className = '';
    this.innerHTML = '';
    this.style = {};
    this.textContent = '';
    this.value = '';
    this.listeners = {};
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, force) => {
        if (force === true) return classes.add(name);
        if (force === false) return classes.delete(name);
        return classes.has(name) ? classes.delete(name) : classes.add(name);
      },
      contains: name => classes.has(name),
    };
  }

  scrollIntoView() {}
  querySelector() { return null; }
  appendChild() {}
  focus() {}
  addEventListener(event, callback) { this.listeners[event] = callback; }
}

function loadFrontend(overrides = {}) {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById,
    querySelector: () => new FakeElement(),
    querySelectorAll: () => [],
  };
  const window = { addEventListener() {}, scrollY: 0 };
  const context = vm.createContext({ document, window, console, setTimeout: fn => fn(), ...overrides });
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  vm.runInContext(source, context);
  return { context, elements };
}

test('a pending score animation cannot overwrite a newer zero score', () => {
  let frames = [];
  const { context } = loadFrontend({
    performance: { now: () => 0 },
    requestAnimationFrame: fn => frames.push(fn),
  });
  const number = new FakeElement();
  context.animateNumber(number, 100, value => `${Math.round(value)}/100`);
  context.animateNumber(number, 0, value => `${Math.round(value)}/100`);
  frames.splice(0).forEach(fn => fn(2000));
  assert.equal(number.textContent, '0/100');
});

test('content summary handles zero, singular, and plural categories', () => {
  const { context, elements } = loadFrontend();
  const makeCategory = () => ({
    level: 'high',
    icon: '!',
    label: 'Urgency',
    count: 1,
    description: 'Urgent language',
    matched: ['urgent'],
  });
  const render = categoryResults => context.renderContentResult({
    risk_level: 'high',
    risk_label: 'High risk',
    total_score: 10,
    category_results: categoryResults,
    extra_indicators: [],
    safety_signals: [],
  });

  render([]);
  assert.match(elements.get('crb-sub').textContent, /risk detected/i);

  render([makeCategory()]);
  assert.equal(elements.get('crb-sub').textContent, '1 suspicious category detected.');

  render([makeCategory(), makeCategory()]);
  assert.equal(elements.get('crb-sub').textContent, '2 suspicious categories detected.');
});

test('DNS timeout remains unverifiable rather than an invalid mailbox', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: false,
    overall: 'unverifiable', verification_complete: false, smtp_message: 'DNS lookup timed out.'});
  assert.match(elements.get('vstep-mx').className, /vstep-warn/);
  assert.match(elements.get('verify-verdict').innerHTML, /Unverifiable/);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /Likely Invalid|records are real/i);
});

test('incomplete analysis is not displayed as zero risk and cancels old animation', () => {
  const frames = [];
  const { context, elements } = loadFrontend({
    performance: { now: () => 0 }, requestAnimationFrame: fn => frames.push(fn),
  });
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [] };
  context.renderContentResult({ ...data, risk_level: 'high', risk_label: 'High', combined_phishing_score: 55 });
  context.renderContentResult({ ...data, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null });
  frames.splice(0).forEach(fn => fn(2000));
  assert.equal(elements.get('crb-score').textContent, '—');
  assert.match(elements.get('crb-sub').textContent, /incomplete/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /risk detected|no indicators detected/i);
  context.renderContentResult({ ...data, risk_level: 'high', risk_label: 'High',
    analysis_complete: false, combined_phishing_score: 55 });
  assert.equal(elements.get('crb-title').textContent, 'High');
  assert.match(elements.get('crb-sub').textContent, /incomplete/i);
});

const senderResult = email => ({
  email, verdict: 'low', label: 'Low Sender Risk', risk_score: 0,
  risk_indicators: [], feature_breakdown: [], high_risk_count: 0, med_risk_count: 0,
});
const contentResult = label => ({
  risk_level: 'safe', risk_label: label, total_score: 0,
  category_results: [], extra_indicators: [], safety_signals: [],
});
const response = data => ({ ok: true, json: async () => data });
const emlBytes = text => new TextEncoder().encode(text).buffer;
function deferredFetch() {
  const pending = [];
  return { pending, fetch: () => new Promise(resolve => pending.push(resolve)) };
}

test('late sender response cannot replace the latest result or undo clearing', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  const input = context.document.getElementById('email-input');
  input.value = 'first@gmail.com';
  const first = context.runEmailAnalysis();
  input.value = 'second@outlook.com';
  const second = context.runEmailAnalysis();
  network.pending[1](response(senderResult(input.value)));
  await second;
  network.pending[0](response(senderResult('first@gmail.com')));
  await first;
  assert.equal(elements.get('vb-email').textContent, 'second@outlook.com');
  const third = context.runEmailAnalysis();
  context.clearEmail();
  network.pending[2](response(senderResult('second@outlook.com')));
  await third;
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('late verification cannot render for another sender', async () => {
  const network = deferredFetch();
  const { context } = loadFrontend({ fetch: network.fetch });
  context.applyPublicConfig({ email_verification_enabled: true });
  context.renderResult(senderResult('first@gmail.com'));
  let rendered = false;
  context.renderVerifyResult = () => { rendered = true; };
  const pending = context.runVerification();
  context.renderResult(senderResult('second@outlook.com'));
  network.pending[0](response({ email: 'first@gmail.com', format_valid: true }));
  await pending;
  assert.equal(rendered, false);
});

test('verification HTTP failures show actionable errors, not a mailbox verdict', async () => {
  for (const [status, expected] of [[429, /37 seconds/i], [503, /unavailable/i], [404, /unavailable/i]]) {
    const { context, elements } = loadFrontend({ fetch: async () => ({
      ok: false, status, headers: { get: () => '37' },
      json: async () => ({ detail: 'Request rejected' }),
    }) });
    context.applyPublicConfig({ email_verification_enabled: true });
    context.renderResult(senderResult('user@gmail.com'));
    await context.runVerification();
    assert.match(elements.get('verify-error')?.textContent || '', expected);
    assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
    assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  }
});

test('non-address input is rejected before calling the sender API', async () => {
  let calls = 0;
  const { context, elements } = loadFrontend({ fetch: async () => { calls++; return response(senderResult('hello')); } });
  context.document.getElementById('email-input').value = 'hello';
  await context.runEmailAnalysis();
  assert.equal(calls, 0);
  assert.match(elements.get('email-error').textContent, /email address/i);
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('structural evidence is included when no keyword category matches', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ ...contentResult('High Risk'), risk_level: 'high',
    extra_indicators: [{ level: 'high', msg: 'IP address link' }, { level: 'info', msg: 'Provider context' }],
  });
  assert.match(elements.get('crb-sub').textContent, /1 technical risk indicator/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /no suspicious patterns/i);
});

test('content requests ignore stale results and results arriving after clear', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  context.document.getElementById('content-subject').value = 'First';
  const first = context.runContentAnalysis();
  context.document.getElementById('content-subject').value = 'Second';
  const second = context.runContentAnalysis();
  network.pending[1](response(contentResult('Second result')));
  await second;
  network.pending[0](response(contentResult('First result')));
  await first;
  assert.equal(elements.get('crb-title').textContent, 'Second result');
  const third = context.runContentAnalysis();
  context.clearContent();
  network.pending[2](response(contentResult('Third result')));
  await third;
  assert.equal(elements.get('content-result-area').classList.contains('hidden'), true);
});

test('choosing a content example clears the file, status and pending file read', async () => {
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  const fileInput = elements.get('raw-email-file');
  fileInput.value = 'previous.eml';
  let finishRead;
  const read = fileInput.listeners.change({ target: { files: [{name: 'previous.eml', arrayBuffer: () => new Promise(resolve => { finishRead = resolve; })}] } });
  context.runContentAnalysis = () => {};
  context.setContentExample('legit-newsletter');
  finishRead(emlBytes('From: old@example.com\n\nOld message'));
  await read;
  assert.equal(fileInput.value, '');
  assert.equal(elements.get('raw-email-status').textContent, '');
  assert.equal(vm.runInContext('_rawEmailSource', context), '');
});

test('editing the sender input invalidates an in-flight verification', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  context.setupInputEvents();
  context.applyPublicConfig({ email_verification_enabled: true });
  context.renderResult(senderResult('first@gmail.com'));
  let rendered = false;
  context.renderVerifyResult = () => { rendered = true; };
  const pending = context.runVerification();
  elements.get('email-input').value = 'second@outlook.com';
  elements.get('email-input').listeners.input();
  network.pending[0](response({ format_valid: true }));
  await pending;
  assert.equal(rendered, false);
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('content analysis waits for file reading and clearing prevents a late read', async () => {
  let calls = 0;
  const { context, elements } = loadFrontend({ fetch: async () => { calls++; return response(contentResult('Result')); } });
  context.setupInputEvents();
  elements.get('content-subject').value = 'Note';
  let finishRead;
  const read = elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'email.eml', arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }),
  }] } });
  await context.runContentAnalysis();
  assert.equal(calls, 0);
  assert.match(elements.get('content-error').textContent, /finish loading/i);
  context.clearContent();
  finishRead(emlBytes('From: test@example.com\n\nHello'));
  await read;
  assert.equal(vm.runInContext('_rawEmailSource', context), '');
  assert.equal(elements.get('raw-email-status').textContent, '');
});

test('upload mode excludes manual fields and restores editing when cleared', async () => {
  let submitted;
  const { context, elements } = loadFrontend({ fetch: async (_url, options) => {
    submitted = _url === '/api/analyze-eml' ? options.body : JSON.parse(options.body);
    return response(contentResult('File result'));
  } });
  context.setupInputEvents();
  elements.get('content-subject').value = 'Old subject';
  elements.get('content-body').value = 'Old body';
  const raw = emlBytes('From: alice@gmail.com\nSubject: File\n\nActual body');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'message.eml', arrayBuffer: async () => raw,
  }] } });
  assert.equal(elements.get('content-body').disabled, true);
  assert.equal(elements.get('content-subject').disabled, true);
  assert.match(elements.get('raw-email-status').textContent, /manual.*ignored/i);
  await context.runContentAnalysis();
  assert.deepEqual(new Uint8Array(submitted), new Uint8Array(raw));
  context.clearRawEmail();
  assert.equal(elements.get('content-body').disabled, false);
  assert.equal(elements.get('content-subject').disabled, false);
  await context.runContentAnalysis();
  assert.equal(submitted.body, 'Old body');
});

test('an empty upload restores manual editing and reports an input error', async () => {
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'empty.eml', arrayBuffer: async () => emlBytes('   '),
  }] } });
  assert.equal(elements.get('content-body').disabled, false);
  assert.match(elements.get('content-error').textContent, /empty/i);
  assert.equal(elements.get('raw-email-status').textContent, '');
});

test('uploaded non-UTF8 bytes reach the binary endpoint unchanged', async () => {
  let submitted;
  const { context, elements } = loadFrontend({ fetch: async (url, options) => {
    submitted = { url, ...options };
    return response(contentResult('File result'));
  } });
  context.setupInputEvents();
  const bytes = new Uint8Array([72, 233, 98, 101]);
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'latin1.eml', size: bytes.length,
    arrayBuffer: async () => bytes.buffer,
    text: async () => { throw new Error('Must not decode original bytes'); },
  }] } });
  await context.runContentAnalysis();
  assert.equal(submitted?.url, '/api/analyze-eml');
  assert.equal(submitted.headers['Content-Type'], 'message/rfc822');
  assert.deepEqual(new Uint8Array(submitted.body), bytes);
});

test('oversized email is rejected before reading and restores manual input', async () => {
  let read = false;
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'large.eml', size: 60001, arrayBuffer: async () => { read = true; return new ArrayBuffer(60001); },
  }] } });
  assert.equal(read, false);
  assert.equal(elements.get('content-body').disabled, false);
  assert.match(elements.get('content-error').textContent, /60,000-byte limit/);
});

test('network and unreadable service responses remain request errors', async () => {
  for (const fetch of [async () => { throw new Error('offline'); },
    async () => ({ok:true,json:async()=>{throw new Error('invalid JSON');}})]) {
    const { context, elements } = loadFrontend({ fetch });
    context.applyPublicConfig({ email_verification_enabled: true });
    context.renderResult(senderResult('user@gmail.com'));
    await context.runVerification();
    assert.match(elements.get('verify-error').textContent, /service/i);
    assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
  }
});

test('public configuration replaces verification controls with a local-only notice', () => {
  const { context, elements } = loadFrontend();

  assert.equal(typeof context.applyPublicConfig, 'function');
  context.applyPublicConfig({ email_verification_enabled: false, deployment_profile: 'production' });

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
  assert.match(elements.get('verification-local-notice').textContent, /your own computer/i);
});

test('local disabled configuration stays accurate after rendering a result', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({ email_verification_enabled: false, deployment_profile: 'development' });
  context.resetVerifyCard();
  assert.match(elements.get('verification-local-notice').textContent, /disabled in this local/i);
  assert.doesNotMatch(elements.get('verification-local-notice').textContent, /public service/i);
});

test('missing configuration does not claim a public deployment', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({});
  assert.match(elements.get('verification-local-notice').textContent, /could not be confirmed/i);
  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
});

test('enabling verification only exposes the idle controls', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({ email_verification_enabled: true, deployment_profile: 'development' });
  assert.equal(elements.get('verification-local-notice').textContent, '');
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), true);
  assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  assert.equal(elements.get('verify-loading').classList.contains('hidden'), true);
  assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
});

test('disposable status and low sender score have distinct neutral presentation', () => {
  const { context, elements } = loadFrontend();
  const result = {
    email: 'user@mailinator.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 0, risk_indicators: [{ level: 'info', msg: 'Known disposable-email provider' }], high_risk_count: 0, med_risk_count: 0,
    phish_feature_count: 0, feature_breakdown: [],
    disposable_status: 'known_disposable_provider', matched_provider_domain: 'mailinator.com',
  };
  context.renderResult(result);
  assert.match(elements.get('verdict-banner').className, /banner-neutral/);
  assert.equal(elements.get('disp-check-label').textContent, 'Known disposable-email provider');
  assert.match(elements.get('vb-scope').textContent, /does not establish.*safe/i);
  assert.doesNotMatch(elements.get('risk-summary').innerHTML, /Disposable|Suspected Phishing/);
  assert.doesNotMatch(elements.get('risk-indicators-list').innerHTML, /disposable-email provider/i);
  context.renderResult({ ...result, verdict: 'critical', risk_score: 92, label: 'Critical Sender Risk' });
  assert.match(elements.get('verdict-banner').className, /banner-phish/);
  assert.equal(elements.get('vb-prob').textContent, '92/100');
});

test('resetting results does not reveal disabled verification controls', () => {
  const { context, elements } = loadFrontend();

  context.applyPublicConfig({ email_verification_enabled: false });
  context.resetVerifyCard();

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
});

test('sender analysis renders an honest heuristic risk score', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'security@paypa1-verify.example',
    verdict: 'critical',
    label: 'Critical Sender Risk',
    risk_score: 92,
    analysis_method: 'sender-domain-heuristics',
    risk_indicators: [],
    high_risk_count: 2,
    med_risk_count: 1,
    phish_feature_count: 5,
    feature_breakdown: [],
    is_disposable: false,
    is_suspected_disposable: false,
    disposable_status: 'no_known_match',
    disposable_confidence: 'unknown',
    matched_provider_domain: null,
    address_alias_type: null,
  });

  assert.equal(elements.get('vb-prob-label').textContent, 'Sender Risk Score');
  assert.equal(elements.get('vb-prob').textContent, '92/100');
  assert.equal(elements.get('disp-check-label').textContent, 'No known disposable-provider match');
  assert.doesNotMatch(elements.get('disp-check-label').textContent, /not a disposable/i);
});

test('privacy relay classification is informational', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'user@relay.firefox.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 0, risk_indicators: [], high_risk_count: 0, med_risk_count: 0,
    phish_feature_count: 0, feature_breakdown: [], is_disposable: false,
    is_suspected_disposable: false, disposable_status: 'privacy_relay',
    disposable_confidence: 'confirmed', matched_provider_domain: 'relay.firefox.com',
    address_alias_type: null,
  });

  assert.equal(elements.get('disp-check-label').textContent, 'Privacy relay / masked address');
  assert.match(elements.get('disp-check-detail').textContent, /not phishing evidence/i);
});

test('suspicious mailbox classification communicates uncertainty', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'xq7m9v2k4p8z@gmail.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 10, risk_indicators: [], high_risk_count: 0, med_risk_count: 1,
    phish_feature_count: 2, feature_breakdown: [], is_disposable: false,
    is_suspected_disposable: true, disposable_status: 'suspicious_mailbox_pattern',
    disposable_confidence: 'heuristic', matched_provider_domain: null,
    address_alias_type: null,
  });

  assert.equal(
    elements.get('disp-check-label').textContent,
    'Mailbox pattern is suspicious; lifetime unknown',
  );
  assert.match(elements.get('disp-check-detail').textContent, /cannot be confirmed/i);
});

test('disposable education copy does not claim mailbox lifetime from a domain match', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /500\+ detected/i);
  assert.doesNotMatch(html, /They require no registration and expire/i);
  assert.match(html, /does not prove that an individual mailbox expires/i);
});

test('content payload includes an uploaded raw email', () => {
  const { context } = loadFrontend();
  const payload = context.buildContentPayload('', '', 'From: sender@example.com\n\nHello');

  assert.equal(payload.raw_email, 'From: sender@example.com\n\nHello');
});

test('attacker-controlled indicator text is HTML escaped before rendering', () => {
  const { context } = loadFrontend();

  assert.equal(
    context.escapeHtml('<img src=x onerror=alert(1)>'),
    '&lt;img src=x onerror=alert(1)&gt;',
  );
});
