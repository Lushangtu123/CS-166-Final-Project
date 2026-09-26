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
  const window = { addEventListener() {}, scrollY: 0,
    PhishGuardVision: { cancel() {}, render() {}, async recognize(file) {
      return {eml_base64: Buffer.from(await file.arrayBuffer()).toString('base64'), observations: [], warnings: []};
    }},
  };
  const context = vm.createContext({ document, window, console, setTimeout: fn => fn(), ...overrides });
  const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
  vm.runInContext(source, context);
  return { context, elements };
}

test('feedback diagnostics retain signal identifiers without source-bearing messages', () => {
  const {context} = loadFrontend();
  const sender = context.feedbackAnalysis({verdict:'high', risk_score:70, label:'High Sender Risk',
    risk_indicators:[{level:'high', msg:'Address alice@example.test is suspicious'}],
    feature_breakdown:[{name:'known_provider', value:-1}, {name:'address_length', value:1}]}, true);
  assert.deepEqual(Array.from(sender.evidence_codes), ['known_provider']);
  assert.doesNotMatch(JSON.stringify(sender), /alice@example\.test/);
  const content = context.feedbackAnalysis({risk_level:'medium', risk_label:'Medium Risk',
    category_results:[{key:'credential_request', matched:['private phrase']}],
    extra_indicators:[{level:'high', msg:'Private destination https://example.test'}]});
  assert.deepEqual(Array.from(content.evidence_codes), ['credential_request']);
  assert.doesNotMatch(JSON.stringify(content), /private phrase|https:\/\/example\.test/);
});

test('public reporting actions follow the server availability flag', () => {
  const {context} = loadFrontend();
  const rows = [{hidden:true}, {hidden:true}];
  context.document.querySelectorAll = selector => selector === '.result-report' ? rows : [];
  context.applyPublicConfig({feedback_enabled:true});
  assert.deepEqual(rows.map(row => row.hidden), [false, false]);
  context.applyPublicConfig({feedback_enabled:false});
  assert.deepEqual(rows.map(row => row.hidden), [true, true]);
});

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

test('image-only results do not present empty email-body analysis as OCR failure', () => {
  const {context, elements} = loadFrontend();
  const result = {risk_level:'unknown', risk_label:'Analysis Incomplete — Risk Undetermined',
    total_score:0, category_results:[], extra_indicators:[], safety_signals:[],
    analysis_complete:false, ml_status:'insufficient_context', ml_label:null,
    input_mode:'image-evidence', visual_analysis:{observations:[{
      status:'processed', ocr_text:'A community newsletter with a long readable message.',
      ocr_confidence:92, ml_status:'available', ml_phishing_probability:12,
    }]}};
  context.renderContentResult(result);
  assert.equal(elements.get('content-ml-card').style.display, 'none');
  assert.equal(elements.get('content-category-grid').style.display, 'none');
  assert.doesNotMatch(elements.get('crb-sub').textContent, /text model could not score this message/);
  assert.match(elements.get('crb-sub').textContent, /Image & QR evidence/);
  assert.match(elements.get('crb-title').textContent, /[Uu]ndetermined/);
  context.renderContentResult({...result, input_mode:'manual', visual_analysis:undefined});
  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-category-grid').style.display, '');
  assert.match(elements.get('content-ml-sub').textContent, /too little text/);
});

test('Null MX explains no mail service without claiming phishing or a missing mailbox', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: false,
    null_mx: true, overall: 'no_mail_service', verification_complete: false,
    smtp_message: 'Domain publishes Null MX: it does not accept email.'});
  assert.match(elements.get('verify-verdict').innerHTML, /No Mail Service/);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /Likely Invalid|probably does not exist/);
  assert.match(elements.get('vstep-mx').className, /vstep-info/);
});

test('partial verification preserves SMTP result while showing incomplete checks', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: true,
    overall: 'verified', smtp_result: 'exists', verification_complete: false,
    domain_age: {found: false, status: 'timeout', message: 'WHOIS lookup failed.'}});
  assert.match(elements.get('verify-verdict').innerHTML, /Verification Incomplete/);
  assert.match(elements.get('verify-verdict').innerHTML, /server accepted/i);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /mailbox exists and can receive/);
  assert.match(elements.get('verify-verdict').className, /vv-warn/);
});

test('DNS timeout remains unverifiable rather than an invalid mailbox', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: false,
    overall: 'unverifiable', verification_complete: false, smtp_message: 'DNS lookup timed out.'});
  assert.match(elements.get('vstep-mx').className, /vstep-warn/);
  assert.match(elements.get('verify-verdict').innerHTML, /Unverifiable/);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /Likely Invalid|records are real/i);
});

test('lite result presents domain evidence without claiming mailbox verification', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({
    email: 'user@example.com',
    format_valid: true,
    mx_found: true,
    mx_records: [[10, 'mx.example.com']],
    smtp_result: 'unavailable',
    smtp_status: 'skipped',
    smtp_message: 'SMTP mailbox probing is unavailable on this deployment.',
    overall: 'domain_valid',
    verification_complete: false,
    domain_verification: { status: 'valid', complete: true },
    mailbox_verification: { status: 'unavailable' },
    spf: { found: true, policy: 'strict', message: 'Strict SPF.' },
    dmarc: { found: true, policy: 'reject', message: 'Reject DMARC.' },
    mx_ptr: { found: true, message: 'PTR found.' },
    domain_age: { found: true, age_days: 365, message: 'Established domain.' },
  });

  assert.match(elements.get('vstep-smtp').className, /vstep-info/);
  assert.match(elements.get('verify-verdict').innerHTML, /Domain Valid/);
  assert.match(elements.get('verify-verdict').innerHTML, /mailbox.*not verified/i);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /SMTP Accepted/);
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

test('attachment coverage is distinguished from parser and model limitations', () => {
  const { context, elements } = loadFrontend();
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null };
  context.renderContentResult({ ...data, message_structure: { attachments: [
    { filename: 'chart.png', content_type: 'image/png', inspection_status: 'metadata_only' }
  ], parse_warnings: [] } });
  assert.match(elements.get('crb-sub').textContent, /attachment contents were not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /could not be reliably parsed/i);
  assert.equal(elements.get('crb-score').textContent, '—');

  context.renderContentResult({ ...data, message_structure: {
    attachments: [], parse_warnings: ['MIME structure is malformed.']
  } });
  assert.match(elements.get('crb-sub').textContent, /could not be reliably parsed/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /attachment contents/i);

  context.renderContentResult({ ...data, ml_status: 'insufficient_context', message_structure: {
    attachments: [], parse_warnings: []
  } });
  assert.match(elements.get('crb-sub').textContent, /text model/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /could not be reliably parsed/i);

  context.renderContentResult({ ...data,
    analysis_warnings: ['Attached message: Attachment content was not inspected; only filenames and MIME types were checked.'],
    message_structure: { attachments: [
      { filename: 'forwarded.eml', content_type: 'message/rfc822', inspection_status: 'message_analyzed' }
    ], parse_warnings: [] } });
  assert.match(elements.get('crb-sub').textContent, /attachment contents were not inspected/i);
});

test('embedded image coverage has distinct incomplete-analysis wording', () => {
  const { context, elements } = loadFrontend();
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, inline_image_coverage: { count: 1, inspection_status: 'metadata_only' } };
  context.renderContentResult(data);
  assert.match(elements.get('crb-sub').textContent, /embedded image content was not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /attachment contents|reliably parsed|text model/i);
  assert.equal(elements.get('crb-score').textContent, '—');
});

test('remote image coverage explains that image content was not inspected', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, remote_image_coverage: { count: 1, inspection_status: 'metadata_only' } });
  assert.match(elements.get('crb-sub').textContent, /remote image content was not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /embedded image content was not inspected/i);
});

test('unresolved image coverage explains that referenced image content was not inspected', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, unresolved_image_coverage: { count: 1, inspection_status: 'metadata_only' } });
  assert.match(elements.get('crb-sub').textContent, /unresolved image references were not inspected/i);
});

test('model-only high result explains that independent evidence is absent', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: true, risk_level: 'high', risk_label: 'High Risk — Model Signal Needs Review',
    combined_phishing_score: 84.2, fusion_basis: 'model_only',
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 84.2,
    ml_legitimate_probability: 15.8, ml_prediction: 1, ml_top_contributors: [], ml_metrics: {} });
  assert.match(elements.get('crb-sub').textContent, /model-only.*no independent/i);
});

test('model-led high result distinguishes weak rules from strong corroboration', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 1, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: true, risk_level: 'high', risk_label: 'High Risk — Model Signal Needs Review',
    combined_phishing_score: 95.8, fusion_basis: 'model_led',
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 95.8,
    ml_legitimate_probability: 4.2, ml_prediction: 1, ml_top_contributors: [], ml_metrics: {} });
  assert.match(elements.get('crb-sub').textContent, /model-led.*no strong independent/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /combined analysis/i);
});

test('content model abstention is shown without probability bars', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_feature_coverage', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /coverage.*not applied/i);
  assert.equal(elements.get('content-phish-bar').style.width, '0%');
  assert.equal(elements.get('content-legit-bar').style.width, '0%');
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('short-message abstention explains that the text is insufficient', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_context', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /too little text.*not applied/i);
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('unverified rendering abstention is explicit and has no stale score bars', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    analysis_warnings: ['A stylesheet may hide or reveal text.'],
    ml_status: 'unverified_rendering', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /CSS visibility or image fallback.*not applied/i);
  assert.match(elements.get('crb-sub').textContent, /text model could not score/i);
  assert.match(elements.get('content-ml-contribs').innerHTML, /Uncertain HTML text was withheld/i);
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('available content model output is labelled a risk score not confidence', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'high', risk_label: 'High', analysis_complete: true,
    combined_phishing_score: 72, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'available', ml_label: 'Likely Phishing',
    ml_phishing_probability: 72, ml_legitimate_probability: 28,
    ml_prediction: 1, ml_top_contributors: [], ml_metrics: {},
  });

  assert.match(elements.get('content-ml-sub').textContent, /model risk score 72\.0%/i);
  assert.equal(elements.get('content-ml-prob-bars').style.display, '');
  assert.doesNotMatch(elements.get('content-ml-sub').textContent, /confidence/i);
  assert.match(elements.get('crb-sub').textContent, /ML risk score: 72%/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /% phishing/i);
});

test('content analysis copy does not describe model output as probability', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /group-isolated probability/i);
  assert.match(html, /group-isolated model score/i);
});

test('benchmark cells carry column labels for the stacked phone layout', () => {
  const { context, elements } = loadFrontend();
  context.renderMetricsTable({
    'Random Forest': { Accuracy: 0.97, Precision: 0.96, Recall: 0.95, F1: 0.94, ROC_AUC: 0.99 },
  });
  const html = elements.get('metrics-tbody').innerHTML;
  for (const label of ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC AUC']) {
    assert.match(html, new RegExp(`data-label="${label}"`));
  }
  assert.doesNotMatch(html, /data-label="ROC_AUC"/);
});

test('benchmark chart colours follow the active theme', () => {
  const { context } = loadFrontend();
  const config = () => ({
    data: { datasets: [{}, {}] },
    options: {
      plugins: { legend: { labels: {} }, tooltip: {} },
      scales: { y: { ticks: {}, grid: {} }, x: { ticks: {} } },
    },
  });
  const dark = config();
  context.applyChartTheme(dark);
  assert.equal(dark.data.datasets[0].backgroundColor, 'rgba(79,209,255,0.80)');

  const tokens = { '--text-muted': '#56627a', '--text': '#0f172a' };
  context.document.documentElement = { dataset: { theme: 'light' } };
  context.getComputedStyle = () => ({ getPropertyValue: name => tokens[name] || '' });
  const light = config();
  context.applyChartTheme(light);
  assert.equal(light.data.datasets[0].backgroundColor, 'rgba(10,127,214,0.80)');
  assert.equal(light.options.scales.x.ticks.color, '#56627a');
  assert.equal(light.options.plugins.tooltip.titleColor, '#0f172a');
});

test('case login stays on the stable deployment except on a local server', () => {
  const { context } = loadFrontend();
  const deployed = 'https://phishguard-email-analyzer.vercel.app/cases';
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    assert.equal(context.caseLoginHref(host, deployed), '/cases');
  }
  for (const host of ['phishguard-email-analyzer.vercel.app', 'preview-abc.vercel.app', 'localhost.example']) {
    assert.equal(context.caseLoginHref(host, deployed), deployed);
  }
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /class="case-login" href="https:\/\/phishguard-email-analyzer\.vercel\.app\/cases"/);
});

test('narrow-screen section menu is wired to the collapsible link list', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /<ul class="nav-links" id="nav-links">/);
  assert.match(html, /id="nav-menu-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="nav-links"/);
});

test('HTML page loads enabled Vercel observability scripts from this site', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /window\.va\s*=\s*window\.va\s*\|\|/);
  assert.match(html, /src="\/_vercel\/insights\/script\.js"/);
  assert.match(html, /window\.si\s*=\s*window\.si\s*\|\|/);
  assert.match(html, /src="\/_vercel\/speed-insights\/script\.js"/);
  assert.doesNotMatch(html, /@vercel\/(analytics|speed-insights)\/next/);
});

test('content input explains server processing and pseudonymous sender retention', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.match(html, /processed on this server/i);
  assert.match(html, /does not retain.*message body.*attachment content/is);
  assert.match(html, /pseudonymous sender observation/i);
  assert.match(html, /remove unrelated personal content/i);
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
  assert.deepEqual(Buffer.from(submitted.eml_base64, 'base64'), Buffer.from(raw));
  assert.equal(submitted.body, undefined);
  assert.equal(submitted.subject, undefined);
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

test('uploaded non-UTF8 bytes survive the visual endpoint base64 envelope', async () => {
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
  assert.equal(submitted?.url, '/api/analyze-visual');
  assert.equal(submitted.headers['Content-Type'], 'application/json');
  assert.deepEqual(Buffer.from(JSON.parse(submitted.body).eml_base64, 'base64'), Buffer.from(bytes));
});

test('oversized email is rejected before reading and restores manual input', async () => {
  let read = false;
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'large.eml', size: 2 * 1024 * 1024 + 1, arrayBuffer: async () => { read = true; return new ArrayBuffer(2 * 1024 * 1024 + 1); },
  }] } });
  assert.equal(read, false);
  assert.equal(elements.get('content-body').disabled, false);
  assert.match(elements.get('content-error').textContent, /2 MiB limit/);
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

test('lite verification exposes domain checks and explains unavailable SMTP', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({
    deployment_profile: 'production',
    verification_mode: 'lite',
    email_verification_enabled: true,
    domain_verification_enabled: true,
    smtp_verification_enabled: false,
  });

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
  assert.match(elements.get('verification-local-notice').textContent, /domain checks are enabled/i);
  assert.match(elements.get('verification-local-notice').textContent, /SMTP mailbox probing is unavailable/i);
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

test('sender history reports a first observation without claiming provider account age', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('new.account@gmail.com'),
    account_observability: 'provider_account_unverifiable',
    sender_history_status: 'first_seen',
    sender_history_scope: 'this_service_history',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'First observed by this service');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /observed 1 time/i);
  assert.match(elements.get('sender-history-detail').textContent, /Gmail account age cannot be verified/i);
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /new account|account created/i);
});

test('sender history distinguishes a previous observation from sender safety', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('billing@outlook.com'),
    sender_history_status: 'previously_seen',
    sender_history_scope: 'this_service_history',
    account_observability: 'provider_account_unverifiable',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Observed previously by this service');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /observed 12 times/i);
  assert.match(elements.get('sender-history-detail').textContent, /does not establish.*safe/i);
});

test('address-only analysis explains that retained history requires a raw message', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('alice@gmail.com'),
    sender_history_status: 'raw_message_required',
    sender_history_scope: 'this_service_history',
    account_observability: 'provider_account_unverifiable',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Available with full-message analysis');
  assert.match(elements.get('sender-history-detail').textContent, /does not query retained sender history/i);
});

test('unavailable sender history never renders a false zero-count claim', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('user@example.com'),
    sender_history_status: 'unavailable',
    sender_history_scope: 'this_service_history',
    account_observability: 'unknown',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Observation history unavailable');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /0 times|never seen/i);
});

test('raw-message results surface the observed sender history', () => {
  const { context, elements } = loadFrontend();

  context.renderContentResult({
    risk_level: 'low', risk_label: 'Low', analysis_complete: true,
    combined_phishing_score: 8, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_feature_coverage', ml_label: null,
    sender_analysis: {
      email: 'new.account@outlook.com',
      account_observability: 'provider_account_unverifiable',
      sender_history_status: 'first_seen',
      sender_history_scope: 'this_service_history',
    },
  });

  assert.equal(
    elements.get('content-sender-history-label').textContent,
    'First observed by this service',
  );
  assert.match(elements.get('content-sender-history-detail').textContent, /Outlook account age cannot be verified/i);
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

test('public OCR forwards language and discards recognition after the selection changes',async()=>{
  let release, selectedLanguage, posts=0;
  const {context,elements}=loadFrontend({fetch:async()=>{posts++;return response(contentResult('File result'));}});
  context.window.PhishGuardVision.recognize=async(_file,_progress,language)=>{
    selectedLanguage=language;return new Promise(resolve=>{release=resolve;});
  };
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({target:{files:[{
    name:'test.png',size:1,arrayBuffer:async()=>new Uint8Array([1]).buffer,
  }]}});
  const select=elements.get('content-ocr-language');
  assert(select,'language selector is wired');select.value='chi_sim';
  const pending=context.runContentAnalysis();
  assert.equal(selectedLanguage,'chi_sim');
  select.value='eng';select.listeners.change();
  release({observations:[],warnings:[]});await pending;
  assert.equal(posts,0);assert.equal(elements.get('content-analyze-btn').disabled,false);
});
