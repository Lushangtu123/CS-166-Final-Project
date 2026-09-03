/* ──────────────────────────────────────────────────────────────────────────
   app.js – PhishGuard frontend logic
   ────────────────────────────────────────────────────────────────────────── */

let metricsChart = null;
let importanceChart = null;

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await loadPublicConfig();
  await loadMetrics();
  setupSmoothScroll();
  setupInputEvents();
});

function setupInputEvents() {
  const input = document.getElementById('email-input');
  const clearBtn = document.getElementById('btn-clear');
  input.addEventListener('input', () => {
    clearBtn.classList.toggle('visible', input.value.length > 0);
  });
}

// ── Email Authenticity Verification ──────────────────────────────────────────
let _verifyEmail = null;   // remember which email was last analyzed
let _emailVerificationEnabled = false;

function applyPublicConfig(config) {
  const enabled = config.email_verification_enabled === true;
  _emailVerificationEnabled = enabled;
  const notice = document.getElementById('verification-local-notice');
  ['verify-idle', 'verify-loading', 'verify-result'].forEach(id => {
    document.getElementById(id).classList.toggle('hidden', !enabled);
  });
  notice.classList.toggle('hidden', enabled);
  notice.textContent = enabled
    ? ''
    : 'Full email authenticity verification is disabled on this public service. Deploy the full version on your own computer to enable SMTP, DNS, and WHOIS checks.';
}

async function loadPublicConfig() {
  let config = { email_verification_enabled: false };
  try {
    const response = await fetch('/api/config');
    if (response.ok) config = await response.json();
  } catch (error) {
    console.warn('Public configuration unavailable; using safe defaults.', error);
  }
  applyPublicConfig(config);
}

function resetVerifyCard() {
  if (!_emailVerificationEnabled) {
    applyPublicConfig({ email_verification_enabled: false });
    return;
  }
  document.getElementById('verify-idle').classList.remove('hidden');
  document.getElementById('verify-loading').classList.add('hidden');
  document.getElementById('verify-result').classList.add('hidden');
}

async function runVerification() {
  const email = _verifyEmail || document.getElementById('email-input').value.trim();
  if (!email) return;

  document.getElementById('verify-idle').classList.add('hidden');
  document.getElementById('verify-loading').classList.remove('hidden');
  document.getElementById('verify-result').classList.add('hidden');

  let data;
  try {
    const res = await fetch('/api/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    data = await res.json();
  } catch (err) {
    document.getElementById('verify-loading').classList.add('hidden');
    document.getElementById('verify-idle').classList.remove('hidden');
    alert('Verification request failed: ' + err.message);
    return;
  }

  document.getElementById('verify-loading').classList.add('hidden');
  renderVerifyResult(data);
}

function renderVerifyResult(data) {
  const ICONS = {
    ok:   { icon: '✅', cls: 'vstep-ok'   },
    warn: { icon: '⚠️', cls: 'vstep-warn' },
    fail: { icon: '❌', cls: 'vstep-fail' },
    skip: { icon: '—',  cls: 'vstep-skip' },
    info: { icon: 'ℹ️', cls: 'vstep-info' },
  };

  function setStep(id, state, detail) {
    const iconEl   = document.getElementById(`vstep-${id}-icon`);
    const detailEl = document.getElementById(`vstep-${id}-detail`);
    const step     = document.getElementById(`vstep-${id}`);
    if (!iconEl) return;
    const cfg = ICONS[state] || ICONS.skip;
    iconEl.textContent   = cfg.icon;
    step.className       = 'verify-step ' + cfg.cls;
    detailEl.textContent = detail;
  }

  // ── Section A: Mailbox Existence ────────────────────────────────────────
  // Step 1 – Format
  if (data.format_valid) {
    setStep('format', 'ok', 'Address conforms to RFC 5321 format.');
  } else {
    setStep('format', 'fail', data.smtp_message || 'Invalid email format.');
    ['mx', 'smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s =>
      setStep(s, 'skip', 'Skipped.'));
    showVerifyVerdict('invalid_format');
    return;
  }

  // Step 2 – DNS / MX
  if (data.mx_found) {
    const recs = (data.mx_records || [])
      .map(r => `${r[1]} (pref ${r[0]})`).join(' · ');
    setStep('mx', 'ok', `MX records: ${recs || data.email.split('@')[1]}`);
  } else {
    setStep('mx',   'fail', data.smtp_message || 'No MX or A records found.');
    ['smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s => setStep(s, 'skip', 'Skipped.'));
    showVerifyVerdict('likely_invalid');
    return;
  }

  // Step 3 – SMTP probe
  const smtpResult = data.smtp_result || '';
  const smtpMsg    = data.smtp_message || '';
  if (smtpResult === 'exists') {
    setStep('smtp', 'ok', smtpMsg);
  } else if (smtpResult === 'does_not_exist') {
    setStep('smtp', 'fail', smtpMsg);
  } else if (smtpResult === 'temporarily_unavailable') {
    setStep('smtp', 'warn', smtpMsg);
  } else {
    setStep('smtp', 'warn',
      smtpMsg || (!data.smtp_connectable
        ? 'Port 25 appears blocked — probe skipped. Domain MX exists, mailbox unconfirmed.'
        : 'Server gave no definitive response.'));
  }

  // Step 4 – MX PTR (reverse DNS)
  const ptr = data.mx_ptr || {};
  if (ptr.found) {
    setStep('ptr', 'ok', ptr.message || `PTR: ${ptr.ptr}`);
  } else if (ptr.message && ptr.message.includes('timed out')) {
    setStep('ptr', 'skip', ptr.message);
  } else {
    setStep('ptr', 'warn',
      ptr.message || 'No PTR record — legitimate mail servers should have reverse DNS.');
  }

  // ── Section B: Email Security Policy ───────────────────────────────────
  // Step 5 – SPF
  const spf = data.spf || {};
  if (spf.found) {
    const policy = spf.policy;
    const state  = policy === 'strict'   ? 'ok'   :
                   policy === 'softfail' ? 'warn'  :
                   policy === 'open'     ? 'fail'  : 'warn';
    setStep('spf', state, spf.message || `Policy: ${policy}`);
  } else {
    setStep('spf', 'warn', spf.message || 'No SPF record found.');
  }

  // Step 6 – DMARC
  const dmarc = data.dmarc || {};
  if (dmarc.found) {
    const policy = dmarc.policy;
    const state  = policy === 'reject'     ? 'ok'   :
                   policy === 'quarantine' ? 'warn'  :
                   policy === 'none'       ? 'warn'  : 'skip';
    setStep('dmarc', state, dmarc.message || `Policy: ${policy}`);
  } else {
    setStep('dmarc', 'warn', dmarc.message || 'No DMARC record found.');
  }

  // ── Section C: Domain Intelligence ─────────────────────────────────────
  // Step 7 – Domain Age
  const age = data.domain_age || {};
  if (age.found && age.age_days !== null) {
    const d = age.age_days;
    const state = d < 30 ? 'fail' : d < 180 ? 'warn' : 'ok';
    const detail = age.message + (age.registrar ? ` · Registrar: ${age.registrar}` : '');
    setStep('age', state, detail);
  } else {
    setStep('age', 'skip', age.message || 'WHOIS data unavailable.');
  }

  showVerifyVerdict(data.overall);
}

function showVerifyVerdict(overall) {
  const VERDICTS = {
    verified:    { cls: 'vv-ok',      icon: '✅',
      text: 'Verified — This mailbox exists and can receive email.' },
    likely_invalid: { cls: 'vv-fail', icon: '❌',
      text: 'Likely Invalid — This address probably does not exist.' },
    unverifiable: { cls: 'vv-warn',   icon: '⚠️',
      text: 'Unverifiable — Domain and MX records are real, but the mail server blocked the mailbox probe (port 25 filtered or server has probe protection). The address may still be valid.' },
    suspicious:  { cls: 'vv-suspicious', icon: '🚨',
      text: 'Suspicious — Domain was registered very recently (< 30 days). Newly registered domains are a hallmark of phishing campaigns.' },
    invalid_format: { cls: 'vv-fail', icon: '❌',
      text: 'Invalid Format — This is not a valid email address.' },
    temporarily_unavailable: { cls: 'vv-warn', icon: '⚠️',
      text: 'Temporarily Unavailable — The server returned a transient error. Try again later.' },
  };
  const cfg = VERDICTS[overall] || { cls: 'vv-warn', icon: '⋯', text: 'Result inconclusive.' };
  const el  = document.getElementById('verify-verdict');
  el.className  = 'verify-verdict ' + cfg.cls;
  el.innerHTML  = `<span>${cfg.icon}</span> ${cfg.text}`;

  document.getElementById('verify-result').classList.remove('hidden');
}

// ── Demo Tab Switcher ─────────────────────────────────────────────────────────
function switchDemoTab(tabName) {
  document.querySelectorAll('.demo-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  document.getElementById('tab-' + tabName).classList.add('active');
  document.getElementById('panel-' + tabName).classList.remove('hidden');
}

// ── Quick examples ────────────────────────────────────────────────────────────
function setExample(email) {
  const input = document.getElementById('email-input');
  input.value = email;
  document.getElementById('btn-clear').classList.add('visible');
  input.focus();
  runEmailAnalysis();
}

function clearEmail() {
  const input = document.getElementById('email-input');
  input.value = '';
  document.getElementById('btn-clear').classList.remove('visible');
  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.add('hidden');
  input.focus();
}

// ── Email Analysis ────────────────────────────────────────────────────────────
async function runEmailAnalysis() {
  const email = document.getElementById('email-input').value.trim();
  if (!email) {
    shakeInput();
    return;
  }

  const btn = document.getElementById('analyze-btn');
  const btnText = document.getElementById('analyze-btn-text');
  btn.disabled = true;
  btnText.textContent = 'Analyzing…';

  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.remove('hidden');

  try {
    const res = await fetch('/api/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || '请求失败');
    }
    const data = await res.json();
    renderResult(data);
  } catch (e) {
    alert('Analysis failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Analyze';
    document.getElementById('loading-area').classList.add('hidden');
  }
}

function shakeInput() {
  const wrap = document.querySelector('.email-input-wrap');
  wrap.classList.add('shake');
  setTimeout(() => wrap.classList.remove('shake'), 500);
}

// ── Render Result ─────────────────────────────────────────────────────────────
function renderResult(data) {
  const isPhishing = data.prediction === 0;
  const area = document.getElementById('result-area');

  // Reset verify card so it shows "Run Verification" for the new email
  _verifyEmail = data.email;
  resetVerifyCard();

  // Disposable email check card — 3 states:
  //   confirmed (purple)  → is_disposable && !is_suspected_disposable
  //   suspected  (amber)  → is_disposable &&  is_suspected_disposable
  //   clean      (green)  → !is_disposable
  const dispIcon  = document.getElementById('disp-check-icon');
  const dispLabel = document.getElementById('disp-check-label');
  const dispDet   = document.getElementById('disp-check-detail');
  const dispRow   = document.getElementById('disp-check-row');
  const dispCard  = document.getElementById('disposable-check-card');
  // Remove old badge if it exists
  const oldBadge = dispCard.querySelector('.disp-confidence-badge');
  if (oldBadge) oldBadge.remove();

  const domain = (data.email || '').split('@')[1] || '';

  if (data.is_disposable && !data.is_suspected_disposable) {
    // ── Confirmed disposable ──────────────────────────────────────
    dispRow.className  = 'disp-check-row disp-is-disposable';
    dispCard.className = 'col-card disposable-check-card is-disposable';
    dispIcon.textContent  = '🗑';
    dispLabel.textContent = 'Disposable / Temporary Email';
    dispDet.textContent   = `Provider: ${data.disposable_service}  —  This inbox is anonymous, expires automatically, and is frequently used to bypass verification. Do not trust emails from this address.`;

  } else if (data.is_disposable && data.is_suspected_disposable) {
    // ── Suspected disposable (heuristic) ─────────────────────────
    dispRow.className  = 'disp-check-row disp-suspected-disposable';
    dispCard.className = 'col-card disposable-check-card suspected-disposable';
    dispIcon.textContent  = '⚠️';
    dispLabel.textContent = 'Suspected Disposable / Auto-Generated';
    dispDet.innerHTML  = `Domain <strong>${domain}</strong> is not in the known disposable provider list, but the username appears to be randomly auto-generated (high entropy, almost no vowels). This pattern is commonly used with disposable or throwaway inboxes.`;
    // Confidence badge
    const badge = document.createElement('div');
    badge.className = 'disp-confidence-badge';
    badge.textContent = 'Heuristic Detection · Not Confirmed';
    dispCard.appendChild(badge);

  } else {
    // ── Not disposable ────────────────────────────────────────────
    dispRow.className  = 'disp-check-row disp-not-disposable';
    dispCard.className = 'col-card disposable-check-card not-disposable';
    dispIcon.textContent  = '✉️';
    dispLabel.textContent = 'Not a Disposable Address';
    dispDet.textContent   = `Domain "${domain}" was not found in the disposable email database (500+ providers tracked).`;
  }

  // Verdict banner
  const isSuspect  = !!data.is_suspected_phishing;
  const banner = document.getElementById('verdict-banner');
  let bannerCls, bannerIcon, probColor;
  if (isPhishing) {
    bannerCls = 'banner-phish';   bannerIcon = '⚠️';  probColor = '#f85149';
  } else if (isSuspect) {
    bannerCls = 'banner-suspect'; bannerIcon = '🔍';  probColor = '#e8a000';
  } else {
    bannerCls = 'banner-legit';   bannerIcon = '✅';  probColor = '#3fb950';
  }
  banner.className = 'verdict-banner ' + bannerCls;
  document.getElementById('vb-icon').textContent  = bannerIcon;
  document.getElementById('vb-title').textContent = data.label;
  document.getElementById('vb-email').textContent = data.email;
  document.getElementById('vb-prob').textContent  = data.phishing_probability + '%';
  document.getElementById('vb-prob').style.color  = probColor;

  // Remove previous suspect note if any
  const oldNote = banner.querySelector('.suspect-note');
  if (oldNote) oldNote.remove();
  if (isSuspect) {
    const note = document.createElement('div');
    note.className = 'suspect-note';
    note.textContent =
      'ML model classifies this as legitimate, but heuristic analysis detected ' +
      data.high_risk_count + ' high-risk structural pattern(s) in the domain. ' +
      'Manual verification is strongly recommended.';
    banner.querySelector('.vb-left').appendChild(note);
  }

  // Probability bars
  const phishPct = data.phishing_probability;
  const legitPct = data.legitimate_probability;
  animateBar('phish-bar', phishPct);
  animateBar('legit-bar', legitPct);
  document.getElementById('phish-pct').textContent = phishPct + '%';
  document.getElementById('legit-pct').textContent = legitPct + '%';

  // Risk summary pills
  const riskSummary = document.getElementById('risk-summary');
  const h = data.high_risk_count;
  const m = data.med_risk_count;
  let dispPill = '';
  if (data.is_disposable && !data.is_suspected_disposable) {
    dispPill = `<span class="pill pill-disp">🗑 Disposable</span>`;
  } else if (data.is_disposable && data.is_suspected_disposable) {
    dispPill = `<span class="pill pill-disp-suspect">⚠️ Suspected Disposable</span>`;
  }
  const suspectPill = isSuspect
    ? `<span class="pill pill-suspect">🔍 Suspected Phishing</span>`
    : '';
  riskSummary.innerHTML = `
    <div class="risk-pills">
      ${suspectPill}
      ${dispPill}
      <span class="pill pill-high">${h} high-risk</span>
      <span class="pill pill-med">${m} medium-risk</span>
      <span class="pill pill-feat">${data.phish_feature_count} phishing features</span>
    </div>
  `;

  // Risk indicators
  const riskList = document.getElementById('risk-indicators-list');
  const countEl = document.getElementById('risk-count');
  if (data.risk_indicators && data.risk_indicators.length > 0) {
    countEl.textContent = `(${data.risk_indicators.length})`;
    riskList.innerHTML = data.risk_indicators.map(r => `
      <div class="risk-item risk-${r.level}">
        <span class="risk-dot"></span>
        <span class="risk-msg">${r.msg}</span>
      </div>
    `).join('');
  } else {
    countEl.textContent = '';
    riskList.innerHTML = '<div class="no-risk">No risk indicators found ✓</div>';
  }

  // Feature breakdown
  const fbList = document.getElementById('feature-breakdown-list');
  fbList.innerHTML = data.feature_breakdown.map(f => {
    const valClass = f.value === -1 ? 'fv-phish' : f.value === 1 ? 'fv-legit' : 'fv-sus';
    const valLabel = f.value === -1 ? '−1' : f.value === 1 ? '+1' : '0';
    const valTitle = f.value === -1 ? 'Phishing' : f.value === 1 ? 'Legit' : 'Suspicious';
    const impPct = Math.round(f.importance * 1000) / 10;
    const barWidth = Math.min(100, f.importance / 0.32 * 100);
    return `
      <div class="fb-row">
        <div class="fb-top">
          <span class="fb-label">${f.label}</span>
          <span class="fb-val ${valClass}" title="${valTitle}">${valLabel}</span>
        </div>
        <div class="fb-desc">${f.email_desc}</div>
        <div class="fb-bar-track">
          <div class="fb-bar" style="width:${barWidth}%;background:${f.value === -1 ? '#f85149' : f.value === 1 ? '#3fb950' : '#e3b341'}"></div>
        </div>
        <div class="fb-imp">${impPct}% importance</div>
      </div>
    `;
  }).join('');

  area.classList.remove('hidden');
  area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateBar(id, pct) {
  const el = document.getElementById(id);
  el.style.width = '0%';
  setTimeout(() => { el.style.width = pct + '%'; }, 50);
}

// ── Metrics Table ─────────────────────────────────────────────────────────────
async function loadMetrics() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();
    renderMetricsTable(data.metrics);
    renderMetricsChart(data.metrics);
    renderImportanceChart(data.feature_importances);
  } catch (e) {
    console.error('Failed to load metrics:', e);
  }
}

function renderMetricsTable(metrics) {
  const tbody = document.getElementById('metrics-tbody');
  const classifiers = Object.keys(metrics);
  const cols = ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC_AUC'];
  const best = {};
  cols.forEach(col => { best[col] = Math.max(...classifiers.map(c => metrics[c][col])); });

  tbody.innerHTML = classifiers.map(clf => {
    const m = metrics[clf];
    const isRF = clf === 'Random Forest';
    return `
      <tr class="${isRF ? 'row-best' : ''}">
        <td class="clf-name">${isRF ? '🏆 ' : ''}${clf}</td>
        ${cols.map(col => `<td class="${m[col] === best[col] ? 'cell-best' : ''}">${m[col].toFixed(4)}</td>`).join('')}
      </tr>
    `;
  }).join('');
}

function renderMetricsChart(metrics) {
  const ctx = document.getElementById('metricsChart').getContext('2d');
  const classifiers = Object.keys(metrics);
  const metricKeys = ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC_AUC'];
  const labels = ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC AUC'];
  const colors = [
    'rgba(99,179,237,0.85)', 'rgba(154,230,180,0.85)',
    'rgba(252,211,77,0.85)', 'rgba(252,129,74,0.85)',
  ];
  const datasets = classifiers.map((clf, i) => ({
    label: clf,
    data: metricKeys.map(k => metrics[clf][k]),
    backgroundColor: colors[i],
    borderColor: colors[i].replace('0.85', '1'),
    borderWidth: 2,
    borderRadius: 4,
  }));
  if (metricsChart) metricsChart.destroy();
  metricsChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#cbd5e0', font: { size: 11 } } },
        tooltip: { callbacks: { label: c => `${c.dataset.label}: ${c.parsed.y.toFixed(4)}` } },

      },
      scales: {
        y: { min: 0.88, max: 1.0, ticks: { color: '#a0aec0' }, grid: { color: 'rgba(255,255,255,0.06)' } },
        x: { ticks: { color: '#a0aec0' }, grid: { display: false } },
      },
    },
  });
}

function renderImportanceChart(importances) {
  const ctx = document.getElementById('importanceChart').getContext('2d');
  const top10 = importances.slice(0, 10);
  const gradient = ctx.createLinearGradient(0, 0, 400, 0);
  gradient.addColorStop(0, 'rgba(99,179,237,0.9)');
  gradient.addColorStop(1, 'rgba(154,230,180,0.6)');
  if (importanceChart) importanceChart.destroy();
  importanceChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top10.map(f => f.label),
      datasets: [{ label: 'Gini Importance', data: top10.map(f => f.importance), backgroundColor: gradient, borderRadius: 4 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: c => `Importance: ${c.parsed.x.toFixed(4)}` } },
      },
      scales: {
        x: { ticks: { color: '#a0aec0' }, grid: { color: 'rgba(255,255,255,0.06)' } },
        y: { ticks: { color: '#e2e8f0', font: { size: 11 } }, grid: { display: false } },
      },
    },
  });
}

// ── Email Content Analysis ────────────────────────────────────────────────────

const CONTENT_EXAMPLES = {
  'phishing-account': {
    subject: 'URGENT: Your P@yP@l account has been SUSPENDED!!!',
    body: `Dear valued customer,

We have detected UNAUTHORIZED ACCESS on your P@yP@l account. Your account has been SUSPENDED due to suspicious activity. Failure to act will result in PERMANENT TERMINATION and legal action.

URGENT ACTION REQUIRED: You must verify your identity within 24 hours!

Click here: http://192.168.1.1/paypal-verify-now
Click here to confirm: http://bit.ly/verify-account-now

Please enter your username, password, credit card number, date of birth, social security number, and bank account number to restore access.

DO NOT share this email. DELETE after reading. Keep this CONFIDENTIAL.

P@yP@l Security Department`,
  },
  'phishing-lottery': {
    subject: 'CONGRATULATIONS!!! You WON $5,000,000 – Claim NOW!!!',
    body: `Dear Lucky Winner,

I am Mr. James Williams, Senior Claims Agent. You have been SPECIALLY SELECTED as the winner of our international lottery draw!!! You have won FIVE MILLION DOLLARS ($5,000,000)!!!

To claim your prize you must act NOW! This offer expires in 24 hours! Kindly revert back to me immediately.

Please send your full name, date of birth, home address, bank account number, and routing number. A release fee of $200 is required via Bitcoin, gift card, or Western Union.

DO NOT tell anyone. Keep this strictly confidential. Do the needful and respond at the earliest.

God Bless You,
I am Barrister James, Esq.`,
  },
  'legit-newsletter': {
    subject: 'Your monthly digest from TechBlog – May 2026',
    body: `Hi Sarah,

Thanks for subscribing to the TechBlog monthly newsletter. Here's a roundup of what's new this month:

• The latest in AI and machine learning research
• Upcoming community events and webinars
• Product updates and release notes

We hope you find this content helpful. If you have feedback, feel free to contact us at hello@techblog.com.

You are receiving this email because you subscribed at techblog.com.
If you no longer wish to receive these emails, please click unsubscribe below or update your preferences.

Privacy Policy | Terms of Service
© 2026 TechBlog, All Rights Reserved.
Sent from TechBlog, 123 Main St, San Francisco, CA 94101`,
  },
};

function setContentExample(key) {
  const ex = CONTENT_EXAMPLES[key];
  if (!ex) return;
  document.getElementById('content-subject').value = ex.subject;
  document.getElementById('content-body').value = ex.body;
  runContentAnalysis();
}

function clearContent() {
  document.getElementById('content-subject').value = '';
  document.getElementById('content-body').value = '';
  document.getElementById('content-result-area').classList.add('hidden');
  document.getElementById('content-loading-area').classList.add('hidden');
}

async function runContentAnalysis() {
  const subject = document.getElementById('content-subject').value.trim();
  const body    = document.getElementById('content-body').value.trim();
  if (!subject && !body) {
    document.getElementById('content-body').classList.add('shake');
    setTimeout(() => document.getElementById('content-body').classList.remove('shake'), 500);
    return;
  }

  const btn = document.getElementById('content-analyze-btn');
  const btnText = document.getElementById('content-btn-text');
  btn.disabled = true;
  btnText.textContent = 'Scanning…';

  document.getElementById('content-result-area').classList.add('hidden');
  document.getElementById('content-loading-area').classList.remove('hidden');

  try {
    const res = await fetch('/api/analyze-content', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, body }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Request failed');
    }
    const data = await res.json();
    renderContentResult(data);
  } catch (e) {
    alert('Analysis failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btnText.textContent = 'Analyze Content';
    document.getElementById('content-loading-area').classList.add('hidden');
  }
}

const RISK_CONFIG = {
  safe:     { icon: '✅', color: 'safe',     scoreColor: '#3fb950' },
  low:      { icon: '🔵', color: 'low',      scoreColor: '#63b3ed' },
  medium:   { icon: '⚠️',  color: 'medium',  scoreColor: '#e3b341' },
  high:     { icon: '🔴', color: 'high',     scoreColor: '#f97316' },
  critical: { icon: '☠️',  color: 'critical', scoreColor: '#f85149' },
};

const LEVEL_ICONS = { high: '🔴', medium: '🟡', low: '🔵' };

function renderContentResult(data) {
  const cfg = RISK_CONFIG[data.risk_level] || RISK_CONFIG.medium;

  // Banner
  const banner = document.getElementById('content-risk-banner');
  banner.className = 'content-risk-banner crb-' + data.risk_level;
  document.getElementById('crb-icon').textContent  = cfg.icon;
  document.getElementById('crb-title').textContent = data.risk_label;
  // Sub-line: now combines heuristic categories with ML verdict
  const subParts = [];
  if (data.ml_label != null) {
    subParts.push(`ML: ${data.ml_label} (${data.ml_phishing_probability}% phishing)`);
  }
  const categoryCount = data.category_results.length;
  subParts.push(
    categoryCount === 0
      ? 'No suspicious patterns detected in this email.'
      : `${categoryCount} suspicious ${categoryCount === 1 ? 'category' : 'categories'} detected.`
  );
  document.getElementById('crb-sub').textContent = subParts.join(' • ');
  const scoreEl = document.getElementById('crb-score');
  // Prefer the blended ML+heuristic score when available; fall back to raw heuristic total.
  scoreEl.textContent = data.combined_phishing_score != null
    ? `${data.combined_phishing_score}%`
    : data.total_score;
  scoreEl.style.color = cfg.scoreColor;

  // ── ML Classifier Card ───────────────────────────────────────────────────
  const mlCard = document.getElementById('content-ml-card');
  if (data.ml_label != null) {
    mlCard.style.display = '';

    const phishPct = data.ml_phishing_probability;
    const legitPct = data.ml_legitimate_probability;

    document.getElementById('content-phish-bar').style.width = phishPct + '%';
    document.getElementById('content-phish-pct').textContent = phishPct + '%';
    document.getElementById('content-legit-bar').style.width = legitPct + '%';
    document.getElementById('content-legit-pct').textContent = legitPct + '%';

    const verdict = data.ml_prediction === 1 ? '🚨 Likely Phishing' : '✅ Likely Legitimate';
    document.getElementById('content-ml-sub').textContent =
      `${verdict} — model confidence ${Math.max(phishPct, legitPct).toFixed(1)}%`;

    // Hold-out evaluation metrics for the content text classifier
    const m = data.ml_metrics || {};
    document.getElementById('content-ml-metrics').innerHTML = m.Accuracy != null ? `
      <div class="ml-metric"><span class="ml-metric-k">Accuracy</span><span class="ml-metric-v">${(m.Accuracy*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">F1</span><span class="ml-metric-v">${(m.F1*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">ROC AUC</span><span class="ml-metric-v">${m.ROC_AUC.toFixed(4)}</span></div>
    ` : '';

    // Per-email token contributions (what pushed the score toward "phishing")
    const contribs = data.ml_top_contributors || [];
    const contribBox = document.getElementById('content-ml-contribs');
    if (contribs.length > 0) {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">Top tokens driving the ML score</div>` +
        `<div class="ml-contribs-list">` +
        contribs.map(c =>
          `<span class="ml-token" title="weighted contribution: ${c.contribution}">${c.term}</span>`
        ).join('') +
        `</div>`;
    } else {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">No phishing-indicative tokens found in this email.</div>`;
    }
  } else {
    mlCard.style.display = 'none';
  }

  // Category cards
  const grid = document.getElementById('content-category-grid');
  if (data.category_results.length === 0) {
    grid.innerHTML = `<div class="cat-empty">No suspicious keyword categories matched in this email.</div>`;
  } else {
    grid.innerHTML = data.category_results.map(cat => `
      <div class="cat-card cat-${cat.level}">
        <div class="cat-header">
          <span class="cat-icon">${cat.icon}</span>
          <div class="cat-title-wrap">
            <div class="cat-title">${cat.label}</div>
            <div class="cat-count">${cat.count} signal${cat.count > 1 ? 's' : ''} matched</div>
          </div>
          <span class="cat-level-badge level-${cat.level}">${cat.level}</span>
        </div>
        <div class="cat-desc">${cat.description}</div>
        <div class="cat-keywords">
          ${cat.matched.map(kw => `<span class="kw-pill">${kw}</span>`).join('')}
        </div>
      </div>
    `).join('');
  }

  // Extra technical indicators
  const extraCard = document.getElementById('content-extra-card');
  const extraList = document.getElementById('content-extra-list');
  if (data.extra_indicators.length > 0) {
    extraCard.style.display = '';
    extraList.innerHTML = data.extra_indicators.map(ind => `
      <div class="risk-item risk-${ind.level}">
        <span class="risk-dot"></span>
        <span class="risk-msg">${ind.msg}</span>
      </div>
    `).join('');
  } else {
    extraCard.style.display = 'none';
  }

  // Safety signals
  const safetyCard = document.getElementById('content-safety-card');
  const safetyList = document.getElementById('content-safety-list');
  if (data.safety_signals.length > 0) {
    safetyCard.style.display = '';
    safetyList.innerHTML = data.safety_signals.map(s => `
      <div class="safety-item">
        <span class="safety-dot">✓</span>
        <span class="safety-msg">${s}</span>
      </div>
    `).join('');
  } else {
    safetyCard.style.display = 'none';
  }

  const area = document.getElementById('content-result-area');
  area.classList.remove('hidden');
  area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Smooth Scroll & Navbar ────────────────────────────────────────────────────
function setupSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(a.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

window.addEventListener('scroll', () => {
  document.querySelector('.navbar').classList.toggle('scrolled', window.scrollY > 30);
});
