/* ──────────────────────────────────────────────────────────────────────────
   app.js – PhishGuard 邮箱检测前端逻辑
   ────────────────────────────────────────────────────────────────────────── */

let metricsChart = null;
let importanceChart = null;

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
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
  const banner = document.getElementById('verdict-banner');
  banner.className = 'verdict-banner ' + (isPhishing ? 'banner-phish' : 'banner-legit');
  document.getElementById('vb-icon').textContent = isPhishing ? '⚠️' : '✅';
  document.getElementById('vb-title').textContent = data.label;
  document.getElementById('vb-email').textContent = data.email;
  document.getElementById('vb-prob').textContent = data.phishing_probability + '%';
  document.getElementById('vb-prob').style.color = isPhishing ? '#f85149' : '#3fb950';

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
  riskSummary.innerHTML = `
    <div class="risk-pills">
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
