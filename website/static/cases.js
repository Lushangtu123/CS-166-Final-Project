'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const labels = {pending: 'Pending', in_progress: 'In progress', closed: 'Closed'};
  let token = '', epoch = 0, listEpoch = 0, detailEpoch = 0, offset = 0, selected = null;
  let creation = null, inputVersion = 0, total = 0;
  let jevAvailable = false, jevTurn = 0;
  const PAGE_SIZE = 25;
  function notice(text = '', error = false) { $('notice').textContent = text; $('notice').dataset.error = String(error); }
  function node(tag, text, className) {
    const el = document.createElement(tag); el.textContent = text;
    if (className) el.className = className;
    return el;
  }
  function riskBadge(risk) {
    const known = ['critical', 'high', 'medium', 'low', 'safe', 'unknown'];
    const level = known.includes(risk) ? risk : 'unknown';
    return node('span', level.toUpperCase(), 'badge risk-' + level);
  }
  function syncSelection() {
    for (const row of $('case-list').children) {
      if (row.dataset.caseId) row.setAttribute('aria-pressed', String(row.dataset.caseId === selected?.id));
    }
  }
  function signOut() {
    jevAvailable = false; clearJev();
    window.PhishGuardVision?.cancel();
    $('vision-progress').textContent = '';
    $('case-file-status').textContent = '';
    $('visual-evidence').replaceChildren(); $('visual-evidence').hidden = true;
    token = ''; epoch++; listEpoch++; detailEpoch++; selected = null; creation = null;
    $('token').value = ''; $('workspace').hidden = true; $('session').hidden = true; $('login-panel').hidden = false;
    $('case-list').replaceChildren(); $('history').replaceChildren(); $('evidence').replaceChildren();
    for (const id of ['actor', 'source', 'analysis-json', 'case-title', 'case-meta', 'analysis-summary', 'source-note', 'count', 'page']) $(id).textContent = '';
    $('badges').replaceChildren(); $('detail').hidden = true; $('empty-detail').hidden = false;
    $('create-form').reset(); $('review-form').reset(); $('subject').disabled = $('body').disabled = false; notice();
  }
  async function api(path, options = {}) {
    const current = epoch;
    // Preserve same-origin deployment access cookies; the API still requires the analyst bearer token.
    const response = await fetch('/api/cases' + path, {...options, cache: 'no-store', credentials: 'same-origin',
      headers: {'Authorization': 'Bearer ' + token, ...options.headers}});
    if (current !== epoch) throw new Error('Session changed');
    const data = await response.json();
    if (current !== epoch) throw new Error('Session changed');
    if (!response.ok) {
      if (response.status === 401) signOut();
      const message = typeof data.detail === 'string' ? data.detail : 'Check the input fields and try again.';
      const error = new Error(message); error.status = response.status; throw error;
    }
    return data;
  }
  async function action(button, work) {
    const current = epoch; button.disabled = true;
    try { await work(); }
    catch (error) { if (current === epoch || error.status === 401) notice(error.message || 'Request failed. Reload to check whether your last operation completed.', true); }
    finally { button.disabled = false; $('previous').disabled = offset === 0; $('next').disabled = offset + PAGE_SIZE >= total; }
  }
  async function loadList() {
    const turn = ++listEpoch;
    const params = new URLSearchParams({limit: PAGE_SIZE, offset});
    for (const [id, key] of [['filter-status', 'status'], ['filter-risk', 'risk'], ['filter-from', 'created_from'], ['filter-to', 'created_to']]) {
      if ($(id).value) params.set(key, $(id).value);
    }
    const data = await api('?' + params);
    if (turn !== listEpoch) return;
    total = data.total;
    $('case-list').replaceChildren(); $('count').textContent = `${data.total} matching cases`;
    if (!data.items.length) $('case-list').append(node('p', 'No cases match these filters.'));
    for (const item of data.items) {
      const button = node('button', '', 'case-row'); button.type = 'button';
      button.setAttribute('aria-pressed', String(item.id === selected?.id));
      button.dataset.caseId = item.id;
      const heading = node('span', '', 'row-heading');
      heading.append(riskBadge(item.risk), node('span', labels[item.status], 'row-status'));
      const footer = node('span', '', 'row-footer');
      footer.append(node('span', item.verdict || 'Not reviewed'), node('span', new Date(item.created_at).toLocaleString(), 'row-date'));
      button.append(heading, node('strong', item.title), footer);
      button.addEventListener('click', () => action(button, () => loadCase(item.id)));
      $('case-list').append(button);
    }
    syncSelection();
    $('page').textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
    $('previous').disabled = offset === 0; $('next').disabled = offset + PAGE_SIZE >= data.total;
  }
  function renderCase(value) {
    clearJev();
    selected = value; syncSelection(); $('detail').hidden = false; $('empty-detail').hidden = true;
    $('case-title').textContent = value.title;
    $('case-meta').textContent = `${value.id} · Revision ${value.version} · Created by ${value.created_by}`;
    $('badges').replaceChildren(riskBadge(value.risk), ...[labels[value.status], value.verdict || 'Not reviewed'].map(text => node('span', text, 'badge')));
    const analysis = value.analysis;
    window.PhishGuardVision?.render($('visual-evidence'), analysis.visual_analysis);
    $('analysis-summary').textContent = `${analysis.risk_label || value.risk}. ${analysis.analysis_complete === false ? 'Analysis is incomplete; inspect the warnings before deciding.' : 'Review the evidence before making a decision.'}`;
    $('evidence').replaceChildren();
    for (const evidence of [...(analysis.analysis_warnings || []), ...(analysis.extra_indicators || [])]) {
      $('evidence').append(node('li', typeof evidence === 'string' ? evidence : (evidence.msg || evidence.message || JSON.stringify(evidence))));
    }
    for (const category of analysis.category_results || []) {
      if (category.count > 0) $('evidence').append(node('li', `${category.label}: ${category.description} Matched: ${(category.matched || []).join(', ')}`));
    }
    $('analysis-json').textContent = JSON.stringify({analysis, provenance: value.provenance, input_sha256: value.input_sha256}, null, 2);
    $('source').textContent = `${value.source.subject}\n\n${value.source.body}`;
    $('source-note').textContent = value.source.text_truncated ? 'Saved text was truncated. See analysis warnings for other coverage limitations.' : 'Message text is displayed without rendering HTML or loading external content.';
    const transitions = {pending: ['pending', 'in_progress'], in_progress: ['in_progress', 'closed'], closed: ['in_progress']};
    $('review-status').replaceChildren(...transitions[value.status].map(status => { const option = node('option', labels[status]); option.value = status; return option; }));
    $('verdict').value = value.verdict || ''; $('note').value = '';
    $('history').replaceChildren(...value.events.map(event => {
      const li = node('li', '');
      li.append(node('strong', `${event.actor} · ${event.action}`), node('p', new Date(event.happened_at).toLocaleString(), 'muted'));
      for (const [key, change] of Object.entries(event.changes)) li.append(node('p', `${key}: ${change.from ?? '—'} → ${change.to ?? '—'}`));
      if (event.note) li.append(node('p', event.note));
      return li;
    }));
  }
  async function loadCase(id) {
    const turn = ++detailEpoch;
    const value = await api('/' + encodeURIComponent(id));
    if (turn !== detailEpoch) return;
    renderCase(value); notice();
  }
  $('login-form').addEventListener('submit', event => {
    event.preventDefault(); const button = event.submitter;
    token = $('token').value.trim(); epoch++;
    action(button, async () => {
      const me = await api('/me'); $('token').value = ''; $('actor').textContent = me.actor;
      jevAvailable = me.jev_available === true;
      $('login-panel').hidden = true; $('session').hidden = false; $('workspace').hidden = false;
      notice(); await loadList();
    });
  });
  $('logout').addEventListener('click', signOut);
  function clearJev() {
    jevTurn++; $('jev-panel').hidden = !jevAvailable;
    $('jev-consent').checked = false; $('jev-status').textContent = '';
    $('jev-results').replaceChildren(); $('jev-run').disabled = false;
  }
  $('jev-run').addEventListener('click', async () => {
    if (!selected || !jevAvailable) return;
    if (!$('jev-consent').checked) { $('jev-status').textContent = 'Confirm permission to send this message first.'; return; }
    const turn = ++jevTurn, session = epoch, id = selected.id, version = selected.version;
    $('jev-run').disabled = true; $('jev-results').replaceChildren(); $('jev-status').textContent = 'Requesting auxiliary opinion…';
    try {
      const result = await api('/' + encodeURIComponent(id) + '/auxiliary', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({allow_external_processing: true})});
      if (turn !== jevTurn || session !== epoch || selected?.id !== id) return;
      if (result.case_id !== id || result.case_version !== version) {
        $('jev-status').textContent = 'The case changed. Reload it before requesting another opinion.'; return;
      }
      if (result.status !== 'available') {
        const reasons = {
          provider_authentication: 'TypeSafe rejected the API key. Ask the administrator to check the deployment key.',
          provider_access_denied: 'TypeSafe denied access. Ask the administrator to check account and model access.',
          provider_request_invalid: 'TypeSafe rejected the request format. Contact the administrator.',
          provider_rate_limited: 'TypeSafe rate limit reached. Wait before making another request.',
          provider_overloaded: 'TypeSafe is temporarily overloaded.',
          provider_timeout: 'TypeSafe timed out. No automatic retry was made.',
          provider_tls_error: 'The secure connection to TypeSafe could not be verified. Contact the administrator.',
          provider_network_error: 'The server could not connect to TypeSafe.',
          provider_http_error: 'TypeSafe returned a service error. Contact the administrator.',
          provider_invalid_response: 'TypeSafe returned an unexpected response. Contact the administrator.',
          local_capacity_exhausted: 'Auxiliary analysis is busy. Wait for current requests to finish.',
          call_budget_exhausted: 'The auxiliary request allowance for this server has been reached.'
        };
        const message = Object.hasOwn(reasons, result.reason) ? reasons[result.reason] : 'Auxiliary analysis was unavailable or skipped.';
        $('jev-status').textContent = message + ' The original detection result is unchanged.'; return;
      }
      $('jev-status').textContent = `${result.model} · Model opinions, not verified findings. Risk and verdict are unchanged.${result.evidence_incomplete ? ' Original evidence is incomplete; this opinion cannot fill missing images or correct OCR.' : ''}`;
      const names = {credential_request: 'Request for authentication secrets', payment_redirection: 'New or changed payment destination', authority_pressure: 'Pressure to bypass normal checks', phishing_intent: 'Deceptive intent', insufficient_evidence: 'Insufficient evidence'};
      for (const [key, label] of Object.entries(names)) {
        const probability = result.probabilities?.[key];
        if (typeof probability === 'number' && Number.isFinite(probability) && probability >= 0 && probability <= 1) {
          $('jev-results').append(node('li', `${label}: ${(probability * 100).toFixed(1)}% estimated probability. This is not a severity score.`));
        }
      }
    } catch (error) {
      if (turn === jevTurn && session === epoch) $('jev-status').textContent = error.message || 'Auxiliary analysis failed. The original detection result is unchanged.';
    } finally {
      if (turn === jevTurn) { $('jev-run').disabled = false; $('jev-consent').checked = false; }
    }
  });
  window.addEventListener('pagehide', signOut);
  $('create-form').addEventListener('input', () => { creation = null; inputVersion++; window.PhishGuardVision?.cancel(); $('vision-progress').textContent = ''; });
  $('case-ocr-language').addEventListener('change', () => { creation = null; inputVersion++; window.PhishGuardVision?.cancel(); $('vision-progress').textContent = ''; });
  $('eml').addEventListener('change', () => {
    creation = null; inputVersion++; window.PhishGuardVision?.cancel();
    const file = $('eml').files[0]; $('subject').disabled = $('body').disabled = Boolean(file);
    $('vision-progress').textContent = '';
    $('case-file-status').textContent = file ? `${file.name} loaded. Click Analyze & create case to continue. Manual fields are ignored.` : '';
  });
  window.PhishGuardFiles?.bind({zone: $('case-file-dropzone'), input: $('eml'),
    enabled: () => Boolean(token) && !$('workspace').hidden,
    onError: message => notice(message, true)});
  $('cancel-vision').addEventListener('click', () => { inputVersion++; creation = null; window.PhishGuardVision?.cancel(); $('vision-progress').textContent = ''; });
  $('create-form').addEventListener('submit', event => {
    event.preventDefault(); const current = epoch;
    action(event.submitter, async () => {
      if (!creation) {
        const snapshot = inputVersion, file = $('eml').files[0];
        if (file && (!file.size || file.size > 2 * 1024 * 1024)) throw new Error('Choose a nonempty email or image file up to 2 MiB.');
        if (file && !window.PhishGuardVision) throw new Error('Image recognition is unavailable. Reload the page.');
        const payload = file ? await window.PhishGuardVision.recognize(file, message => {
          if (current === epoch && snapshot === inputVersion) $('vision-progress').textContent = message;
        }, $('case-ocr-language').value || 'eng') : {subject: $('subject').value, body: $('body').value};
        const body = JSON.stringify(payload);
        if (current !== epoch) return;
        if (snapshot !== inputVersion) throw new Error('Input changed while reading the file. Submit again.');
        creation = {key: crypto.randomUUID(), body, file: Boolean(file)};
      }
      const submitted = creation;
      const value = await api(submitted.file ? '/visual' : '', {method: 'POST', headers: {'Content-Type': 'application/json', 'Idempotency-Key': submitted.key}, body: submitted.body});
      // Do not clear input edited while this submission was in flight.
      if (creation === submitted) { creation = null; $('create-form').reset(); $('subject').disabled = $('body').disabled = false; $('case-file-status').textContent = ''; }
      $('vision-progress').textContent = '';
      detailEpoch++; renderCase(value); notice('Case saved.'); await loadList();
    });
  });
  $('review-form').addEventListener('submit', event => {
    event.preventDefault(); if (!selected) return;
    const id = selected.id, version = selected.version, turn = detailEpoch;
    const payload = {expected_version: version, status: $('review-status').value, verdict: $('verdict').value || null, note: $('note').value};
    action(event.submitter, async () => {
      try {
        const value = await api('/' + encodeURIComponent(id), {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
        if (turn === detailEpoch) { renderCase(value); notice('Review saved.'); }
        await loadList();
      } catch (error) {
        if (error.status === 409) throw new Error('Another analyst changed this case. Your note is still here. Copy it, reload the case, then review the latest version before saving.');
        throw error;
      }
    });
  });
  $('filters').addEventListener('submit', event => { event.preventDefault(); offset = 0; action(event.submitter, loadList); });
  $('refresh').addEventListener('click', event => action(event.currentTarget, loadList));
  $('reload-case').addEventListener('click', event => { if (selected) action(event.currentTarget, () => loadCase(selected.id)); });
  for (const [id, delta] of [['previous', -PAGE_SIZE], ['next', PAGE_SIZE]]) $(id).addEventListener('click', async event => {
    const button = event.currentTarget; offset = Math.max(0, offset + delta);
    await action(button, loadList);
    // loadList owns pagination availability, including the last page.
    if (token) button.disabled = id === 'previous' ? offset === 0 : button.disabled;
  });
})();
