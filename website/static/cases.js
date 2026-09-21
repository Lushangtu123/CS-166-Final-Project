'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const labels = {pending: 'Pending', in_progress: 'In progress', closed: 'Closed'};
  let token = '', epoch = 0, listEpoch = 0, detailEpoch = 0, offset = 0, selected = null;
  let creation = null, inputVersion = 0, total = 0;
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
    token = ''; epoch++; listEpoch++; detailEpoch++; selected = null; creation = null;
    $('token').value = ''; $('workspace').hidden = true; $('session').hidden = true; $('login-panel').hidden = false;
    $('case-list').replaceChildren(); $('history').replaceChildren(); $('evidence').replaceChildren();
    for (const id of ['actor', 'source', 'analysis-json', 'case-title', 'case-meta', 'analysis-summary', 'source-note', 'count', 'page']) $(id).textContent = '';
    $('badges').replaceChildren(); $('detail').hidden = true; $('empty-detail').hidden = false;
    $('create-form').reset(); $('review-form').reset(); $('subject').disabled = $('body').disabled = false; notice();
  }
  async function api(path, options = {}) {
    const current = epoch;
    const response = await fetch('/api/cases' + path, {...options, cache: 'no-store', credentials: 'omit',
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
    selected = value; syncSelection(); $('detail').hidden = false; $('empty-detail').hidden = true;
    $('case-title').textContent = value.title;
    $('case-meta').textContent = `${value.id} · Revision ${value.version} · Created by ${value.created_by}`;
    $('badges').replaceChildren(riskBadge(value.risk), ...[labels[value.status], value.verdict || 'Not reviewed'].map(text => node('span', text, 'badge')));
    const analysis = value.analysis;
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
      $('login-panel').hidden = true; $('session').hidden = false; $('workspace').hidden = false;
      notice(); await loadList();
    });
  });
  $('logout').addEventListener('click', signOut);
  window.addEventListener('pagehide', signOut);
  $('create-form').addEventListener('input', () => { creation = null; inputVersion++; });
  $('eml').addEventListener('change', () => { creation = null; const file = $('eml').files[0]; $('subject').disabled = $('body').disabled = Boolean(file); });
  $('create-form').addEventListener('submit', event => {
    event.preventDefault(); const current = epoch;
    action(event.submitter, async () => {
      if (!creation) {
        const snapshot = inputVersion, file = $('eml').files[0];
        if (file && (!file.size || file.size > 60000)) throw new Error('Choose a nonempty .eml file up to 60,000 bytes.');
        const body = file ? await file.arrayBuffer() : JSON.stringify({subject: $('subject').value, body: $('body').value});
        if (current !== epoch) return;
        if (snapshot !== inputVersion) throw new Error('Input changed while reading the file. Submit again.');
        creation = {key: crypto.randomUUID(), body, file: Boolean(file)};
      }
      const submitted = creation;
      const value = await api(submitted.file ? '/eml' : '', {method: 'POST', headers: {'Content-Type': submitted.file ? 'message/rfc822' : 'application/json', 'Idempotency-Key': submitted.key}, body: submitted.body});
      // Do not clear input edited while this submission was in flight.
      if (creation === submitted) { creation = null; $('create-form').reset(); $('subject').disabled = $('body').disabled = false; }
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
