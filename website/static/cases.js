'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const labels = {pending: 'Pending', in_progress: 'In progress', closed: 'Closed'};
  const transitions = {pending: ['pending', 'in_progress'], in_progress: ['in_progress', 'closed'], closed: ['in_progress']};
  const reviewFields = {status: 'review-status', verdict: 'verdict', note: 'note',
    feedback_reason: 'feedback-reason', evidence_basis: 'evidence-basis'};
  const reviewDrafts = new Map(), reviewSaves = new Map();
  const opinionSaves = new Map();
  const latestVersions = new Map();
  let reviewBaseline = null;
  let capacityTurn = 0;
  let token = '', epoch = 0, listEpoch = 0, detailEpoch = 0, offset = 0, selected = null;
  let creation = null, inputVersion = 0, total = 0;
  let jevAvailable = false, jevTurn = 0, createPending = false;
  let jevConfig = {status: 'disabled'}, jevBusy = false, jevStatusTurn = 0;
  let jevOpinion = null;
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
  function resetComposer() {
    $('create-form').reset();
    $('subject').value = ''; $('body').value = '';
    $('subject').disabled = $('body').disabled = false;
    $('case-file-status').textContent = ''; $('vision-progress').textContent = '';
  }
  function openComposer() {
    if (!token || $('workspace').hidden || $('compose-dialog').open) return;
    $('compose-dialog').showModal();
  }
  function closeComposer({reset = false, force = false} = {}) {
    if (createPending && !force) return;
    if (reset) resetComposer();
    if ($('compose-dialog').open) $('compose-dialog').close();
  }
  function syncSelection() {
    for (const row of $('case-list').children) {
      if (row.dataset.caseId) row.setAttribute('aria-pressed', String(row.dataset.caseId === selected?.id));
    }
  }
  function reviewValues() {
    return Object.fromEntries(Object.entries(reviewFields).map(([key, element]) => [key, $(element).value]));
  }
  function recordPath(id, kind) {
    return '/' + encodeURIComponent(id) + '?kind=' + (kind === 'feedback' ? 'feedback' : 'case');
  }
  function rememberVersion(value) {
    const key = recordPath(value.id, value.kind);
    if (value.version < (latestVersions.get(key) || 0)) return false;
    latestVersions.set(key, value.version);
    return true;
  }
  function reviewDefaults(value) {
    const result = {status: transitions[value.status][0], verdict: value.verdict || '', note: '', feedback_reason: '', evidence_basis: ''};
    if (value.kind === 'feedback') for (const event of value.events) {
      for (const key of ['feedback_reason', 'evidence_basis']) if (event.changes?.[key]) result[key] = event.changes[key].to || '';
    }
    return result;
  }
  function keepDraft(id, version, values, baseline) {
    if (Object.keys(reviewFields).some(key => values[key] !== baseline[key])) reviewDrafts.set(id, {version, values});
    else reviewDrafts.delete(id);
  }
  function captureDraft() {
    if (!selected || !reviewBaseline) return;
    const values = reviewValues(), version = reviewDrafts.get(selected.id)?.version ?? selected.version;
    const saving = reviewSaves.get(selected.id);
    if (saving && Object.keys(reviewFields).some(key => values[key] !== saving.submittedFields[key])) {
      reviewDrafts.set(selected.id, {version, values});
    } else keepDraft(selected.id, version, values, reviewBaseline);
  }
  function restoreReview(values) {
    for (const [key, text] of Object.entries(values)) {
      if (key === 'status' && !transitions[selected.status].includes(text)) {
        const option = node('option', `${labels[text] || text} (no longer available)`);
        option.value = text; option.disabled = true; $('review-status').append(option);
      }
      $(reviewFields[key]).value = text;
    }
  }
  function renderDraftState() {
    const draft = reviewDrafts.get(selected?.id), conflict = draft && draft.version !== selected.version;
    $('draft-status').textContent = conflict
      ? `This draft started at revision ${draft.version}. Compare the latest evidence and history before using it with revision ${selected.version}.`
      : draft ? 'Unsaved draft kept in this tab. Save it before leaving.' : '';
    $('draft-rebase').hidden = !conflict;
    $('draft-discard').hidden = !draft;
    $('draft-discard').disabled = reviewSaves.has(selected?.id);
    $('save-review').disabled = Boolean(conflict || reviewSaves.has(selected?.id) || opinionSaves.has(selected?.id));
    renderJevAvailability();
  }
  function hasUnsavedWork() {
    captureDraft();
    return reviewDrafts.size > 0 || reviewSaves.size > 0 || opinionSaves.size > 0 || createPending || Boolean($('subject').value || $('body').value || $('eml').files.length);
  }
  function signOut() {
    jevAvailable = false; jevConfig = {status: 'disabled'}; jevStatusTurn++; clearJev();
    $('jev-panel').hidden = true; $('jev-availability').textContent = '';
    window.PhishGuardVision?.cancel();
    closeComposer({reset: true, force: true});
    $('vision-progress').textContent = '';
    $('case-file-status').textContent = '';
    $('visual-evidence').replaceChildren(); $('visual-evidence').hidden = true;
    token = ''; epoch++; listEpoch++; detailEpoch++; selected = null; creation = null;
    reviewDrafts.clear(); reviewSaves.clear(); opinionSaves.clear(); reviewBaseline = null; renderDraftState();
    latestVersions.clear(); $('queue-warning').textContent = '';
    capacityTurn++;
    for (const id of ['case-capacity', 'feedback-capacity', 'capacity-warning']) $(id).textContent = '';
    $('token').value = ''; $('workspace').hidden = true; $('session').hidden = true; $('login-panel').hidden = false;
    $('case-list').replaceChildren(); $('history').replaceChildren(); $('evidence').replaceChildren();
    for (const id of ['actor', 'source', 'analysis-json', 'case-title', 'case-meta', 'analysis-summary', 'source-note', 'count', 'page']) $(id).textContent = '';
    $('badges').replaceChildren(); $('detail').hidden = true; $('empty-detail').hidden = false;
    $('review-form').reset(); notice();
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
    if ($('filter-kind').value) params.set('kind', $('filter-kind').value);
    for (const [id, key] of [['filter-status', 'status'], ['filter-risk', 'risk'], ['filter-from', 'created_from'], ['filter-to', 'created_to']]) {
      if ($(id).value) params.set(key, $(id).value);
    }
    const data = await api('?' + params);
    if (turn !== listEpoch) return;
    total = data.total;
    $('case-list').replaceChildren();
    $('count').textContent = `${data.total} ${data.partial ? 'records from available sources' : 'matching records'}`;
    $('queue-warning').textContent = data.partial
      ? Object.entries(data.sources || {}).filter(([,status]) => status === 'unavailable')
        .map(([kind]) => `${kind === 'case' ? 'Cases' : 'User feedback'} unavailable.`).join(' ') + ' Showing available records only. Refresh to retry.' : '';
    if (!data.items.length) $('case-list').append(node('p', 'No cases match these filters.'));
    for (const item of data.items) {
      const button = node('button', '', 'case-row'); button.type = 'button';
      button.setAttribute('aria-pressed', String(item.id === selected?.id));
      button.dataset.caseId = item.id;
      const risk = node('span', '', 'case-cell risk-cell'); risk.append(riskBadge(item.risk));
      const title = node('span', '', 'case-cell title-cell');
      title.append(node('strong', item.title), node('span', item.kind === 'feedback' ? 'User feedback' : 'Case', 'record-kind'));
      const status = node('span', labels[item.status], 'case-cell status-cell');
      const verdict = node('span', item.verdict || 'Not reviewed', 'case-cell verdict-cell');
      const created = node('time', new Date(item.created_at).toLocaleString(), 'case-cell date-cell');
      button.append(risk, title, status, verdict, created);
      button.addEventListener('click', () => action(button, () => loadCase(item.id, item.kind)));
      $('case-list').append(button);
    }
    syncSelection();
    $('page').textContent = `Page ${Math.floor(offset / PAGE_SIZE) + 1}`;
    $('previous').disabled = offset === 0; $('next').disabled = offset + PAGE_SIZE >= data.total;
    await refreshCapacity();
  }
  async function refreshCapacity() {
    const turn = ++capacityTurn, session = epoch;
    let data = {};
    try { data = await api('/capacity'); } catch (_) { /* Capacity is advisory; keep the queue usable. */ }
    if (turn !== capacityTurn || session !== epoch || !token) return;
    const warnings = [];
    for (const [key, id, label] of [['cases', 'case-capacity', 'Cases'], ['feedback', 'feedback-capacity', 'User feedback']]) {
      const value = data?.[key];
      let text = `${label}: capacity unavailable. Refresh to check again.`, level = 'unknown';
      if (value?.status === 'disabled') { text = `${label}: not configured.`; level = 'disabled'; }
      if (value?.status === 'available' && Number.isInteger(value.used) && value.used >= 0 &&
          (value.limit === null || Number.isInteger(value.limit) && value.limit > 0)) {
        text = value.limit === null ? `${label}: ${value.used} stored · no application count limit.`
          : `${label}: ${value.used} / ${value.limit} stored · ${Math.max(0, value.limit - value.used)} remaining.`;
        level = 'available';
        if (value.limit !== null && value.used >= value.limit * .8) {
          level = value.used >= value.limit ? 'full' : 'near';
          warnings.push(`${key === 'cases' ? 'Case storage' : 'Feedback storage'} ${level === 'full' ? 'is full' : 'is nearing capacity'}.`);
        }
      }
      $(id).textContent = text; $(id).dataset.level = level;
    }
    $('capacity-warning').textContent = warnings.length
      ? warnings.join(' ') + ' Ask the administrator to archive and verify closed records before removing any. Closing a record does not free space.' : '';
  }
  function renderCase(value, {capture = true} = {}) {
    if (!rememberVersion(value)) return false;
    if (capture) captureDraft();
    clearJev();
    selected = value; syncSelection(); $('detail').hidden = false; $('empty-detail').hidden = true;
    renderJevAvailability();
    $('case-title').textContent = value.title;
    $('case-meta').textContent = `${value.id} · Revision ${value.version} · Created by ${value.created_by}`;
    $('badges').replaceChildren(riskBadge(value.risk), ...[labels[value.status], value.verdict || 'Not reviewed'].map(text => node('span', text, 'badge')));
    if (value.kind === 'feedback') $('badges').append(node('span', 'USER FEEDBACK', 'badge feedback-badge'));
    $('feedback-context').hidden = value.kind !== 'feedback';
    $('feedback-context').textContent = value.kind === 'feedback'
      ? `User report: ${(value.provenance?.report_type || 'other').replaceAll('_', ' ')} · Original input ${value.provenance?.source_consent ? 'included' : 'not included'}.${value.provenance?.note ? ' Reporter note: ' + value.provenance.note : ''} This diagnostic snapshot was supplied by the browser; verify before relying on it.`
      : '';
    const analysis = value.analysis;
    window.PhishGuardVision?.render($('visual-evidence'), analysis.visual_analysis);
    $('analysis-summary').textContent = `${analysis.risk_label || value.risk}. ${analysis.analysis_complete === false ? 'Analysis is incomplete; inspect the warnings before deciding.' : 'Review the evidence before making a decision.'}`;
    $('evidence').replaceChildren();
    if (value.kind === 'feedback') {
      for (const code of analysis.evidence_codes || []) {
        $('evidence').append(node('li', 'Reported signal: ' + code.replaceAll('_', ' ')));
      }
    }
    for (const evidence of [...(analysis.analysis_warnings || []), ...(analysis.extra_indicators || [])]) {
      $('evidence').append(node('li', typeof evidence === 'string' ? evidence : (evidence.msg || evidence.message || JSON.stringify(evidence))));
    }
    for (const category of analysis.category_results || []) {
      if (category.count > 0) $('evidence').append(node('li', `${category.label}: ${category.description} Matched: ${(category.matched || []).join(', ')}`));
    }
    $('analysis-json').textContent = JSON.stringify({analysis, provenance: value.provenance, input_sha256: value.input_sha256}, null, 2);
    $('source').textContent = value.kind === 'feedback' && !value.provenance?.source_consent
      ? '' : `${value.source.subject || ''}\n\n${value.source.body || ''}`;
    $('source-note').textContent = value.kind === 'feedback' && !value.provenance?.source_consent
      ? 'Original input was not included. Review is limited to the diagnostic summary and reporter note.'
      : value.source.text_truncated ? 'Saved text was truncated. See analysis warnings for other coverage limitations.'
      : 'Message text is displayed without rendering HTML or loading external content.';
    $('review-status').replaceChildren(...transitions[value.status].map(status => { const option = node('option', labels[status]); option.value = status; return option; }));
    $('review-status').value = transitions[value.status][0];
    $('feedback-review-fields').hidden = value.kind !== 'feedback';
    reviewBaseline = reviewDefaults(value);
    restoreReview(reviewDrafts.get(value.id)?.values || reviewBaseline);
    renderDraftState();
    $('history').replaceChildren(...value.events.map(event => {
      const li = node('li', '');
      li.append(node('strong', `${event.actor} · ${event.action === 'auxiliary_saved' ? 'Jev opinion saved' : event.action}`), node('p', new Date(event.happened_at).toLocaleString(), 'muted'));
      for (const [key, change] of Object.entries(event.changes)) {
        if (key === 'auxiliary_opinion' && event.action === 'auxiliary_saved' && change.to) {
          const opinion = change.to;
          li.append(node('p', `${opinion.model} · Requested ${new Date(opinion.requested_at).toLocaleString()}. Saved model opinion; risk and human verdict unchanged.`));
          renderProbabilities(li, opinion);
          if (opinion.evidence_incomplete) li.append(node('p', 'Original evidence was incomplete.'));
          const provenance = node('details', '');
          provenance.append(node('summary', 'Opinion provenance'), node('pre', JSON.stringify(opinion, null, 2)));
          li.append(provenance);
        } else li.append(node('p', `${key}: ${change.from ?? '—'} → ${change.to ?? '—'}`));
      }
      if (event.note) li.append(node('p', event.note));
      return li;
    }));
  }
  async function loadCase(id, kind) {
    captureDraft();
    const turn = ++detailEpoch;
    const value = await api(recordPath(id, kind));
    if (turn !== detailEpoch) return;
    if (renderCase(value) !== false) notice();
  }
  $('login-form').addEventListener('submit', event => {
    event.preventDefault(); const button = event.submitter;
    token = $('token').value.trim(); epoch++;
    action(button, async () => {
      const me = await refreshJev(); $('token').value = ''; $('actor').textContent = me.actor;
      $('login-panel').hidden = true; $('session').hidden = false; $('workspace').hidden = false;
      notice(); await loadList();
    });
  });
  $('open-compose').addEventListener('click', openComposer);
  $('close-compose').addEventListener('click', () => closeComposer());
  $('compose-dialog').addEventListener('cancel', event => {
    event.preventDefault();
    if (createPending) { notice('Wait for the current case submission to finish before closing the form.', true); return; }
    closeComposer();
  });
  $('logout').addEventListener('click', () => {
    if (!hasUnsavedWork() || window.confirm('Sign out and discard unsaved drafts in this tab?')) signOut();
  });
  function renderJevAvailability() {
    $('jev-panel').hidden = !token || !selected || selected.kind === 'feedback';
    const messages = {
      disabled: 'Jev is disabled for this deployment. An administrator can enable it and redeploy.',
      configuration_error: 'Jev configuration is incomplete or invalid. Check this deployment’s API key and daily limit, then redeploy.',
      control_unavailable: 'Jev request controls are unavailable. No new request can be sent. Refresh to check again.',
      quota_exhausted: 'The workspace daily allowance is exhausted. An existing opinion can still be retrieved; new requests resume after the UTC reset.',
      available: 'Jev is configured. Each new request requires your permission. Provider access is checked only when requested.'
    };
    let message = messages[jevConfig.status] || 'Jev status is unavailable. Refresh to check again.';
    if (Number.isInteger(jevConfig.used) && Number.isInteger(jevConfig.daily_limit)) {
      message += ` Workspace attempts today: ${jevConfig.used}/${jevConfig.daily_limit}.`;
    }
    if (Number.isInteger(jevConfig.reset_at)) message += ` Resets ${new Date(jevConfig.reset_at * 1000).toLocaleString()}.`;
    $('jev-availability').textContent = message;
    const busy = jevBusy || opinionSaves.has(selected?.id);
    $('jev-run').disabled = !jevAvailable || busy;
    $('jev-consent').disabled = !jevAvailable || busy;
    $('jev-read').disabled = busy;
    $('jev-save').hidden = !jevOpinion;
    $('jev-save').disabled = jevBusy || reviewSaves.has(selected?.id) || opinionSaves.has(selected?.id) || selected?.status === 'closed';
  }
  async function refreshJev() {
    const turn = ++jevStatusTurn;
    try {
      const me = await api('/me');
      if (turn !== jevStatusTurn) return me;
      jevAvailable = me.jev_available === true;
      jevConfig = me.jev || {status: jevAvailable ? 'available' : 'disabled'};
      renderJevAvailability();
      return me;
    } catch (error) {
      if (turn === jevStatusTurn && token) {
        jevAvailable = false; jevConfig = {status: 'control_unavailable'}; renderJevAvailability();
      }
      throw error;
    }
  }
  function clearJev() {
    jevTurn++; jevBusy = false; jevOpinion = null;
    $('jev-consent').checked = false; $('jev-status').textContent = '';
    $('jev-results').replaceChildren(); renderJevAvailability();
  }
  function renderProbabilities(target, result) {
    const names = {credential_request: 'Request for authentication secrets', payment_redirection: 'New or changed payment destination', authority_pressure: 'Pressure to bypass normal checks', phishing_intent: 'Deceptive intent', insufficient_evidence: 'Insufficient evidence'};
    const list = node('ul', '');
    for (const [key, label] of Object.entries(names)) {
      const probability = result.probabilities?.[key];
      if (typeof probability === 'number' && Number.isFinite(probability) && probability >= 0 && probability <= 1) {
        list.append(node('li', `${label}: ${(probability * 100).toFixed(1)}% estimated probability. This is not a severity score.`));
      }
    }
    target.append(list);
  }
  async function loadOpinion(readOnly) {
    if (!selected || selected.kind === 'feedback' || (!readOnly && !jevAvailable) || jevBusy || opinionSaves.has(selected.id)) return;
    if (!readOnly && !$('jev-consent').checked) { $('jev-status').textContent = 'Confirm permission to send this message first.'; return; }
    const turn = ++jevTurn, session = epoch, id = selected.id, version = selected.version;
    jevBusy = true; jevOpinion = null; renderJevAvailability(); $('jev-results').replaceChildren();
    $('jev-status').textContent = readOnly ? 'Reading your existing result…' : 'Requesting auxiliary opinion…';
    try {
      const result = await api('/' + encodeURIComponent(id) + '/auxiliary', readOnly ? {method:'GET'} : {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({allow_external_processing: true})});
      if (turn !== jevTurn || session !== epoch || selected?.id !== id) return;
      if (result.case_id !== id || result.case_version !== version) {
        $('jev-status').textContent = 'The case changed. Reload it before requesting another opinion.'; return;
      }
      if (result.quota) {
        jevStatusTurn++;
        jevConfig = {...result.quota, status: result.quota.used >= result.quota.daily_limit ? 'quota_exhausted' : 'available'};
        renderJevAvailability();
      }
      const receiptNote = result.receipt_expires_at
        ? ` This request record is reused until ${new Date(result.receipt_expires_at * 1000).toLocaleString()}; submitting again will not start another provider call during that period.` : '';
      if (result.status !== 'available') {
        const reasons = {
          no_cached_opinion: 'No unexpired result exists for your account and this case. No new model call was made.',
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
          local_capacity_exhausted: 'Auxiliary analysis is busy. This attempt did not reach TypeSafe. Wait for current requests to finish.',
          call_budget_exhausted: 'The auxiliary request allowance has been reached.',
          daily_quota_exhausted: 'The workspace daily allowance is exhausted. Wait for the UTC reset.',
          request_pending: 'An identical request is still running or its outcome is unknown. No additional provider call was made.',
          empty_or_oversized_text: 'Saved text is empty or exceeds the 12,000-character auxiliary limit.',
          legacy_source_format: 'This older case lacks separate readable email text. Create a new case from the original email.'
        };
        const message = Object.hasOwn(reasons, result.reason) ? reasons[result.reason] : 'Auxiliary analysis was unavailable or skipped.';
        $('jev-status').textContent = message + ' The original detection result is unchanged.' + receiptNote; return;
      }
      $('jev-status').textContent = `${result.model} · Model opinions, not verified findings. Risk and verdict are unchanged.${result.evidence_incomplete ? ' Original evidence is incomplete; this opinion cannot fill missing images or correct OCR.' : ''}`;
      if (result.reused) $('jev-status').textContent += ' Reused the previous request; no new provider call.';
      if (/^[0-9a-f]{64}$/.test(result.receipt_id || '')) jevOpinion = {id, version, receipt:result.receipt_id};
      if (selected.status === 'closed') $('jev-status').textContent += ' Reopen the case before saving this opinion.';
      renderProbabilities($('jev-results'), result);
    } catch (error) {
      if (turn === jevTurn && session === epoch) $('jev-status').textContent = error.message || 'Auxiliary analysis failed. The original detection result is unchanged.';
    } finally {
      if (turn === jevTurn) { jevBusy = false; $('jev-consent').checked = false; renderJevAvailability(); }
    }
  }
  $('jev-run').addEventListener('click', () => loadOpinion(false));
  $('jev-read').addEventListener('click', () => loadOpinion(true));
  $('jev-save').addEventListener('click', async () => {
    if (!selected || !jevOpinion || jevBusy || reviewSaves.has(selected.id) || opinionSaves.has(selected.id) || selected.status === 'closed') return;
    if (!window.confirm('Save this structured Jev opinion to case history for all workspace analysts? It will remain after the 24-hour cache expires. Risk and human verdict will not change.')) return;
    const opinion = jevOpinion, session = epoch, turn = jevTurn, operation = {};
    const version = selected.version;
    captureDraft(); opinionSaves.set(opinion.id, operation); jevBusy = true; renderDraftState();
    try {
      const saved = await api('/' + encodeURIComponent(opinion.id) + '/auxiliary/save', {method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({expected_version:version,receipt_id:opinion.receipt,confirm_save:true})});
      captureDraft(); rememberVersion(saved);
      if (opinionSaves.get(opinion.id) === operation) opinionSaves.delete(opinion.id);
      const draft = reviewDrafts.get(opinion.id);
      // This write changes only history. Preserve drafts based on the same prior revision.
      if (draft?.version === version && saved.version === version + 1) draft.version = saved.version;
      if (selected?.id === opinion.id && selected.version <= saved.version) {
        renderCase(saved, {capture:false}); notice('Jev opinion saved to case history. Human assessment is unchanged.');
      }
      await loadList();
    } catch (error) {
      if (session === epoch) notice(error.message || 'Could not confirm the save. Reload the case before retrying.', true);
    } finally {
      if (opinionSaves.get(opinion.id) === operation) opinionSaves.delete(opinion.id);
      if (session === epoch) { if (turn === jevTurn) jevBusy = false; renderDraftState(); }
    }
  });
  window.addEventListener('pagehide', signOut);
  window.addEventListener('beforeunload', event => {
    if (token && hasUnsavedWork()) { event.preventDefault(); event.returnValue = ''; }
  });
  for (const event of ['input', 'change']) $('review-form').addEventListener(event, () => { captureDraft(); renderDraftState(); });
  $('draft-rebase').addEventListener('click', () => {
    captureDraft();
    const draft = reviewDrafts.get(selected?.id);
    if (draft) draft.version = selected.version;
    renderDraftState();
  });
  $('draft-discard').addEventListener('click', () => {
    if (!selected || reviewSaves.has(selected.id)) return;
    reviewDrafts.delete(selected.id); restoreReview(reviewBaseline); renderDraftState();
  });
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
    event.preventDefault(); const current = epoch; createPending = true;
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
      if (creation === submitted) { creation = null; closeComposer({reset: true, force: true}); }
      $('vision-progress').textContent = '';
      detailEpoch++; renderCase(value); notice('Case saved.'); await loadList();
    }).finally(() => { createPending = false; });
  });
  $('review-form').addEventListener('submit', event => {
    event.preventDefault(); if (!selected) return;
    captureDraft();
    if (reviewSaves.has(selected.id) || opinionSaves.has(selected.id)) return;
    if (reviewDrafts.get(selected.id)?.version !== undefined && reviewDrafts.get(selected.id).version !== selected.version) {
      renderDraftState(); notice('Compare the latest case history, then confirm your draft against the current revision.', true); return;
    }
    if (!transitions[selected.status].includes($('review-status').value)) {
      notice('The saved case no longer supports this status. Choose an available status; your edits are still here.', true); return;
    }
    const id = selected.id, version = selected.version, session = epoch;
    const submittedFields = reviewValues();
    const operation = {submittedFields};
    const payload = {expected_version: version, status: $('review-status').value, verdict: $('verdict').value || null, note: $('note').value};
    if (selected.kind === 'feedback') {
      payload.feedback_reason = $('feedback-reason').value;
      payload.evidence_basis = $('evidence-basis').value;
    }
    reviewSaves.set(id, operation); renderDraftState();
    action(event.submitter, async () => {
      try {
        const value = await api(recordPath(id, selected.kind), {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
        rememberVersion(value);
        captureDraft();
        if (reviewSaves.get(id) === operation) reviewSaves.delete(id);
        const draft = reviewDrafts.get(id);
        if (!draft || draft.version <= version) {
          const later = Object.fromEntries(Object.entries(draft?.values || submittedFields).filter(([key, text]) => text !== submittedFields[key]));
          const baseline = reviewDefaults(value);
          keepDraft(id, value.version, {...baseline, ...later}, baseline);
        }
        if (selected?.id === id && selected.version <= value.version) {
          renderCase(value, {capture: false});
          notice(reviewDrafts.has(id) ? 'Review saved. Your newer edits are still unsaved.' : 'Review saved.');
        }
        await loadList();
      } catch (error) {
        if (error.status === 409) throw new Error('Another analyst changed this case. Your note is still here. Copy it, reload the case, then review the latest version before saving.');
        throw error;
      }
    }).finally(() => {
      if (reviewSaves.get(id) === operation) reviewSaves.delete(id);
      if (session === epoch) { captureDraft(); renderDraftState(); }
    });
  });
  $('filters').addEventListener('submit', event => { event.preventDefault(); offset = 0; action(event.submitter, loadList); });
  $('refresh').addEventListener('click', event => action(event.currentTarget, async () => { await refreshJev(); await loadList(); }));
  $('reload-case').addEventListener('click', event => { if (selected) {
    const id = selected.id, kind = selected.kind, turn = detailEpoch;
    action(event.currentTarget, async () => { await refreshJev(); if (turn === detailEpoch) await loadCase(id, kind); });
  } });
  for (const [id, delta] of [['previous', -PAGE_SIZE], ['next', PAGE_SIZE]]) $(id).addEventListener('click', async event => {
    const button = event.currentTarget; offset = Math.max(0, offset + delta);
    await action(button, loadList);
    // loadList owns pagination availability, including the last page.
    if (token) button.disabled = id === 'previous' ? offset === 0 : button.disabled;
  });
})();
