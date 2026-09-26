/* Public reports are opt-in. Source builders run only after retention consent. */
'use strict';
window.PhishGuardFeedback = (() => {
  const contexts = {sender: null, content: null};
  // A report belongs to an analysis, so closing its dialog must not discard a
  // sent request, its idempotency key, or a receipt that arrives while closed.
  const sessions = {sender: null, content: null};
  let active = null;
  const $ = id => document.getElementById(id);
  const askConfirm = (message, options) => window.PhishGuardConfirm
    ? window.PhishGuardConfirm(message, options) : Promise.resolve(window.confirm(message));

  function clear(kind) {
    contexts[kind] = null;
    sessions[kind] = null;
    if (active?.kind === kind) {
      detach();
      $('feedback-dialog')?.close();
    }
  }
  function set(kind, context) { clear(kind); contexts[kind] = context; }
  function draft() {
    return {type: $('feedback-type').value, note: $('feedback-note').value,
      consent: $('feedback-consent').checked, evaluation: $('feedback-evaluation-consent').checked};
  }
  function detach() {
    if (!active) return;
    active.draft = draft();
    // A hash has no server-side effects. Cancel it without blocking a new
    // attempt; its eventual completion cannot unlock that newer attempt.
    if (!active.retry?.sent) { active.revision++; active.pending = null; }
    active = null;
  }
  function close() { detach(); $('feedback-dialog').close(); }
  function createSession(kind) {
    $('feedback-form').reset();
    return {kind, context: contexts[kind], pending: null, submitted: false,
      retry: null, receipt: null, revision: 0, draft: draft(), error: ''};
  }
  function render(session, restoreDraft = false) {
    if (active !== session) return;
    if (restoreDraft) {
      $('feedback-type').value = session.draft.type;
      $('feedback-note').value = session.draft.note;
      $('feedback-consent').checked = session.draft.consent;
      $('feedback-evaluation-consent').checked = session.draft.evaluation;
    }
    const supportsEvaluation = ['content', 'eml'].includes(session.context.inputMode);
    $('feedback-evaluation-consent-row').hidden = !supportsEvaluation;
    $('feedback-evaluation-consent').disabled = !supportsEvaluation || !$('feedback-consent').checked;
    $('feedback-error').textContent = session.error;
    $('feedback-error').classList[session.error ? 'remove' : 'add']('hidden');
    const edited = session.submitted && session.revision !== session.retry.revision;
    $('feedback-success').textContent = session.submitted ? 'Report received. Reference: ' + session.receipt +
      (edited ? '. Later edits were not sent. Start a new report to submit them.' : '') : '';
    $('feedback-success').classList[session.submitted ? 'remove' : 'add']('hidden');
    $('feedback-fields').hidden = session.submitted && !edited;
    $('feedback-cancel').textContent = session.submitted ? 'Close' : 'Cancel';
    $('feedback-submit').hidden = session.submitted;
    $('feedback-submit').disabled = !!session.pending;
    $('feedback-submit').textContent = session.pending ? 'Submitting report…'
      : session.retry?.sent ? 'Retry original report' : 'Submit report';
    $('feedback-new-report').hidden = !session.submitted;
  }
  function open(kind) {
    if (!contexts[kind]) return;
    if (active) detach();
    active = sessions[kind] ||= createSession(kind);
    render(active, true);
    if (!$('feedback-dialog').open) $('feedback-dialog').showModal();
    $(active.submitted ? 'feedback-new-report' : 'feedback-type').focus();
  }
  function newReport() {
    if (!active?.submitted || active.pending) return;
    const previous = active, edited = previous.revision !== previous.retry.revision;
    previous.draft = draft();
    active = sessions[previous.kind] = createSession(previous.kind);
    if (edited) active.draft = {...previous.draft, consent: false, evaluation: false};
    render(active, true);
    $('feedback-type').focus();
  }
  async function fingerprint(value) {
    const bytes = value instanceof ArrayBuffer ? value : new TextEncoder().encode(String(value));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return 'sha256:' + [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function consentedSource(context) {
    if (context.inputMode === 'eml' && context.fingerprintInput.byteLength > 60000) {
      throw new Error('This email file exceeds the 60 KB report retention limit. Uncheck original input to submit a source-free report.');
    }
    const source = context.buildSource();
    if (context.inputMode === 'image' && !source.ocr_text && !source.qr_text) {
      throw new Error('No text or QR evidence was extracted from this image. Uncheck original input to submit a source-free report.');
    }
    const limits = {email:320, subject:500, body:50000, ocr_text:12000, qr_text:4000};
    for (const [key, value] of Object.entries(source)) {
      if (key === 'eml_base64') continue;
      if (typeof value !== 'string' || new TextEncoder().encode(value).length > limits[key] || value.toLowerCase().includes('data:')) {
        throw new Error('Original input exceeds report limits or contains inline image data. Uncheck original input to submit a source-free report.');
      }
    }
    return source;
  }
  async function submit(event) {
    event.preventDefault();
    if (!active || active.pending || active.submitted) return;
    const session = active, revision = session.revision, context = session.context, attempt = {};
    const current = () => active === session && $('feedback-dialog').open &&
      session.revision === revision && session.pending === attempt;
    session.draft = draft();
    session.pending = attempt;
    render(session);
    try {
      let submission = session.retry;
      if (submission?.sent && submission.revision !== revision) {
        const original = JSON.parse(submission.body);
        const retry = await askConfirm('Retry the originally submitted report' + (original.include_source
          ? ', including the original input you previously agreed to retain' : ', without original input') +
          (original.evaluation_consent ? ' and allowing its use in private detection evaluation' : '') +
          '? Your later edits and consent changes will not be sent.', {confirmLabel: 'Retry original report'});
        if (!retry || !current()) return;
      }
      session.error = '';
      render(session);
      if (!submission) {
        const include = $('feedback-consent').checked;
        const payload = {
          report_type: $('feedback-type').value, note: $('feedback-note').value.trim(),
          include_source: include,
          evaluation_consent: include && ['content', 'eml'].includes(context.inputMode) && $('feedback-evaluation-consent').checked,
          input_mode: context.inputMode,
          analysis: context.analysis,
        };
        payload.input_fingerprint = await fingerprint(context.fingerprintInput);
        // Closing, replacing or editing this dialog invalidates unsent work.
        if (!current()) return;
        payload.source = include ? consentedSource(context) : null;
        submission = {key: crypto.randomUUID(), body: JSON.stringify(payload), revision};
        session.retry = submission;
      }
      submission.sent = true;
      const response = await fetch('/api/feedback', {method: 'POST', cache: 'no-store',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'Idempotency-Key': submission.key},
        body: submission.body});
      let result;
      try { result = await response.json(); } catch (_error) { throw new Error('The server returned an unreadable response.'); }
      if (!response.ok) {
        // A definite rejection cannot settle an earlier ambiguous attempt.
        if ([400, 413, 422, 429].includes(response.status) && !submission.uncertain) session.retry = null;
        throw new Error(typeof result.detail === 'string' ? result.detail : 'Report could not be saved.');
      }
      // Save the receipt even with no active modal. Rendering remains isolated
      // from sessions belonging to replaced or cleared analysis contexts.
      session.receipt = result.id;
      session.submitted = true;
    } catch (error) {
      if (session.pending !== attempt) return;
      if (session.retry?.sent) session.retry.uncertain = true;
      session.error = (error.message || 'Report could not be saved.') +
        (session.retry?.sent ? ' The outcome is unconfirmed. Retry checks the original submission; later edits are not sent.' : ' Correct the report and try again.');
    } finally {
      if (session.pending === attempt) {
        session.pending = null;
        render(session);
      }
    }
  }
  function setup() {
    $('feedback-form').addEventListener('submit', submit);
    $('feedback-cancel').addEventListener('click', close);
    $('feedback-close').addEventListener('click', close);
    $('feedback-new-report').addEventListener('click', newReport);
    $('feedback-dialog').addEventListener('close', () => { if (!$('feedback-dialog').open) detach(); });
    for (const event of ['input', 'change']) $('feedback-form').addEventListener(event, () => {
      if (active) { if (!active.retry?.sent) active.retry = null; active.revision++; }
    });
    $('feedback-consent').addEventListener('change', () => {
      const allowed = $('feedback-consent').checked && !($('feedback-evaluation-consent-row').hidden);
      $('feedback-evaluation-consent').disabled = !allowed;
      if (!allowed) $('feedback-evaluation-consent').checked = false;
    });
  }
  document.addEventListener('DOMContentLoaded', setup);
  return {set, clear, open};
})();
