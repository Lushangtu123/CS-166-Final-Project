/* Public reports are opt-in. Source builders run only after retention consent. */
'use strict';
window.PhishGuardFeedback = (() => {
  const contexts = {sender: null, content: null};
  let active = null;
  const $ = id => document.getElementById(id);

  function clear(kind) {
    contexts[kind] = null;
    if (active?.kind === kind) {
      active = null;
      $('feedback-dialog')?.close();
    }
  }
  function set(kind, context) { clear(kind); contexts[kind] = context; }
  function close() { active = null; $('feedback-dialog').close(); }
  function open(kind) {
    if (!contexts[kind]) return;
    active = {kind, context: contexts[kind], pending: false, submitted: false, retry: null, revision: 0};
    $('feedback-form').reset();
    $('feedback-evaluation-consent-row').hidden = !['content', 'eml'].includes(contexts[kind].inputMode);
    $('feedback-evaluation-consent').checked = false;
    $('feedback-evaluation-consent').disabled = true;
    $('feedback-error').textContent = '';
    $('feedback-error').classList.add('hidden');
    $('feedback-success').textContent = '';
    $('feedback-success').classList.add('hidden');
    $('feedback-fields').hidden = false;
    $('feedback-cancel').textContent = 'Cancel';
    $('feedback-submit').hidden = false;
    $('feedback-submit').disabled = false;
    $('feedback-submit').textContent = 'Submit report';
    $('feedback-dialog').showModal();
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
    const session = active, revision = session.revision, context = session.context, button = $('feedback-submit');
    const current = () => active === session && session.revision === revision;
    session.pending = true; button.disabled = true;
    $('feedback-error').classList.add('hidden');
    try {
      let submission = session.retry;
      if (submission?.sent && submission.revision !== revision && !window.confirm(
        'Retry the originally submitted report' + (JSON.parse(submission.body).include_source
          ? ', including the original input you previously agreed to retain' : ', without original input') +
        '? Your later edits and consent changes will not be sent.')) return;
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
      if (active !== session) return;
      const edited = session.revision !== submission.revision;
      $('feedback-success').textContent = 'Report received. Reference: ' + result.id +
        (edited ? '. Later edits were not sent. Copy them before closing.' : '');
      $('feedback-success').classList.remove('hidden');
      $('feedback-fields').hidden = !edited;
      $('feedback-cancel').textContent = 'Close';
      button.hidden = true;
      session.submitted = true;
      session.retry = null;
    } catch (error) {
      if (session.retry?.sent) session.retry.uncertain = true;
      if (active === session) {
        $('feedback-error').textContent = (error.message || 'Report could not be saved.') +
          (session.retry?.sent ? ' The outcome is unconfirmed. Retry checks the original submission; later edits are not sent.' : ' Correct the report and try again.');
        $('feedback-error').classList.remove('hidden');
      }
    } finally {
      session.pending = false;
      if (active === session) {
        button.disabled = false;
        button.textContent = session.retry?.sent ? 'Retry original report' : 'Submit report';
      }
    }
  }
  function setup() {
    $('feedback-form').addEventListener('submit', submit);
    $('feedback-cancel').addEventListener('click', close);
    $('feedback-close').addEventListener('click', close);
    $('feedback-dialog').addEventListener('close', () => { if (!$('feedback-dialog').open) active = null; });
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
