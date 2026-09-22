/* Public reports are opt-in. Source builders run only after retention consent. */
'use strict';
window.PhishGuardFeedback = (() => {
  const contexts = {sender: null, content: null};
  let active = null, version = 0, pending = false, submitted = false, retry = null;
  const $ = id => document.getElementById(id);

  function clear(kind) {
    contexts[kind] = null;
    version++;
    if (active === kind) {
      active = null;
      $('feedback-dialog')?.close();
    }
  }
  function set(kind, context) { clear(kind); contexts[kind] = context; }
  function close() { active = null; version++; retry = null; $('feedback-dialog').close(); }
  function open(kind) {
    if (!contexts[kind]) return;
    active = kind; version++; pending = false; submitted = false; retry = null;
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
    if (pending || submitted || !active || !contexts[active]) return;
    const turn = version, context = contexts[active], button = $('feedback-submit');
    pending = true; button.disabled = true;
    $('feedback-error').classList.add('hidden');
    try {
      if (!retry) {
        const include = $('feedback-consent').checked;
        const payload = {
          report_type: $('feedback-type').value, note: $('feedback-note').value.trim(),
          include_source: include,
          evaluation_consent: include && ['content', 'eml'].includes(context.inputMode) && $('feedback-evaluation-consent').checked,
          input_mode: context.inputMode,
          input_fingerprint: await fingerprint(context.fingerprintInput),
          analysis: context.analysis, source: include ? consentedSource(context) : null,
        };
        retry = {key: crypto.randomUUID(), body: JSON.stringify(payload)};
      }
      const response = await fetch('/api/feedback', {method: 'POST', cache: 'no-store',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'Idempotency-Key': retry.key},
        body: retry.body});
      let result;
      try { result = await response.json(); } catch (_error) { throw new Error('The server returned an unreadable response.'); }
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Report could not be saved.');
      if (turn !== version) return;
      $('feedback-success').textContent = 'Report received. Reference: ' + result.id;
      $('feedback-success').classList.remove('hidden');
      $('feedback-fields').hidden = true;
      $('feedback-cancel').textContent = 'Close';
      button.hidden = true;
      submitted = true;
      retry = null;
    } catch (error) {
      if (turn === version) {
        $('feedback-error').textContent = error.message || 'Report could not be saved. Try again.';
        $('feedback-error').classList.remove('hidden');
      }
    } finally {
      pending = false; button.disabled = false;
    }
  }
  function setup() {
    $('feedback-form').addEventListener('submit', submit);
    $('feedback-cancel').addEventListener('click', close);
    $('feedback-close').addEventListener('click', close);
    $('feedback-dialog').addEventListener('close', () => { active = null; version++; retry = null; });
    for (const id of ['feedback-type', 'feedback-note', 'feedback-consent', 'feedback-evaluation-consent']) {
      $('feedback-form').addEventListener(id === 'feedback-note' ? 'input' : 'change', () => { retry = null; });
    }
    $('feedback-consent').addEventListener('change', () => {
      const allowed = $('feedback-consent').checked && !($('feedback-evaluation-consent-row').hidden);
      $('feedback-evaluation-consent').disabled = !allowed;
      if (!allowed) $('feedback-evaluation-consent').checked = false;
    });
  }
  document.addEventListener('DOMContentLoaded', setup);
  return {set, clear, open};
})();
