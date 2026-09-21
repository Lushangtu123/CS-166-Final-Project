/* Browser extraction is supplementary evidence; all risk decisions happen on the server. */
'use strict';
window.PhishGuardVision = (() => {
  let active = null;
  const MAX_BYTES = 2 * 1024 * 1024;
  function cancel() { if (active) { active.stop(); active = null; } }
  function base64(buffer) {
    const bytes = new Uint8Array(buffer); let text = '';
    for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(text);
  }
  async function recognize(file, onProgress = () => {}) {
    cancel();
    if (!file.size || file.size > MAX_BYTES) throw new Error('Choose a nonempty PNG, JPEG, WebP or EML file up to 2 MiB.');
    const kind = /\.eml$/i.test(file.name) || file.type === 'message/rfc822' ? 'eml' : 'image';
    // Register before the asynchronous file read, so clear/sign-out cancels reading too.
    let cancelled = false, worker, rejectWork, timer;
    const task = {stop() { cancelled = true; clearTimeout(timer); worker?.terminate(); rejectWork?.(new Error('Recognition cancelled.')); }};
    active = task;
    try {
      const buffer = await file.arrayBuffer();
      if (cancelled) throw new Error('Recognition cancelled.');
      if (!buffer.byteLength || buffer.byteLength > MAX_BYTES) throw new Error('File exceeds the 2 MiB limit.');
      const result = await new Promise((resolve, reject) => {
        rejectWork = reject;
        worker = new Worker('/static/vision-worker.mjs?v=1', {type: 'module'});
        timer = setTimeout(() => { worker.terminate(); reject(new Error('Recognition timed out. Try a smaller image.')); }, 150000);
        worker.onerror = () => reject(new Error('Recognition could not start. Reload the page or try a supported browser.'));
        worker.onmessage = ({data}) => {
          if (cancelled) return;
          if (data.progress) onProgress(data.progress);
          if (data.error) reject(new Error(data.error));
          if (data.result) resolve(data.result);
        };
        worker.postMessage({buffer, name: file.name, kind});
      });
      if (cancelled) throw new Error('Recognition cancelled.');
      return {...result, ...(kind === 'eml' ? {eml_base64: base64(buffer)} : {})};
    } finally { clearTimeout(timer); worker?.terminate(); if (active === task) active = null; }
  }
  function render(target, analysis) {
    if (!target) return;
    target.replaceChildren(); target.hidden = !analysis;
    if (!analysis) return;
    const node = (tag, text) => { const el = document.createElement(tag); el.textContent = text; return el; };
    target.append(node('h3', 'Image & QR evidence'), node('p', 'Extracted in your browser; not independently verified. Recognition may miss content and does not assess malware or all image meaning. Links are shown as text and are not opened.'));
    for (const item of analysis.observations || []) {
      const section = node('section', '');
      section.append(node('h4', item.name), node('p', `${item.status} · ${item.risk_level || 'unscored'} · OCR confidence ${Math.round(item.ocr_confidence)}%`));
      for (const payload of item.qr_payloads || []) section.append(node('strong', 'QR payload'), node('pre', payload));
      if (item.ocr_text) section.append(node('strong', 'Extracted text'), node('pre', item.ocr_text));
      for (const warning of [...new Set([...(item.warnings || []), ...(item.assessment_warnings || [])])]) section.append(node('p', warning));
      target.append(section);
    }
    for (const warning of analysis.warnings || []) target.append(node('p', warning));
    if (!analysis.observations?.length) target.append(node('p', 'No image observations were available. Review coverage warnings.'));
  }
  return {recognize, cancel, render, MAX_BYTES};
})();
