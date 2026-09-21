// Exact, offline scoring. Whitespace and punctuation are intentionally preserved.
export const SCHEMA = 'phishguard-vision-benchmark/v1';
const languages = ['eng', 'chi_sim', 'eng+chi_sim'];
const statuses = ['processed', 'partial', 'failed', 'timeout', 'missing', 'hash_mismatch', 'cancelled'];
function insist(ok, message) { if (!ok) throw new Error(message); }
function strings(value) { return Array.isArray(value) && value.every(s => typeof s === 'string'); }
export function validateManifest(manifest) {
  insist(manifest?.schema_version === SCHEMA, 'Unsupported manifest schema.');
  insist(typeof manifest.dataset_id === 'string' && manifest.dataset_id.length > 0, 'dataset_id is required.');
  insist(Array.isArray(manifest.records) && manifest.records.length > 0 && manifest.records.length <= 1000, 'Expected 1–1000 records.');
  const ids = new Set(), paths = new Set();
  for (const r of manifest.records) {
    insist(typeof r.id === 'string' && r.id.length > 0 && !ids.has(r.id), 'Duplicate or invalid record id.'); ids.add(r.id);
    insist(typeof r.filename === 'string' && r.filename.length <= 300 && !/[\\:\x00-\x1f]/.test(r.filename) && !r.filename.startsWith('/') && r.filename.split('/').every(p => p && p !== '.' && p !== '..'), `Unsafe filename: ${r.id}`);
    insist(/\.(png|jpe?g|webp)$/i.test(r.filename), `Expected a PNG, JPEG or WebP image: ${r.id}`);
    insist(!paths.has(r.filename), 'Duplicate filename.'); paths.add(r.filename);
    insist(/^[a-f0-9]{64}$/.test(r.sha256), `Invalid SHA-256: ${r.id}`);
    insist(languages.includes(r.language), `Invalid language: ${r.id}`);
    insist(typeof r.expected_text === 'string' && r.expected_text.length <= 24000, `Missing or oversized expected_text: ${r.id}`);
    insist(strings(r.expected_qr_payloads) && new Set(r.expected_qr_payloads).size === r.expected_qr_payloads.length, `Invalid QR ground truth: ${r.id}`);
    insist(r.expected_urls === undefined || (strings(r.expected_urls) && new Set(r.expected_urls).size === r.expected_urls.length), `Invalid URL ground truth: ${r.id}`);
    insist(['benign', 'phishing', 'unknown'].includes(r.label), `Label must be benign, phishing or unknown: ${r.id}`);
  }
  return manifest;
}
export function editDistance(a, b) {
  a = Array.from(a); b = Array.from(b);
  let row = Array.from({length: b.length + 1}, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const next = [i + 1];
    for (let j = 0; j < b.length; j++) next.push(Math.min(next[j] + 1, row[j + 1] + 1, row[j] + (a[i] === b[j] ? 0 : 1)));
    row = next;
  }
  return row[b.length];
}
export function extractURLs(text) {
  // Strict token comparison: do not repair OCR spelling, punctuation or scheme.
  return [...new Set(text.match(/https?:\/\/[^\s<>"']+/gu) || [])].sort();
}
const exactSet = (a, b) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());
const ratio = (n, d) => d ? n / d : null;
function summarize(rows, riskRequested) {
  const elapsed = rows.filter(r => r.elapsed_ms !== null).map(r => r.elapsed_ms).sort((a,b) => a-b);
  const count = rows.length, chars = rows.reduce((n,r) => n+r.reference_characters,0), edits = rows.reduce((n,r) => n+r.edit_distance,0);
  const qr = rows.filter(r => r.expected_qr_count > 0), urls = rows.filter(r => r.urls_scored);
  const english = rows.filter(r => r.language === 'eng'), risk = rows.filter(r => r.label !== 'unknown');
  return {count, statuses: Object.fromEntries(statuses.map(s => [s, rows.filter(r => r.status === s).length])),
    reference_characters: chars, edit_distance: edits, character_error_rate: ratio(edits, chars),
    empty_reference_false_text_count: rows.filter(r => r.reference_characters === 0 && r.actual_characters > 0).length,
    text_exact_rate: ratio(rows.filter(r => r.text_exact).length,count),
    qr_exact_set_rate: ratio(rows.filter(r => r.qr_exact).length,count),
    qr_positive_count: qr.length, qr_positive_exact_set_rate: ratio(qr.filter(r => r.qr_exact).length,qr.length),
    qr_payload_recall: ratio(rows.reduce((n,r) => n+r.qr_matched_count,0),rows.reduce((n,r) => n+r.expected_qr_count,0)),
    qr_extra_payload_count: rows.reduce((n,r) => n+r.qr_extra_count,0),
    url_scored_count: urls.length, url_exact_set_rate: ratio(urls.filter(r => r.urls_exact).length,urls.length),
    english_count: english.length, unexpected_han_image_rate: ratio(english.filter(r => r.unexpected_han_count > 0).length,english.length),
    risk_evaluation: riskRequested ? 'evaluated' : 'not_requested',
    risk_labeled_count: risk.length, risk_correct_rate: riskRequested ? ratio(risk.filter(r => r.risk_correct).length,risk.length) : null,
    risk_unavailable_count: riskRequested ? risk.filter(r => r.risk_prediction === 'unavailable').length : null,
    risk_undetermined_count: riskRequested ? risk.filter(r => r.risk_prediction === 'unknown').length : null,
    elapsed_ms: {measured_count: elapsed.length, mean: ratio(elapsed.reduce((a,b)=>a+b,0),elapsed.length), p50: elapsed.length ? elapsed[Math.ceil(elapsed.length*.5)-1] : null, p95: elapsed.length ? elapsed[Math.ceil(elapsed.length*.95)-1] : null}};
}
export function score(manifest, outcomes, identity = {}) {
  validateManifest(manifest);
  const riskRequested = identity.risk_requested === true;
  insist(Array.isArray(outcomes), 'Outcomes must be an array.');
  const allowed = new Set(manifest.records.map(r=>r.id)), byId = new Map();
  for (const o of outcomes) {
    insist(allowed.has(o.id) && !byId.has(o.id), 'Duplicate or unknown outcome id.');
    insist(statuses.includes(o.status), `Invalid outcome status: ${o.id}`);
    insist(typeof o.text === 'string' && o.text.length <= 24000 && strings(o.qr_payloads), `Invalid outcome content: ${o.id}`);
    insist(o.elapsed_ms === undefined || o.elapsed_ms === null || (Number.isFinite(o.elapsed_ms) && o.elapsed_ms >= 0), 'Invalid elapsed time.');
    byId.set(o.id,o);
  }
  const rows = manifest.records.map(r => {
    const o = byId.get(r.id) || {status:'missing',text:'',qr_payloads:[]};
    const usable = ['processed','partial'].includes(o.status);
    const text = usable ? o.text : '', qr = usable ? [...new Set(o.qr_payloads)] : [];
    const prediction = !riskRequested ? null : !o.risk_level ? 'unavailable' : ['medium','high','critical'].includes(o.risk_level) ? 'phishing' : ['low','safe'].includes(o.risk_level) ? 'benign' : 'unknown';
    return {id:r.id, language:r.language, label:r.label, status:o.status, reference_characters:Array.from(r.expected_text).length,
      actual_characters:Array.from(text).length, edit_distance:editDistance(r.expected_text,text), text_exact:usable && text === r.expected_text,
      qr_exact:usable && exactSet(qr,r.expected_qr_payloads), expected_qr_count:r.expected_qr_payloads.length,
      qr_matched_count:qr.filter(p=>r.expected_qr_payloads.includes(p)).length, qr_extra_count:qr.filter(p=>!r.expected_qr_payloads.includes(p)).length,
      urls_scored:r.expected_urls !== undefined, urls_exact:r.expected_urls !== undefined && usable && exactSet(extractURLs(text),r.expected_urls),
      unexpected_han_count:r.language === 'eng' ? (text.match(/\p{Script=Han}/gu)||[]).length : 0,
      elapsed_ms:o.elapsed_ms ?? null, risk_prediction:prediction, risk_correct:riskRequested ? usable && r.label !== 'unknown' && prediction === r.label : null};
  });
  return {schema_version:SCHEMA, dataset_id:manifest.dataset_id, identity, risk_evaluation:riskRequested ? 'evaluated' : 'not_requested',
    semantics:{text:'Unicode code points; no whitespace/punctuation/case normalization; CER may exceed 1.',missing:'Every manifest record is scored; failed extraction has empty output and never counts as exact.',urls:'Literal HTTP(S) tokens from OCR text; no URL requests or repair.',risk:'medium/high/critical=phishing alert; low/safe=benign non-alert; other=unknown. Not a safety guarantee.',provenance:'Browser extraction is unverified. Synthetic controls do not estimate production accuracy.'},
    summary:summarize(rows,riskRequested), by_language:Object.fromEntries(languages.map(l=>[l,summarize(rows.filter(r=>r.language===l),riskRequested)])), records:rows};
}
