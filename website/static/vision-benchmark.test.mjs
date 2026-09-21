import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {SCHEMA, validateManifest, editDistance, extractURLs, score} from '../tools/vision-benchmark/metrics.mjs';
const record = (id, changes={}) => ({id,filename:`${id}.png`,sha256:'a'.repeat(64),language:'eng',expected_text:'Visit https://example.com/a.\n',expected_qr_payloads:['https://example.com/a'],expected_urls:['https://example.com/a.'],label:'benign',...changes});
const manifest = records => ({schema_version:SCHEMA,dataset_id:'negative-controls',records});
const outcome = (id, changes={}) => ({id,status:'processed',text:'Visit https://example.com/a.\n',qr_payloads:['https://example.com/a'],elapsed_ms:20,...changes});

test('strict CER preserves punctuation, case, whitespace and counts Unicode code points',()=>{
  assert.equal(editDistance('a.\n','A'),3);
  assert.equal(editDistance('𠀀a','𠀀b'),1);
  const result=score(manifest([record('a')]),[outcome('a',{text:'Visit https://example.com/a\n'})]);
  assert.equal(result.summary.edit_distance,1);
  assert.equal(result.summary.url_exact_set_rate,0);
  assert.deepEqual(extractURLs('https://example.com/a. https://example.com/a.'),['https://example.com/a.']);
});
test('missing, timeout, hash mismatch and cancelled records stay in every applicable denominator',()=>{
  const data=manifest(['a','b','c','d','e'].map(id=>record(id)));
  const result=score(data,[outcome('a'),outcome('b',{status:'timeout'}),outcome('c',{status:'hash_mismatch'}),outcome('d',{status:'cancelled'})]);
  assert.equal(result.summary.count,5);
  assert.equal(result.summary.text_exact_rate,.2);
  assert.equal(result.summary.qr_positive_exact_set_rate,.2);
  assert.equal(result.summary.url_exact_set_rate,.2);
  assert.equal(result.summary.character_error_rate,.8);
  assert.equal(result.summary.statuses.missing,1);
});
test('QR omission and extra payload are measured even when one payload matches',()=>{
  const result=score(manifest([record('a',{expected_qr_payloads:['one','two']})]),[outcome('a',{qr_payloads:['one','unexpected']})]);
  assert.equal(result.summary.qr_positive_exact_set_rate,0);
  assert.equal(result.summary.qr_payload_recall,.5);
  assert.equal(result.summary.qr_extra_payload_count,1);
});
test('English Han insertion counted and language groups preserve failures',()=>{
  const result=score(manifest([record('a'),record('b',{language:'chi_sim'})]),[outcome('a',{text:'过'})]);
  assert.equal(result.summary.unexpected_han_image_rate,1);
  assert.equal(result.by_language.chi_sim.statuses.missing,1);
  assert.equal(result.by_language['eng+chi_sim'].text_exact_rate,null);
});
test('empty-reference failures cannot silently improve exact scores or produce invalid CER',()=>{
  const data=manifest([record('a',{expected_text:'',expected_qr_payloads:[]}),record('b',{expected_text:'',expected_qr_payloads:[]})]);
  const result=score(data,[outcome('a',{text:'noise',qr_payloads:[]})]);
  assert.equal(result.summary.character_error_rate,null);
  assert.equal(result.summary.empty_reference_false_text_count,1);
  assert.equal(result.summary.text_exact_rate,0);
  assert.equal(result.summary.qr_exact_set_rate,.5);
});
test('ground truth rejects traversal, duplicates, unsupported labels and missing text',()=>{
  for (const patch of [{filename:'../x.png'},{filename:'/tmp/a.png'},{filename:'a\\b.png'},{filename:'https://a.png'}, {sha256:'abc'}, {language:'auto'}, {label:'tampered'}, {expected_text:undefined}, {expected_qr_payloads:['a','a']}]) {
    assert.throws(()=>validateManifest(manifest([record('a',patch)])));
  }
  assert.throws(()=>validateManifest(manifest([record('a'),record('a')])));
  assert.throws(()=>validateManifest(manifest([record('a'),record('b',{filename:'a.png'})])));
});
test('outcome duplicates, unknown ids and invalid measurements are rejected',()=>{
  const data=manifest([record('a')]);
  for(const outcomes of [[outcome('a'),outcome('a')],[outcome('unknown')],[outcome('a',{elapsed_ms:NaN})],[outcome('a',{status:'skipped'})]]) assert.throws(()=>score(data,outcomes));
});
test('risk assessment separates unavailable, unknown and incorrect predictions',()=>{
  const result=score(manifest([record('a'),record('b'),record('c',{label:'phishing'}),record('d',{label:'unknown'})]),[outcome('a',{risk_level:'low'}),outcome('b',{risk_level:'unknown'}),outcome('c'),outcome('d',{risk_level:'high'})],{risk_requested:true});
  assert.equal(result.risk_evaluation,'evaluated');
  assert.equal(result.summary.risk_correct_rate,1/3);
  assert.equal(result.summary.risk_unavailable_count,1);
  assert.equal(result.summary.risk_undetermined_count,1);
  assert.equal(score(manifest([record('a',{label:'phishing'})]),[outcome('a',{risk_level:'medium'})],{risk_requested:true}).summary.risk_correct_rate,1);
});
test('disabled risk evaluation is explicit and does not report zero accuracy or failure counts',()=>{
  const result=score(manifest([record('a'),record('b')]),[outcome('a',{risk_level:'high'})],{risk_requested:false});
  assert.equal(result.risk_evaluation,'not_requested');
  assert.equal(result.summary.risk_labeled_count,2);
  for(const group of [result.summary,result.by_language.eng]) {
    assert.equal(group.risk_evaluation,'not_requested');
    assert.equal(group.risk_correct_rate,null);
    assert.equal(group.risk_unavailable_count,null);
    assert.equal(group.risk_undetermined_count,null);
  }
  assert.ok(result.records.every(r=>r.risk_prediction === null && r.risk_correct === null));
  assert.equal(result.summary.statuses.missing,1);
});
test('synthetic manifest hashes match real repository fixtures and report excludes raw extracted content',()=>{
  const fixture=JSON.parse(readFileSync(new URL('../tools/vision-benchmark/synthetic-manifest.json',import.meta.url)));
  validateManifest(fixture);
  for(const r of fixture.records) assert.equal(createHash('sha256').update(readFileSync(new URL(`../tests/fixtures/vision/${r.filename}`,import.meta.url))).digest('hex'),r.sha256);
  const result=score(manifest([record('a')]),[outcome('a',{text:'private OCR sentinel',qr_payloads:['private QR sentinel']})]);
  assert.ok(!JSON.stringify(result).includes('private'));
});
