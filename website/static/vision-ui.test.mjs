import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.textContent=''; }
  set innerHTML(_) {throw new Error('HTML rendering is forbidden');}
  append(...nodes) {this.children.push(...nodes);}
  replaceChildren(...nodes) {this.children=nodes;}
}
function setup() {
  const workers=[];
  class Worker {
    constructor() {workers.push(this);}
    postMessage(message) {this.input=message;}
    terminate() {this.terminated=true;}
  }
  const window={};
  vm.runInNewContext(readFileSync(new URL('./vision.js',import.meta.url),'utf8'),{
    window,document:{createElement:tag=>new Element(tag)},Worker,setTimeout,clearTimeout,Uint8Array,
    btoa:s=>Buffer.from(s,'binary').toString('base64'),
  });
  return {api:window.PhishGuardVision,workers};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
test('cancel while reading a file prevents the worker and result from appearing',async()=>{
  const {api,workers}=setup();let release;
  const promise=api.recognize({name:'test.png',size:1,arrayBuffer:()=>new Promise(resolve=>{release=resolve;})});
  const rejected=assert.rejects(promise,/cancelled/);
  api.cancel(); release(new Uint8Array([1]).buffer);await rejected;
  assert.equal(workers.length,0);
});
test('cancel terminates active recognition; late messages cannot restore a result',async()=>{
  const {api,workers}=setup();
  const promise=api.recognize({name:'test.png',size:1,arrayBuffer:async()=>new Uint8Array([1]).buffer});
  const rejected=assert.rejects(promise,/cancelled/);
  await tick();api.cancel();workers[0].onmessage({data:{result:{observations:[],warnings:[]}}});await rejected;
  assert.equal(workers[0].terminated,true);
});
test('EML envelope preserves non-UTF8 bytes and recognition evidence',async()=>{
  const {api,workers}=setup(),bytes=new Uint8Array([72,233,98,101]);
  const promise=api.recognize({name:'original.eml',size:4,arrayBuffer:async()=>bytes.buffer});
  await tick();workers[0].onmessage({data:{result:{observations:[],warnings:['Some images skipped']}}});
  const payload=await promise;
  assert.deepEqual(Buffer.from(payload.eml_base64,'base64'),Buffer.from(bytes));
  assert.equal(payload.warnings[0],'Some images skipped');assert.equal(workers[0].terminated,true);
});
test('recognition evidence renders malicious payloads only as text, never links or HTML',()=>{
  const {api}=setup(),root=new Element('section');
  const payload='<img src=x onerror=alert(1)>',url='javascript:alert(1)';
  api.render(root,{observations:[{name:payload,status:'processed',risk_level:'high',ocr_confidence:80,qr_payloads:[url],ocr_text:payload,warnings:[]}],warnings:[]});
  function walk(node) {return [node,...node.children.flatMap(walk)];}
  const nodes=walk(root);
  assert(nodes.some(n=>n.tag==='pre'&&n.textContent===url));
  assert(nodes.some(n=>n.tag==='pre'&&n.textContent===payload));
  assert(!nodes.some(n=>['img','a','script'].includes(n.tag)));
  api.render(root,null);assert.equal(root.children.length,0);assert.equal(root.hidden,true);
});

test('successful OCR with unknown risk distinguishes recognition from risk and model confidence',()=>{
  const {api}=setup(),root=new Element('section');
  const item={name:'newsletter.png',status:'processed',risk_level:'unknown',ocr_confidence:92,
    qr_payloads:[],ocr_text:'Readable newsletter text.',warnings:[],ml_status:'available',ml_phishing_probability:12};
  function textOf(node) {return [node.textContent,...node.children.map(textOf)].join(' ');}
  api.render(root,{observations:[item],warnings:[]});
  let text=textOf(root);
  assert.match(text,/Recognition completed/);
  assert.match(text,/Risk undetermined/);
  assert.match(text,/OCR confidence 92%/);
  assert.match(text,/Extracted-text model score: 12%/);
  assert.match(text,/not a phishing probability/);
  api.render(root,{observations:[{...item,status:'failed',ocr_text:'',ml_status:'insufficient_context',ml_phishing_probability:null}],warnings:[]});
  text=textOf(root);
  assert.match(text,/Recognition failed/);
  assert.doesNotMatch(text,/Recognition completed|model score: 12%/);
  assert.match(text,/Too little readable text/);
});
