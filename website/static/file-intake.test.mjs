import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

class Target extends EventTarget {
  constructor() { super(); const names=new Set(); this.classList={add:n=>names.add(n),remove:n=>names.delete(n),contains:n=>names.has(n)}; }
  contains(target) { return target === this; }
}
const png = {name:'screenshot.png',type:'image/png',size:100};
function setup(options={}) {
  const document=new Target(),window=new Target(),zone=new Target(),input=new Target(),errors=[];
  let enabled=true, changes=0;
  input.files=[];
  Object.defineProperty(input,'value',{set(value){if(value==='')this.files=[];}});
  input.addEventListener('change',()=>changes++);
  class Transfer {constructor(){this.files=[];this.items={add:file=>this.files.push(file)};}}
  vm.runInNewContext(readFileSync(new URL('./file-intake.js',import.meta.url),'utf8'),{
    window,document,Event,DataTransfer:options.unsupported?undefined:Transfer,
  });
  window.PhishGuardFiles.bind({zone,input,enabled:()=>enabled,onError:error=>errors.push(error)});
  const fire=(name,data={},target=zone)=>{
    const event=new Event(name,{cancelable:true});
    Object.assign(event,data); target.dispatchEvent(event); return event;
  };
  return {window,document,zone,input,errors,fire,get changes(){return changes;},disable(){enabled=false;}};
}
const transfer=files=>({files,types:['Files'],dropEffect:'none'});

test('file drop highlights the target and selects exactly one file without submitting',()=>{
  const ui=setup(),data=transfer([png]);
  const over=ui.fire('dragover',{dataTransfer:data});
  assert(over.defaultPrevented);assert.equal(data.dropEffect,'copy');assert(ui.zone.classList.contains('drag-active'));
  ui.fire('dragleave',{relatedTarget:ui.zone});assert(ui.zone.classList.contains('drag-active'));
  const drop=ui.fire('drop',{dataTransfer:data});
  assert(drop.defaultPrevented);assert(!ui.zone.classList.contains('drag-active'));
  assert.equal(ui.input.files[0],png);assert.equal(ui.changes,1);assert.equal(ui.errors.length,0);
});
test('screenshot paste uses file data, while ordinary text and URL paste remain untouched',()=>{
  const ui=setup();
  const event=ui.fire('paste',{clipboardData:{items:[{kind:'file',getAsFile:()=>png}]}});
  assert(event.defaultPrevented);assert.equal(ui.input.files[0],png);assert.equal(ui.changes,1);
  for(const type of ['text/plain','text/uri-list','text/html']){
    assert(!ui.fire('paste',{clipboardData:{types:[type],files:[]}}).defaultPrevented);
    assert(!ui.fire('drop',{dataTransfer:{types:[type],files:[]}}).defaultPrevented);
  }
  assert.equal(ui.changes,1);
});
test('invalid files clear a previous selection and produce actionable errors',()=>{
  for(const [files,message] of [
    [[png,png],/one file/], [[{...png,size:2097153}],/2 MiB/], [[{...png,size:0}],/nonempty/],
    [[{name:'other.pdf',type:'application/pdf',size:10}],/PNG, JPEG, WebP/],
  ]){
    const ui=setup();ui.fire('drop',{dataTransfer:transfer([png])});ui.fire('drop',{dataTransfer:transfer(files)});
    assert.equal(ui.input.files.length,0);assert.equal(ui.changes,2);assert.match(ui.errors[0],message);
  }
});
test('inactive areas cannot accept files and drops outside the target cannot navigate away',()=>{
  const ui=setup();ui.disable();
  ui.fire('drop',{dataTransfer:transfer([png])});ui.fire('paste',{clipboardData:transfer([png])});
  assert.equal(ui.changes,0);
  assert(ui.fire('drop',{dataTransfer:transfer([png])},ui.document).defaultPrevented);
});
test('transfer API failures offer the existing file picker; abandoned drags clear highlight',()=>{
  const ui=setup({unsupported:true});
  ui.fire('drop',{dataTransfer:transfer([png])});assert.match(ui.errors[0],/Choose File/);
  ui.fire('dragenter',{dataTransfer:transfer([png])});ui.fire('blur',{},ui.window);
  assert(!ui.zone.classList.contains('drag-active'));
});
