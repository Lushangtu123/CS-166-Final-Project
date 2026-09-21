import {validateManifest, score} from './metrics.mjs';
const el = id => document.getElementById(id);
if (!['127.0.0.1','localhost','[::1]'].includes(location.hostname)) throw new Error('Localhost only.');
const identity = await (await fetch('/identity.json')).json();
el('identity').textContent = `Code: ${identity.code_commit || 'unknown'}; local risk API ${identity.risk_enabled ? 'enabled' : 'disabled'}.`;
el('risk').disabled = !identity.risk_enabled;
let stopped = false, report = null;
const digest = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(n=>n.toString(16).padStart(2,'0')).join('');
el('cancel').onclick = () => {stopped=true; window.PhishGuardVision.cancel();};
el('run').onclick = async () => {
  stopped=false; report=null; el('text-comparison').textContent=''; el('run').disabled=true; el('cancel').disabled=false; el('download').disabled=true;
  try {
    const selected=el('manifest').files[0];
    if (!selected || selected.size > 4*1024*1024) throw new Error('Select a manifest JSON up to 4 MiB.');
    const bytes=await selected.arrayBuffer(), manifest=validateManifest(JSON.parse(new TextDecoder().decode(bytes)));
    const files=new Map();
    for (const file of [...el('images').files,...el('folder').files]) {
      const path=file.webkitRelativePath ? file.webkitRelativePath.split('/').slice(1).join('/') : file.name;
      if (files.has(path)) throw new Error(`Duplicate selected path: ${path}`);
      files.set(path,file);
    }
    const outcomes=[];
    const evaluateRisk=el('risk').checked && identity.risk_enabled;
    for (const [index,r] of manifest.records.entries()) {
      if (stopped) {outcomes.push({id:r.id,status:'cancelled',text:'',qr_payloads:[]});continue;}
      const start=performance.now(), file=files.get(r.filename);
      const outcome={id:r.id,status:'missing',text:'',qr_payloads:[]};
      try {
        if (!file) {outcomes.push(outcome);continue;}
        if (!file.size || file.size>window.PhishGuardVision.MAX_BYTES) throw new Error('File size limit exceeded.');
        if (await digest(await file.arrayBuffer()) !== r.sha256) {outcome.status='hash_mismatch';outcomes.push(outcome);continue;}
        if (stopped) throw new Error('Recognition cancelled.');
        const data=await window.PhishGuardVision.recognize(file,message=>{el('status').textContent=`${index+1}/${manifest.records.length} ${r.id}: ${message}`;},r.language);
        const observations=data.observations || [];
        outcome.status=observations.length === 0 || observations.every(o=>['failed','skipped'].includes(o.status)) ? 'failed' : observations.some(o=>o.status!=='processed') ? 'partial' : 'processed';
        outcome.text=observations.map(o=>o.ocr_text || '').join('\n');
        outcome.qr_payloads=observations.flatMap(o=>o.qr_payloads || []);
        el('text-comparison').textContent += JSON.stringify({id:r.id,expected:r.expected_text,extracted:outcome.text,warnings:observations.flatMap(o=>o.warnings || [])},null,2)+'\n';
        if (evaluateRisk) {
          try {
            const response=await fetch('/api/analyze-visual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),signal:AbortSignal.timeout(30000)});
            if (!response.ok) throw new Error('Risk request failed.');
            outcome.risk_level=(await response.json()).risk_level;
          } catch {outcome.risk_error=true;}
        }
      } catch(error) {outcome.status=stopped ? 'cancelled' : /timed out/i.test(error.message) ? 'timeout' : 'failed';}
      outcome.elapsed_ms=Math.round(performance.now()-start); outcomes.push(outcome);
    }
    report=score(manifest,outcomes,{...identity,manifest_sha256:await digest(bytes),started_with_browser:navigator.userAgent,generated_at:new Date().toISOString(),risk_requested:evaluateRisk});
    el('report').textContent=JSON.stringify(report,null,2); el('download').disabled=false;
    el('status').textContent=`${stopped ? 'Stopped' : 'Finished'}: all ${manifest.records.length} manifest records included in the report.`;
  } catch(error) {el('status').textContent=error.message;}
  finally {el('run').disabled=false;el('cancel').disabled=true;}
};
el('download').onclick=()=>{
  const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download='vision-evaluation-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
