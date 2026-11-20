const form=document.querySelector('#scenario-form'),decision=document.querySelector('#decision'),raw=document.querySelector('#raw');
const esc=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
let data;
try{const response=await fetch('assets/demo-results.json');if(!response.ok)throw Error('Engine fixture unavailable');data=await response.json();render();}catch(e){decision.textContent='The recorded engine results could not load. Open the operator console or reload this page.';}
form.addEventListener('change',render);
function render(){if(!data)return;const action=document.querySelector('#action').value,network=document.querySelector('#network').value,s=data.scenarios.find(x=>x.action===action&&x.network===network),d=s.output;decision.innerHTML=`<div class="decision-top"><h3 class="${d.decision?'green':'denied'}">${d.decision?'Allow':'Deny'}</h3><p>${esc(action)} CASE-7 · ${esc(network)} network</p></div><p>${d.decision?'Every applicable control passed.':'At least one applicable control refused this request.'}</p><ol class="trace">${d.trace.map(t=>`<li><b class="${t.outcome==='deny'?'denied':'green'}">${esc(t.outcome)}</b><div><code>${esc(t.rule)}</code><p>${esc(t.reason)}</p>${t.path?`<p>${esc(t.path.join(' → '))}</p>`:''}</div></li>`).join('')}</ol>`;raw.textContent=JSON.stringify({request:s.request,response:s.output},null,2);}
const local=['127.0.0.1','localhost','[::1]'].includes(location.hostname);
if(!local){document.querySelectorAll('.local-console').forEach(x=>x.hidden=true);document.querySelector('[data-remote-console]').hidden=false;}
document.querySelectorAll('video').forEach(v=>v.addEventListener('play',()=>document.querySelectorAll('video').forEach(other=>{if(other!==v)other.pause();})));
