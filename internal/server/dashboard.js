const $=id=>document.getElementById(id)
$('token').value=''
$('tenant').value=sessionStorage.ciradarTenant||'default'

async function api(path,opt={}){
 const tenant=$('tenant').value.trim()||'default'
 sessionStorage.ciradarTenant=tenant
 opt.headers={...(opt.headers||{}),'X-CI-Radar-Tenant':tenant,'Content-Type':'application/json'}
 const r=await fetch(path,opt)
 if(!r.ok)throw new Error((await r.json().catch(()=>({error:r.statusText}))).error)
 return r.status===204?null:r.json()
}

async function secureLogin(){
 const token=$('token').value.trim(),tenant=$('tenant').value.trim()||'default'
 if(!token)throw new Error('Enter an admin token or API key')
 const r=await fetch('/auth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,tenant})})
 if(!r.ok)throw new Error((await r.json().catch(()=>({error:r.statusText}))).error)
 $('token').value=''
 await load()
}

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function pairs(o){return Object.entries(o||{}).sort((a,b)=>b[1]-a[1])}
function series(o){return Object.entries(o||{}).sort((a,b)=>a[0].localeCompare(b[0]))}
function pct(v){return Math.max(0,Math.min(100,Math.round(Number(v)||0)))}
function trend(id,data,suffix=''){
 const values=series(data),mx=Math.max(1,...values.map(x=>Number(x[1])))
 $(id).innerHTML=values.map(x=>`<span class="h${pct(Number(x[1])/mx*100)}" data-label="${esc(x[0])}: ${Number(x[1]).toFixed(suffix?2:0)} ${esc(suffix)}"></span>`).join('')||'<span class="muted">No data</span>'
}
function empty(cols,msg){return `<tr><td colspan="${cols}" class="empty">${esc(msg)}</td></tr>`}
function button(action,id,label){return `<button type="button" data-action="${esc(action)}" data-id="${esc(id)}">${esc(label)}</button>`}
function actionText(x){return (x.suggested_actions||[]).slice(0,3).map(a=>`<div><b>${esc(a.type)}</b> — ${esc(a.title)} <span class="muted">[${esc(a.risk)}]</span></div>`).join('')||'<span class="muted">—</span>'}

async function load(){
 try{
  $('error').textContent=''
  const [d,repos,notifs,tests]=await Promise.all([api('/api/v1/dashboard?range='+encodeURIComponent($('range').value)),api('/api/v1/repositories'),api('/api/v1/notifications/deliveries?limit=15'),api('/api/v1/tests?limit=50')])
  const f=d.diagnosis_feedback||{},u=d.usage||{},dm=d.dora||{}
  const cards=[['Diagnoses',d.total_analyses],['CI runs',u.runs||0],['Runner hours',(u.duration_hours||0).toFixed(1)],['Estimated cost',(u.estimated_cost||0).toFixed(2)+' '+(u.currency||'USD')],['Deployments',dm.deployments||0],['Change failure',(dm.change_failure_rate_percent||0).toFixed(1)+'%'],['External',d.external_analyses],['Code',d.code_analyses],['Open incidents',d.open_incidents],['Critical',d.critical_incidents],['Feedback precision',(f.precision_percent||0).toFixed(1)+'%'],['Tracked tests',d.test_cases_tracked||0],['Flaky tests',d.flaky_tests||0],['Quarantined',d.quarantined_tests||0],['Toolchain',d.toolchain_analyses],['Alert failures',d.notification_failures],['Mixed',d.mixed_analyses]]
  $('cards').innerHTML=cards.map(x=>`<div class="card"><span class="muted">${esc(x[0])}</span><b>${esc(x[1]??0)}</b></div>`).join('')
  $('dora').innerHTML=[['Deployment frequency/day',(dm.deployment_frequency_per_day||0).toFixed(2)],['Lead time (min)',(dm.lead_time_for_changes_minutes||0).toFixed(1)],['MTTR (min)',(dm.mean_time_to_restore_minutes||0).toFixed(1)],['Change failure rate',(dm.change_failure_rate_percent||0).toFixed(1)+'%']].map(x=>`<span>${esc(x[0])}</span><b>${esc(x[1])}</b>`).join('')
  trend('costtrend',d.daily_cost||{},u.currency||'USD');trend('analysistrend',d.daily_analyses||{});trend('incidenttrend',d.daily_incidents||{});trend('testtrend',d.daily_test_failures||{})
  $('categories').innerHTML=pairs(d.categories).map(x=>`<tr><td>${esc(x[0])}</td><td>${x[1]}</td></tr>`).join('')||empty(2,'No diagnoses')
  $('incidents').innerHTML=(d.recent_incidents||[]).filter(x=>x.state!=='resolved').map(x=>`<tr><td><b>${esc(x.title)}</b><div class="muted">${esc(x.provider)} · ${esc(x.severity)} · ${esc(x.attribution)}</div></td><td><span class="pill ${esc(x.state)}">${esc(x.state)}</span></td><td>${x.repository_count} repos<br>${x.occurrence_count} occurrences</td><td class="actions">${button('incident-ack',x.fingerprint,'Ack')}${button('incident-resolve',x.fingerprint,'Resolve')}</td></tr>`).join('')||empty(4,'No active incidents')
  $('analyses').innerHTML=(d.recent_analyses||[]).map(x=>`<tr><td>${new Date(x.created_at).toLocaleString()}<div class="muted">${esc(x.repository||'local')} · ${esc(x.job||x.workflow||'')}</div></td><td><span class="pill ${esc(x.attribution)}">${esc(x.attribution)}</span><div class="muted">${esc(x.category)}</div></td><td class="summary"><b>${esc(x.summary)}</b><div class="suggestions">${esc(x.decision_reason||'')}</div></td><td>${x.score}/100<div class="bar"><i class="p${pct(x.score)}"></i></div></td><td>${actionText(x)}</td><td class="actions">${button('feedback-correct',x.id,'✓')}${button('feedback-partial',x.id,'~')}${button('feedback-incorrect',x.id,'✕')}</td></tr>`).join('')||empty(6,'No diagnoses')
  $('tests').innerHTML=(tests.tests||[]).map(x=>`<tr><td><b>${esc(x.name)}</b><div class="muted">${esc([x.file,x.suite,x.class_name,x.parameters].filter(Boolean).join(' · '))}</div></td><td>${esc(x.repository)}</td><td>${x.total_runs}<div class="muted">${x.passes} pass · ${x.failures} fail</div></td><td>${Number(x.flake_score||0).toFixed(1)}<div class="muted">${esc(x.primary_flake_cause||'unknown')} ${(Number(x.cause_confidence||0)*100).toFixed(0)}%</div><div class="bar"><i class="p${pct(x.flake_score)}"></i></div></td><td><span class="pill ${esc(x.classification)}">${esc(x.classification)}</span>${x.quarantined?'<div class="muted">quarantined</div>':''}</td><td class="actions">${x.quarantined?button('unquarantine',x.test_key,'Restore'):button('quarantine',x.test_key,'Quarantine')}</td></tr>`).join('')||empty(6,'Upload test results to start test intelligence')
  $('repositories').innerHTML=(repos.repositories||[]).map(x=>`<tr><td>${esc(x.repository)}</td><td>${esc(x.team||x.owner||'—')}</td><td><span class="pill">${esc(x.criticality)}</span></td><td>${esc((x.notification_channels||[]).join(', ')||'default')}</td></tr>`).join('')||empty(4,'No repository profiles')
  $('deliveries').innerHTML=(notifs.deliveries||[]).map(x=>`<tr><td>${esc(x.channel)}</td><td><span class="pill ${esc(x.status)}">${esc(x.status)}</span></td><td>${x.attempts}</td><td>${esc(x.last_error||x.suppressed_reason||'—')}</td></tr>`).join('')||empty(4,'No deliveries')
 }catch(e){$('error').textContent=e.message}
}

async function incidentState(id,action){await api('/api/v1/incidents/'+encodeURIComponent(id)+'/'+action,{method:'POST',body:'{}'});await load()}
async function feedback(id,verdict){let actual='';if(verdict==='incorrect')actual=prompt('Actual cause: EXTERNAL, CODE, MIXED, TOOLCHAIN, or UNKNOWN','CODE')||'';await api('/api/v1/analyses/'+encodeURIComponent(id)+'/feedback',{method:'POST',body:JSON.stringify({verdict,actual_cause:actual})});await load()}
async function quarantine(key){const owner=prompt('Test owner','platform')||'platform',reason=prompt('Reason','Known flaky test under investigation')||'Known flaky test',expires=new Date(Date.now()+7*864e5).toISOString();await api('/api/v1/tests/'+encodeURIComponent(key)+'/quarantine',{method:'POST',body:JSON.stringify({owner,reason,expires_at:expires})});await load()}
async function unquarantine(key){await api('/api/v1/tests/'+encodeURIComponent(key)+'/quarantine',{method:'DELETE'});await load()}

async function act(button){
 const action=button.dataset.action,id=button.dataset.id
 if(action==='incident-ack')return incidentState(id,'acknowledge')
 if(action==='incident-resolve')return incidentState(id,'resolve')
 if(action==='feedback-correct')return feedback(id,'correct')
 if(action==='feedback-partial')return feedback(id,'partial')
 if(action==='feedback-incorrect')return feedback(id,'incorrect')
 if(action==='quarantine')return quarantine(id)
 if(action==='unquarantine')return unquarantine(id)
}

document.addEventListener('click',event=>{const button=event.target.closest('button[data-action]');if(!button)return;act(button).catch(error=>$('error').textContent=error.message)})
$('secure-login').addEventListener('click',()=>secureLogin().catch(error=>$('error').textContent=error.message))
$('sso-login').addEventListener('click',()=>location.assign('/auth/login?return_to=/'))
$('logout').addEventListener('click',()=>location.assign('/auth/logout'))
$('source').addEventListener('click',()=>location.assign('/source'))
$('refresh').addEventListener('click',()=>load())
$('range').addEventListener('change',()=>load())
setInterval(()=>load(),30000)
load()
