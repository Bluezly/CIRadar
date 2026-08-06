const $=id=>document.getElementById(id)
const state={dashboard:null,repositories:[],deliveries:[],tests:[],analyses:[],incidents:[],providers:[]}
$('tenant').value=sessionStorage.ciradarTenant||'default'

async function api(path,opt={}){
 const tenant=$('tenant').value.trim()||'default'
 sessionStorage.ciradarTenant=tenant
 opt.headers={...(opt.headers||{}),'X-CI-Radar-Tenant':tenant,'Content-Type':'application/json'}
 const response=await fetch(path,opt)
 if(!response.ok){const error=new Error((await response.json().catch(()=>({error:response.statusText}))).error||response.statusText);error.status=response.status;throw error}
 return response.status===204?null:response.json()
}

async function secureLogin(){
 const token=$('token').value.trim(),tenant=$('tenant').value.trim()||'default'
 if(!token)throw new Error('Enter an admin token or API key')
 const response=await fetch('/auth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,tenant})})
 if(!response.ok)throw new Error((await response.json().catch(()=>({error:response.statusText}))).error||response.statusText)
 $('token').value=''
 await load()
}

function esc(value){return String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]))}
function text(value){return String(value??'').toLowerCase()}
function empty(columns,message){return `<tr><td colspan="${columns}" class="empty">${esc(message)}</td></tr>`}
function button(action,id,label,kind=''){return `<button type="button" class="compact ${esc(kind)}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(label)}</button>`}
function fmtDate(value){return value?new Date(value).toLocaleString():'—'}
function pct(value){return Math.max(0,Math.min(100,Math.round(Number(value)||0)))}
function evidenceValue(item){const explicit=Number(item.evidence_strength);if(explicit>0)return explicit;return Math.abs(Number(item.score||item.externality_score||0))}
function externalityValue(item){const explicit=Number(item.externality_score);if(explicit!==0)return explicit;return Number(item.score||0)}
function scoreBar(value){return `<div class="score"><span>${Number(value||0).toFixed(0)}</span><div class="bar"><i class="p${pct(value)}"></i></div></div>`}
function pill(value){return `<span class="pill ${esc(value)}">${esc(value||'unknown')}</span>`}
function pairs(value){return Object.entries(value||{}).sort((a,b)=>Number(b[1])-Number(a[1]))}
function series(value){return Object.entries(value||{}).sort((a,b)=>a[0].localeCompare(b[0]))}

function svgChart(id,data,unit=''){
 const points=series(data),container=$(id)
 if(!points.length){container.innerHTML='<div class="chart-empty">No data in this range</div>';return}
 const values=points.map(item=>Number(item[1])||0),max=Math.max(1,...values),min=Math.min(0,...values),width=720,height=220,pad=28
 const x=index=>pad+(width-pad*2)*(points.length===1?.5:index/(points.length-1))
 const y=value=>height-pad-(height-pad*2)*(value-min)/(max-min||1)
 const poly=points.map((item,index)=>`${x(index)},${y(values[index])}`).join(' ')
 const area=`${pad},${height-pad} ${poly} ${width-pad},${height-pad}`
 const circles=points.map((item,index)=>`<circle cx="${x(index)}" cy="${y(values[index])}" r="4"><title>${esc(item[0])}: ${values[index].toFixed(unit?2:0)} ${esc(unit)}</title></circle>`).join('')
 const labels=[points[0],points[Math.floor((points.length-1)/2)],points[points.length-1]].filter((item,index,array)=>array.findIndex(other=>other[0]===item[0])===index).map(item=>{const index=points.findIndex(point=>point[0]===item[0]);return `<text x="${x(index)}" y="${height-5}" text-anchor="middle">${esc(item[0].slice(5))}</text>`}).join('')
 container.innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img"><defs><linearGradient id="grad-${esc(id)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7aa2ff" stop-opacity=".38"/><stop offset="1" stop-color="#7aa2ff" stop-opacity="0"/></linearGradient></defs><polygon points="${area}" fill="url(#grad-${esc(id)})"/><polyline points="${poly}" fill="none" stroke="#8eb2ff" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>${circles}${labels}</svg>`
}

function renderCards(d){
 const feedback=d.diagnosis_feedback||{},usage=d.usage||{},dora=d.dora||{}
 const cards=[['Diagnoses',d.total_analyses,'all analyzed failures'],['Open incidents',d.open_incidents,'currently active'],['Critical incidents',d.critical_incidents,'requires attention'],['External',d.external_analyses,'likely outside code'],['Code failures',d.code_analyses,'likely project changes'],['Feedback precision',(feedback.precision_percent||0).toFixed(1)+'%','confirmed diagnoses'],['CI runs',usage.runs||0,'recorded executions'],['Runner hours',(usage.duration_hours||0).toFixed(1),'selected range'],['Estimated cost',(usage.estimated_cost||0).toFixed(2)+' '+(usage.currency||'USD'),'configured rates'],['Deployments',dora.deployments||0,'selected range'],['Change failure',(dora.change_failure_rate_percent||0).toFixed(1)+'%','DORA metric'],['Flaky tests',d.flaky_tests||0,'tracked instability']]
 $('cards').innerHTML=cards.map(item=>`<article class="card"><span>${esc(item[0])}</span><b>${esc(item[1]??0)}</b><small>${esc(item[2])}</small></article>`).join('')
}

function renderOverview(d){
 renderCards(d)
 const dm=d.dora||{},usage=d.usage||{}
 $('dora').innerHTML=[['Deployment frequency/day',(dm.deployment_frequency_per_day||0).toFixed(2)],['Lead time for changes',(dm.lead_time_for_changes_minutes||0).toFixed(1)+' min'],['Mean time to restore',(dm.mean_time_to_restore_minutes||0).toFixed(1)+' min'],['Change failure rate',(dm.change_failure_rate_percent||0).toFixed(1)+'%']].map(item=>`<span>${esc(item[0])}</span><b>${esc(item[1])}</b>`).join('')
 svgChart('costtrend',d.daily_cost||{},usage.currency||'USD');svgChart('analysistrend',d.daily_analyses||{});svgChart('incidenttrend',d.daily_incidents||{});svgChart('testtrend',d.daily_test_failures||{})
 const categories=pairs(d.categories),max=Math.max(1,...categories.map(item=>Number(item[1])))
 $('category-bars').innerHTML=categories.map(item=>`<div><span>${esc(item[0])}</span><div class="category-track"><i class="p${pct(Number(item[1])/max*100)}"></i></div><b>${esc(item[1])}</b></div>`).join('')||'<div class="chart-empty">No diagnoses</div>'
 $('incident-preview').innerHTML=state.incidents.filter(item=>item.state!=='resolved').slice(0,8).map(incidentRowPreview).join('')||empty(4,'No active incidents')
}

function incidentRowPreview(item){return `<tr data-open="incident" data-id="${esc(item.fingerprint)}"><td><b>${esc(item.title)}</b><small>${esc(item.provider)} · ${esc(item.severity)} · ${esc(item.attribution)}</small></td><td>${pill(item.state)}</td><td>${Number(item.repository_count||0)} repos<br>${Number(item.occurrence_count||0)} events</td><td class="actions">${button('incident-ack',item.fingerprint,'Ack')}${button('incident-resolve',item.fingerprint,'Resolve','danger')}</td></tr>`}
function incidentRow(item){return `<tr data-open="incident" data-id="${esc(item.fingerprint)}"><td><b>${esc(item.title)}</b><small>${esc(item.attribution)} · ${esc(item.category||'')}</small></td><td>${esc(item.provider||'—')}</td><td>${pill(item.state)}</td><td>${Number(item.repository_count||0)}</td><td>${Number(item.occurrence_count||0)}</td><td>${fmtDate(item.last_seen)}</td><td class="actions">${button('incident-ack',item.fingerprint,'Ack')}${button('incident-resolve',item.fingerprint,'Resolve','danger')}</td></tr>`}
function analysisRow(item){return `<tr data-open="analysis" data-id="${esc(item.id)}"><td>${fmtDate(item.created_at)}</td><td><b>${esc(item.repository||'local')}</b><small>${esc(item.workflow||'')} · ${esc(item.job||'')}</small></td><td>${pill(item.attribution)}<small>${esc(item.category)}</small></td><td class="summary"><b>${esc(item.summary)}</b><small>${esc(item.decision_reason||'')}</small></td><td>${scoreBar(evidenceValue(item))}</td><td class="actions">${button('feedback-correct',item.id,'✓')}${button('feedback-partial',item.id,'~')}${button('feedback-incorrect',item.id,'✕','danger')}</td></tr>`}
function testRow(item){return `<tr data-open="test" data-id="${esc(item.test_key)}"><td><b>${esc(item.name)}</b><small>${esc([item.file,item.suite,item.class_name,item.parameters].filter(Boolean).join(' · '))}</small></td><td>${esc(item.repository)}</td><td>${Number(item.executed_runs||0)} executed<small>${Number(item.passes||0)} pass · ${Number(item.failures||0)} fail · ${Number(item.skipped||0)} skip</small></td><td>${scoreBar(item.flake_score)}</td><td>${esc(item.primary_flake_cause||'unknown')}<small>${(Number(item.cause_confidence||0)*100).toFixed(0)}% confidence</small></td><td>${pill(item.classification)}${item.quarantined?'<small>quarantined</small>':''}</td><td class="actions">${item.quarantined?button('unquarantine',item.test_key,'Restore'):button('quarantine',item.test_key,'Quarantine')}</td></tr>`}

function renderIncidentTable(){
 const query=text($('incident-search').value),filterState=$('incident-state').value,filterSeverity=$('incident-severity').value
 const items=state.incidents.filter(item=>(!filterState||item.state===filterState)&&(!filterSeverity||item.severity===filterSeverity)&&(!query||text([item.title,item.provider,item.attribution,item.category,(item.repositories||[]).join(' ')].join(' ')).includes(query)))
 $('incident-count').textContent=`${items.length} incidents`; $('incident-table').innerHTML=items.map(incidentRow).join('')||empty(7,'No matching incidents')
}
function renderAnalysisFilters(){
 const category=$('analysis-category').value,provider=$('analysis-provider').value
 const categories=[...new Set(state.analyses.map(item=>item.category).filter(Boolean))].sort(),providers=[...new Set(state.analyses.map(item=>item.provider).filter(Boolean))].sort()
 $('analysis-category').innerHTML='<option value="">All categories</option>'+categories.map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join('');$('analysis-category').value=category
 $('analysis-provider').innerHTML='<option value="">All providers</option>'+providers.map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join('');$('analysis-provider').value=provider
}
function renderAnalysisTable(){
 const query=text($('analysis-search').value),attribution=$('analysis-attribution').value,category=$('analysis-category').value,provider=$('analysis-provider').value
 const items=state.analyses.filter(item=>(!attribution||item.attribution===attribution)&&(!category||item.category===category)&&(!provider||item.provider===provider)&&(!query||text([item.repository,item.workflow,item.job,item.summary,item.decision_reason].join(' ')).includes(query)))
 $('analysis-count').textContent=`${items.length} diagnoses`; $('analysis-table').innerHTML=items.map(analysisRow).join('')||empty(6,'No matching diagnoses')
}
function renderTestTable(){
 const query=text($('test-search').value),classification=$('test-state').value,cause=$('test-cause').value
 const items=state.tests.filter(item=>(!classification||item.classification===classification)&&(!cause||item.primary_flake_cause===cause)&&(!query||text([item.name,item.repository,item.file,item.suite,item.class_name].join(' ')).includes(query)))
 $('test-count').textContent=`${items.length} tests`; $('test-table').innerHTML=items.map(testRow).join('')||empty(7,'No matching tests')
}
function renderOperations(){
 $('repositories').innerHTML=state.repositories.map(item=>`<tr><td><b>${esc(item.repository)}</b></td><td>${esc(item.team||item.owner||'—')}</td><td>${pill(item.criticality)}</td><td>${esc((item.notification_channels||[]).join(', ')||'default')}</td></tr>`).join('')||empty(4,'No repository profiles')
 $('deliveries').innerHTML=state.deliveries.map(item=>`<tr><td>${esc(item.channel)}</td><td>${pill(item.status)}</td><td>${Number(item.attempts||0)}</td><td>${esc(item.last_error||item.suppressed_reason||'—')}</td></tr>`).join('')||empty(4,'No deliveries')
 $('provider-count').textContent=`${state.providers.length} configured`; $('providers').innerHTML=state.providers.map(provider=>`<div class="provider-card"><span class="provider-dot"></span><b>${esc(provider)}</b><small>webhook ingestion enabled</small></div>`).join('')||'<div class="chart-empty">No connector enabled</div>'
}

function switchTab(name){document.querySelectorAll('.view').forEach(view=>view.classList.toggle('active',view.id===name));document.querySelectorAll('[data-tab]').forEach(button=>button.classList.toggle('active',button.dataset.tab===name));history.replaceState(null,'','#'+name)}
function openDrawer(kind,item){
 $('drawer-kind').textContent=kind.toUpperCase();$('drawer-title').textContent=item.title||item.summary||item.name||item.id||item.fingerprint
 let body=''
 if(kind==='analysis')body=analysisDetail(item)
 if(kind==='incident')body=incidentDetail(item)
 if(kind==='test')body=testDetail(item)
 $('drawer-body').innerHTML=body;$('drawer').classList.add('open');$('drawer').setAttribute('aria-hidden','false');$('backdrop').hidden=false
}
function closeDrawer(){$('drawer').classList.remove('open');$('drawer').setAttribute('aria-hidden','true');$('backdrop').hidden=true}
function keyValues(values){return `<dl>${values.filter(item=>item[1]!==undefined&&item[1]!==null&&item[1]!=='').map(item=>`<dt>${esc(item[0])}</dt><dd>${esc(item[1])}</dd>`).join('')}</dl>`}
function analysisDetail(item){
 const evidence=(item.human_evidence||[]).map(value=>`<li>${esc(value)}</li>`).join('')||'<li>No evidence list recorded</li>',actions=(item.suggested_actions||[]).map(action=>`<article class="recommendation"><header><b>${esc(action.title)}</b>${pill(action.risk)}</header><p>${esc(action.description||'')}</p><small>${esc(action.type||'')}</small></article>`).join('')||'<p class="muted">No action recommendation</p>'
 return `${keyValues([['Repository',item.repository],['Workflow',item.workflow],['Job',item.job],['Provider',item.provider],['Category',item.category],['Attribution',item.attribution],['Evidence strength',evidenceValue(item)],['Externality score',externalityValue(item)],['External evidence',item.external_evidence_score],['Code evidence',item.code_evidence_score],['Fingerprint',item.fingerprint],['Created',fmtDate(item.created_at)]])}<h3>Evidence</h3><ul class="evidence">${evidence}</ul><h3>Decision</h3><p>${esc(item.decision_reason||item.summary)}</p><h3>Redacted excerpt</h3><pre>${esc(item.excerpt||item.redacted_excerpt||'Raw logs are not stored by default.')}</pre><h3>Recommended actions</h3>${actions}<div class="drawer-actions">${button('github-issue',item.id,'Open GitHub issue')}</div>`
}
function incidentDetail(item){return `${keyValues([['Provider',item.provider],['Category',item.category],['Attribution',item.attribution],['Severity',item.severity],['State',item.state],['Repositories',item.repository_count],['Occurrences',item.occurrence_count],['First seen',fmtDate(item.first_seen)],['Last seen',fmtDate(item.last_seen)],['Fingerprint',item.fingerprint]])}<h3>Affected repositories</h3><ul class="evidence">${(item.repositories||[]).map(repo=>`<li>${esc(repo)}</li>`).join('')||'<li>Not recorded</li>'}<\/ul><div class="drawer-actions">${button('incident-ack',item.fingerprint,'Acknowledge')}${button('incident-resolve',item.fingerprint,'Resolve','danger')}</div>`}
function testDetail(item){return `${keyValues([['Repository',item.repository],['Framework',item.framework],['File',item.file],['Suite',item.suite],['Class',item.class_name],['Observations',item.total_runs],['Executed',item.executed_runs],['Skipped',item.skipped],['Passes',item.passes],['Failures',item.failures],['Failure rate',(Number(item.failure_rate||0)*100).toFixed(1)+'%'],['95% interval',(Number(item.failure_rate_low||0)*100).toFixed(1)+'–'+(Number(item.failure_rate_high||0)*100).toFixed(1)+'%'],['History confidence',(Number(item.history_confidence||0)*100).toFixed(0)+'%'],['Rerun recoveries',item.rerun_recoveries],['Compute minutes lost',Number(item.estimated_compute_minutes_lost||0).toFixed(1)],['Engineering minutes lost',Number(item.estimated_engineering_minutes_lost||0).toFixed(1)],['Flake score',Number(item.flake_score||0).toFixed(1)],['Flake probability',Number(item.flake_probability||0).toFixed(1)],['Classification',item.classification],['Likely cause',item.primary_flake_cause],['Cause confidence',(Number(item.cause_confidence||0)*100).toFixed(0)+'%'],['Last seen',fmtDate(item.last_seen)]])}<h3>Quarantine</h3><p>${item.quarantined?'This test is currently quarantined.':'This test blocks CI when it fails.'}</p><div class="drawer-actions">${item.quarantined?button('unquarantine',item.test_key,'Restore'):button('quarantine',item.test_key,'Quarantine')}</div>`}

async function load(){
 try{
  $('error').textContent=''
  const range=encodeURIComponent($('range').value)
  const [dashboard,repositories,deliveries,tests,analyses,incidents,status]=await Promise.all([api('/api/v1/dashboard?range='+range),api('/api/v1/repositories'),api('/api/v1/notifications/deliveries?limit=100'),api('/api/v1/tests?limit=500'),api('/api/v1/analyses?limit=500'),api('/api/v1/incidents?limit=500'),api('/api/v1/status')])
  state.dashboard=dashboard;state.repositories=repositories.repositories||[];state.deliveries=deliveries.deliveries||[];state.tests=tests.tests||[];state.analyses=analyses.analyses||analyses||[];state.incidents=incidents.incidents||incidents||[];state.providers=status.connectors_enabled||[]
  renderOverview(dashboard);renderIncidentTable();renderAnalysisFilters();renderAnalysisTable();renderTestTable();renderOperations()
 }catch(error){$('error').textContent=error.message}
}

async function incidentState(id,action){await api('/api/v1/incidents/'+encodeURIComponent(id)+'/'+action,{method:'POST',body:'{}'});closeDrawer();await load()}
async function feedback(id,verdict){let actual='';if(verdict==='incorrect')actual=prompt('Actual cause: EXTERNAL, CODE, MIXED, TOOLCHAIN, or UNKNOWN','CODE')||'';await api('/api/v1/analyses/'+encodeURIComponent(id)+'/feedback',{method:'POST',body:JSON.stringify({verdict,actual_cause:actual})});await load()}
async function quarantine(key){const owner=prompt('Test owner','platform')||'platform',reason=prompt('Reason','Known flaky test under investigation')||'Known flaky test',expires=new Date(Date.now()+7*864e5).toISOString();await api('/api/v1/tests/'+encodeURIComponent(key)+'/quarantine',{method:'POST',body:JSON.stringify({owner,reason,expires_at:expires})});closeDrawer();await load()}
async function unquarantine(key){await api('/api/v1/tests/'+encodeURIComponent(key)+'/quarantine',{method:'DELETE'});closeDrawer();await load()}
async function githubIssue(id){
 let result
 try{result=await api('/api/v1/analyses/'+encodeURIComponent(id)+'/github-issue')}catch(error){if(error.status!==404)throw error;result=await api('/api/v1/analyses/'+encodeURIComponent(id)+'/github-issue',{method:'POST',body:'{}'})}
 const url=result?.issue?.html_url||result?.link?.url
 if(url)window.open(url,'_blank','noopener,noreferrer')
}
async function act(button){const action=button.dataset.action,id=button.dataset.id;if(action==='incident-ack')return incidentState(id,'acknowledge');if(action==='incident-resolve')return incidentState(id,'resolve');if(action==='feedback-correct')return feedback(id,'correct');if(action==='feedback-partial')return feedback(id,'partial');if(action==='feedback-incorrect')return feedback(id,'incorrect');if(action==='quarantine')return quarantine(id);if(action==='unquarantine')return unquarantine(id);if(action==='github-issue')return githubIssue(id)}

function handleOpen(row){const kind=row.dataset.open,id=row.dataset.id;if(kind==='analysis'){const item=state.analyses.find(value=>value.id===id);if(item)openDrawer(kind,item)}if(kind==='incident'){const item=state.incidents.find(value=>value.fingerprint===id);if(item)openDrawer(kind,item)}if(kind==='test'){const item=state.tests.find(value=>value.test_key===id);if(item)openDrawer(kind,item)}}

document.addEventListener('click',event=>{const action=event.target.closest('button[data-action]');if(action){event.stopPropagation();act(action).catch(error=>$('error').textContent=error.message);return}const tab=event.target.closest('[data-tab]');if(tab){switchTab(tab.dataset.tab);return}const jump=event.target.closest('[data-tab-jump]');if(jump){switchTab(jump.dataset.tabJump);return}const row=event.target.closest('tr[data-open]');if(row)handleOpen(row)})
for(const id of ['incident-search','incident-state','incident-severity'])$(id).addEventListener('input',renderIncidentTable)
for(const id of ['analysis-search','analysis-attribution','analysis-category','analysis-provider'])$(id).addEventListener('input',renderAnalysisTable)
for(const id of ['test-search','test-state','test-cause'])$(id).addEventListener('input',renderTestTable)
$('drawer-close').addEventListener('click',closeDrawer);$('backdrop').addEventListener('click',closeDrawer)
$('secure-login').addEventListener('click',()=>secureLogin().catch(error=>$('error').textContent=error.message));$('sso-login').addEventListener('click',()=>location.assign('/auth/login?return_to=/'));$('logout').addEventListener('click',()=>location.assign('/auth/logout'));$('refresh').addEventListener('click',load);$('range').addEventListener('change',load)
window.addEventListener('keydown',event=>{if(event.key==='Escape')closeDrawer()})
switchTab(location.hash.slice(1)||'overview');setInterval(load,30000);load()
