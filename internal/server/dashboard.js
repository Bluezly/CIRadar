const $ = id => document.getElementById(id)

const state = {
 dashboard: null,
 repositories: [],
 deliveries: [],
 tests: [],
 analyses: [],
 incidents: [],
 providers: [],
 loading: false
}

const pageMeta = {
 overview: ['Overview', 'CI health across the selected period.'],
 incidents: ['Incidents', 'Correlated failures that need ownership and resolution.'],
 diagnoses: ['Diagnoses', 'Evidence and attribution for analyzed CI failures.'],
 tests: ['Tests', 'History, instability and quarantine state.'],
 operations: ['Operations', 'Repository routing, delivery health and connected providers.']
}

let actionContext = null

$('tenant').value = sessionStorage.ciradarTenant || 'default'

async function api(path, options = {}) {
 const tenant = $('tenant').value.trim() || 'default'
 sessionStorage.ciradarTenant = tenant
 options.headers = {
  ...(options.headers || {}),
  'X-CI-Radar-Tenant': tenant,
  'Content-Type': 'application/json'
 }
 const response = await fetch(path, options)
 if (!response.ok) {
  const payload = await response.json().catch(() => ({ error: response.statusText }))
  const error = new Error(payload.error || response.statusText)
  error.status = response.status
  throw error
 }
 return response.status === 204 ? null : response.json()
}

async function secureLogin() {
 const token = $('token').value.trim()
 const tenant = $('tenant').value.trim() || 'default'
 if (!token) throw new Error('Enter an admin token or API key.')
 const response = await fetch('/auth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token, tenant })
 })
 if (!response.ok) {
  const payload = await response.json().catch(() => ({ error: response.statusText }))
  throw new Error(payload.error || response.statusText)
 }
 $('token').value = ''
 $('session-panel')?.removeAttribute('open')
 await load(true)
}

function esc(value) {
 return String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
 }[character]))
}

function slug(value) {
 return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]+/g, '_')
}

function text(value) {
 return String(value ?? '').toLowerCase()
}

function empty(columns, message) {
 return `<tr><td colspan="${columns}" class="empty">${esc(message)}</td></tr>`
}

function button(action, id, label, kind = '') {
 return `<button type="button" class="compact ${esc(kind)}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(label)}</button>`
}

function fmtDate(value) {
 return value ? new Date(value).toLocaleString() : '—'
}

function pct(value) {
 return Math.max(0, Math.min(100, Math.round(Number(value) || 0)))
}

function evidenceValue(item) {
 const explicit = Number(item.evidence_strength)
 return explicit > 0 ? explicit : Math.abs(Number(item.score || item.externality_score || 0))
}

function externalityValue(item) {
 const explicit = Number(item.externality_score)
 return explicit !== 0 ? explicit : Number(item.score || 0)
}

function scoreBar(value) {
 const score = pct(value)
 return `<div class="score"><span>${Number(value || 0).toFixed(0)}</span><progress max="100" value="${score}" aria-label="Score ${score} out of 100"></progress></div>`
}

function pill(value) {
 return `<span class="tag tag-${slug(value)}">${esc(String(value || 'unknown').replaceAll('_', ' '))}</span>`
}

function pairs(value) {
 return Object.entries(value || {}).sort((left, right) => Number(right[1]) - Number(left[1]))
}

function series(value) {
 return Object.entries(value || {}).sort((left, right) => left[0].localeCompare(right[0]))
}

function setConnection(label, mode) {
 const element = $('connection-state')
 element.textContent = label
 element.className = `connection-state ${mode || ''}`.trim()
}

function setLoading(loading) {
 state.loading = loading
 document.body.classList.toggle('loading', loading)
 $('refresh').disabled = loading
}

function setError(message = '') {
 $('error').textContent = message
}

function svgChart(id, data, unit = '') {
 const points = series(data)
 const container = $(id)
 if (!points.length) {
  container.innerHTML = '<div class="chart-empty">No data in this period.</div>'
  return
 }
 const values = points.map(item => Number(item[1]) || 0)
 const maximum = Math.max(1, ...values)
 const minimum = Math.min(0, ...values)
 const width = 720
 const height = 210
 const horizontalPadding = 34
 const verticalPadding = 24
 const x = index => horizontalPadding + (width - horizontalPadding * 2) * (points.length === 1 ? 0.5 : index / (points.length - 1))
 const y = value => height - verticalPadding - (height - verticalPadding * 2) * (value - minimum) / (maximum - minimum || 1)
 const polyline = points.map((item, index) => `${x(index)},${y(values[index])}`).join(' ')
 const grid = [0, 0.5, 1].map(position => {
  const gridY = verticalPadding + (height - verticalPadding * 2) * position
  return `<line class="gridline" x1="${horizontalPadding}" y1="${gridY}" x2="${width - horizontalPadding}" y2="${gridY}"></line>`
 }).join('')
 const circles = points.map((item, index) => `<circle cx="${x(index)}" cy="${y(values[index])}" r="3"><title>${esc(item[0])}: ${values[index].toFixed(unit ? 2 : 0)} ${esc(unit)}</title></circle>`).join('')
 const labelPoints = [points[0], points[Math.floor((points.length - 1) / 2)], points[points.length - 1]].filter((item, index, array) => array.findIndex(other => other[0] === item[0]) === index)
 const labels = labelPoints.map(item => {
  const index = points.findIndex(point => point[0] === item[0])
  return `<text x="${x(index)}" y="${height - 4}" text-anchor="middle">${esc(item[0].slice(5))}</text>`
 }).join('')
 container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img">${grid}<polyline class="line" points="${polyline}"></polyline>${circles}${labels}</svg>`
}

function renderCards(dashboard) {
 const feedback = dashboard.diagnosis_feedback || {}
 const usage = dashboard.usage || {}
 const cards = [
  ['Open incidents', dashboard.open_incidents, 'Needs attention'],
  ['Critical', dashboard.critical_incidents, 'Highest severity'],
  ['Diagnoses', dashboard.total_analyses, 'Failures analyzed'],
  ['Flaky tests', dashboard.flaky_tests, 'Tracked instability'],
  ['CI runs', usage.runs || 0, 'Recorded executions'],
  ['Runner hours', Number(usage.duration_hours || 0).toFixed(1), 'Selected period'],
  ['Estimated cost', `${Number(usage.estimated_cost || 0).toFixed(2)} ${usage.currency || 'USD'}`, 'Configured rates'],
  ['Precision', `${Number(feedback.precision_percent || 0).toFixed(1)}%`, 'Confirmed feedback']
 ]
 $('cards').innerHTML = cards.map(item => `<article class="metric"><span>${esc(item[0])}</span><b>${esc(item[1] ?? 0)}</b><small>${esc(item[2])}</small></article>`).join('')
}

function renderOverview(dashboard) {
 renderCards(dashboard)
 const dora = dashboard.dora || {}
 const usage = dashboard.usage || {}
 const doraMetrics = [
  ['Deployment frequency / day', Number(dora.deployment_frequency_per_day || 0).toFixed(2)],
  ['Lead time for changes', `${Number(dora.lead_time_for_changes_minutes || 0).toFixed(1)} min`],
  ['Mean time to restore', `${Number(dora.mean_time_to_restore_minutes || 0).toFixed(1)} min`],
  ['Change failure rate', `${Number(dora.change_failure_rate_percent || 0).toFixed(1)}%`]
 ]
 $('dora').innerHTML = doraMetrics.map(item => `<span>${esc(item[0])}</span><b>${esc(item[1])}</b>`).join('')
 svgChart('costtrend', dashboard.daily_cost || {}, usage.currency || 'USD')
 svgChart('analysistrend', dashboard.daily_analyses || {})
 svgChart('incidenttrend', dashboard.daily_incidents || {})
 svgChart('testtrend', dashboard.daily_test_failures || {})
 const categories = pairs(dashboard.categories)
 const maximum = Math.max(1, ...categories.map(item => Number(item[1])))
 $('category-bars').innerHTML = categories.map(item => {
  const share = pct(Number(item[1]) / maximum * 100)
  return `<div><span>${esc(item[0])}</span><progress max="100" value="${share}" aria-label="${esc(item[0])}: ${share}% of the largest category"></progress><b>${esc(item[1])}</b></div>`
 }).join('') || '<div class="chart-empty">No diagnoses in this period.</div>'
 $('incident-preview').innerHTML = state.incidents.filter(item => item.state !== 'resolved').slice(0, 8).map(incidentRowPreview).join('') || empty(4, 'No active incidents.')
}

function incidentRowPreview(item) {
 return `<tr data-open="incident" data-id="${esc(item.fingerprint)}"><td><b>${esc(item.title)}</b><small>${esc(item.provider)} · ${esc(item.severity)} · ${esc(item.attribution)}</small></td><td>${pill(item.state)}</td><td>${Number(item.repository_count || 0)} repos<small>${Number(item.occurrence_count || 0)} events</small></td><td class="actions">${button('incident-ack', item.fingerprint, 'Acknowledge')}${button('incident-resolve', item.fingerprint, 'Resolve', 'danger')}</td></tr>`
}

function incidentRow(item) {
 return `<tr data-open="incident" data-id="${esc(item.fingerprint)}"><td><b>${esc(item.title)}</b><small>${esc(item.attribution)} · ${esc(item.category || '')}</small></td><td>${esc(item.provider || '—')}</td><td>${pill(item.state)}</td><td>${Number(item.repository_count || 0)}</td><td>${Number(item.occurrence_count || 0)}</td><td>${fmtDate(item.last_seen)}</td><td class="actions">${button('incident-ack', item.fingerprint, 'Acknowledge')}${button('incident-resolve', item.fingerprint, 'Resolve', 'danger')}</td></tr>`
}

function analysisRow(item) {
 return `<tr data-open="analysis" data-id="${esc(item.id)}"><td>${fmtDate(item.created_at)}</td><td><b>${esc(item.repository || 'local')}</b><small>${esc(item.workflow || '')} · ${esc(item.job || '')}</small></td><td>${pill(item.attribution)}<small>${esc(item.category)}</small></td><td class="summary"><b>${esc(item.summary)}</b><small>${esc(item.decision_reason || '')}</small></td><td>${scoreBar(evidenceValue(item))}</td><td class="actions">${button('feedback-correct', item.id, 'Correct')}${button('feedback-partial', item.id, 'Partial')}${button('feedback-incorrect', item.id, 'Wrong', 'danger')}</td></tr>`
}

function testRow(item) {
 const detail = [item.file, item.suite, item.class_name, item.parameters].filter(Boolean).join(' · ')
 return `<tr data-open="test" data-id="${esc(item.test_key)}"><td><b>${esc(item.name)}</b><small>${esc(detail)}</small></td><td>${esc(item.repository)}</td><td>${Number(item.executed_runs || 0)} executed<small>${Number(item.passes || 0)} pass · ${Number(item.failures || 0)} fail · ${Number(item.skipped || 0)} skip</small></td><td>${scoreBar(item.flake_score)}</td><td>${esc(item.primary_flake_cause || 'unknown')}<small>${(Number(item.cause_confidence || 0) * 100).toFixed(0)}% confidence</small></td><td>${pill(item.classification)}${item.quarantined ? '<small>Quarantined</small>' : ''}</td><td class="actions">${item.quarantined ? button('unquarantine', item.test_key, 'Restore') : button('quarantine', item.test_key, 'Quarantine')}</td></tr>`
}

function renderIncidentTable() {
 const query = text($('incident-search').value)
 const filterState = $('incident-state').value
 const filterSeverity = $('incident-severity').value
 const items = state.incidents.filter(item => (!filterState || item.state === filterState) && (!filterSeverity || item.severity === filterSeverity) && (!query || text([item.title, item.provider, item.attribution, item.category, (item.repositories || []).join(' ')].join(' ')).includes(query)))
 $('incident-count').textContent = `${items.length} shown`
 $('incident-table').innerHTML = items.map(incidentRow).join('') || empty(7, 'No incidents match these filters.')
}

function renderAnalysisFilters() {
 const selectedCategory = $('analysis-category').value
 const selectedProvider = $('analysis-provider').value
 const categories = [...new Set(state.analyses.map(item => item.category).filter(Boolean))].sort()
 const providers = [...new Set(state.analyses.map(item => item.provider).filter(Boolean))].sort()
 $('analysis-category').innerHTML = '<option value="">All categories</option>' + categories.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('')
 $('analysis-provider').innerHTML = '<option value="">All providers</option>' + providers.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('')
 $('analysis-category').value = selectedCategory
 $('analysis-provider').value = selectedProvider
}

function renderAnalysisTable() {
 const query = text($('analysis-search').value)
 const attribution = $('analysis-attribution').value
 const category = $('analysis-category').value
 const provider = $('analysis-provider').value
 const items = state.analyses.filter(item => (!attribution || item.attribution === attribution) && (!category || item.category === category) && (!provider || item.provider === provider) && (!query || text([item.repository, item.workflow, item.job, item.summary, item.decision_reason].join(' ')).includes(query)))
 $('analysis-count').textContent = `${items.length} shown`
 $('analysis-table').innerHTML = items.map(analysisRow).join('') || empty(6, 'No diagnoses match these filters.')
}

function renderTestTable() {
 const query = text($('test-search').value)
 const classification = $('test-state').value
 const cause = $('test-cause').value
 const items = state.tests.filter(item => (!classification || item.classification === classification) && (!cause || item.primary_flake_cause === cause) && (!query || text([item.name, item.repository, item.file, item.suite, item.class_name].join(' ')).includes(query)))
 $('test-count').textContent = `${items.length} shown`
 $('test-table').innerHTML = items.map(testRow).join('') || empty(7, 'No tests match these filters.')
}

function renderOperations() {
 $('repositories').innerHTML = state.repositories.map(item => `<tr><td><b>${esc(item.repository)}</b></td><td>${esc(item.team || item.owner || '—')}</td><td>${pill(item.criticality)}</td><td>${esc((item.notification_channels || []).join(', ') || 'default')}</td></tr>`).join('') || empty(4, 'No repository profiles.')
 $('deliveries').innerHTML = state.deliveries.map(item => `<tr><td>${esc(item.channel)}</td><td>${pill(item.status)}</td><td>${Number(item.attempts || 0)}</td><td>${esc(item.last_error || item.suppressed_reason || '—')}</td></tr>`).join('') || empty(4, 'No notification deliveries.')
 $('provider-count').textContent = `${state.providers.length} configured`
 $('providers').innerHTML = state.providers.map(provider => `<div class="provider-row"><div><b>${esc(provider)}</b><small>Webhook ingestion enabled</small></div></div>`).join('') || '<div class="chart-empty">No provider is configured.</div>'
}

function renderNavigationCounts() {
 $('nav-overview-count').textContent = ''
 $('nav-incident-count').textContent = state.incidents.filter(item => item.state !== 'resolved').length || ''
 $('nav-diagnosis-count').textContent = state.analyses.length || ''
 $('nav-test-count').textContent = state.tests.filter(item => ['flaky', 'suspected_flaky', 'consistently_failing'].includes(item.classification)).length || ''
 $('nav-provider-count').textContent = state.providers.length || ''
}

function switchTab(name) {
 const target = pageMeta[name] ? name : 'overview'
 document.querySelectorAll('.view').forEach(view => view.classList.toggle('active', view.id === target))
 document.querySelectorAll('[data-tab]').forEach(buttonElement => buttonElement.classList.toggle('active', buttonElement.dataset.tab === target))
 $('page-title').textContent = pageMeta[target][0]
 $('page-description').textContent = pageMeta[target][1]
 document.title = `${pageMeta[target][0]} · CI Radar`
 history.replaceState(null, '', `#${target}`)
}

function openDrawer(kind, item) {
 $('drawer-kind').textContent = kind
 $('drawer-title').textContent = item.title || item.summary || item.name || item.id || item.fingerprint
 let body = ''
 if (kind === 'analysis') body = analysisDetail(item)
 if (kind === 'incident') body = incidentDetail(item)
 if (kind === 'test') body = testDetail(item)
 $('drawer-body').innerHTML = body
 $('drawer').classList.add('open')
 $('drawer').setAttribute('aria-hidden', 'false')
 $('backdrop').hidden = false
}

function closeDrawer() {
 $('drawer').classList.remove('open')
 $('drawer').setAttribute('aria-hidden', 'true')
 $('backdrop').hidden = true
}

function keyValues(values) {
 return `<dl>${values.filter(item => item[1] !== undefined && item[1] !== null && item[1] !== '').map(item => `<dt>${esc(item[0])}</dt><dd>${esc(item[1])}</dd>`).join('')}</dl>`
}

function analysisDetail(item) {
 const evidence = (item.human_evidence || []).map(value => `<li>${esc(value)}</li>`).join('') || '<li>No evidence list recorded.</li>'
 const actions = (item.suggested_actions || []).map(action => `<article class="recommendation"><header><b>${esc(action.title)}</b>${pill(action.risk)}</header><p>${esc(action.description || '')}</p><small>${esc(action.type || '')}</small></article>`).join('') || '<p>No recommended action was recorded.</p>'
 const values = [
  ['Repository', item.repository],
  ['Workflow', item.workflow],
  ['Job', item.job],
  ['Provider', item.provider],
  ['Category', item.category],
  ['Attribution', item.attribution],
  ['Evidence strength', evidenceValue(item)],
  ['Externality score', externalityValue(item)],
  ['External evidence', item.external_evidence_score],
  ['Code evidence', item.code_evidence_score],
  ['Fingerprint', item.fingerprint],
  ['Created', fmtDate(item.created_at)]
 ]
 return `${keyValues(values)}<h3>Evidence</h3><ul class="evidence">${evidence}</ul><h3>Decision</h3><p>${esc(item.decision_reason || item.summary)}</p><h3>Redacted excerpt</h3><pre>${esc(item.excerpt || item.redacted_excerpt || 'Raw logs are not stored by default.')}</pre><h3>Recommended actions</h3>${actions}<div class="drawer-actions">${button('github-issue', item.id, 'Open GitHub issue')}</div>`
}

function incidentDetail(item) {
 const values = [
  ['Provider', item.provider],
  ['Category', item.category],
  ['Attribution', item.attribution],
  ['Severity', item.severity],
  ['State', item.state],
  ['Repositories', item.repository_count],
  ['Occurrences', item.occurrence_count],
  ['First seen', fmtDate(item.first_seen)],
  ['Last seen', fmtDate(item.last_seen)],
  ['Fingerprint', item.fingerprint]
 ]
 const repositories = (item.repositories || []).map(repository => `<li>${esc(repository)}</li>`).join('') || '<li>Not recorded.</li>'
 return `${keyValues(values)}<h3>Affected repositories</h3><ul class="evidence">${repositories}</ul><div class="drawer-actions">${button('incident-ack', item.fingerprint, 'Acknowledge')}${button('incident-resolve', item.fingerprint, 'Resolve', 'danger')}</div>`
}

function testDetail(item) {
 const values = [
  ['Repository', item.repository],
  ['Framework', item.framework],
  ['File', item.file],
  ['Suite', item.suite],
  ['Class', item.class_name],
  ['Observations', item.total_runs],
  ['Executed', item.executed_runs],
  ['Skipped', item.skipped],
  ['Passes', item.passes],
  ['Failures', item.failures],
  ['Failure rate', `${(Number(item.failure_rate || 0) * 100).toFixed(1)}%`],
  ['95% interval', `${(Number(item.failure_rate_low || 0) * 100).toFixed(1)}–${(Number(item.failure_rate_high || 0) * 100).toFixed(1)}%`],
  ['History confidence', `${(Number(item.history_confidence || 0) * 100).toFixed(0)}%`],
  ['Rerun recoveries', item.rerun_recoveries],
  ['Compute minutes lost', Number(item.estimated_compute_minutes_lost || 0).toFixed(1)],
  ['Engineering minutes lost', Number(item.estimated_engineering_minutes_lost || 0).toFixed(1)],
  ['Flake score', Number(item.flake_score || 0).toFixed(1)],
  ['Flake probability', Number(item.flake_probability || 0).toFixed(1)],
  ['Classification', item.classification],
  ['Likely cause', item.primary_flake_cause],
  ['Cause confidence', `${(Number(item.cause_confidence || 0) * 100).toFixed(0)}%`],
  ['Last seen', fmtDate(item.last_seen)]
 ]
 const status = item.quarantined ? 'This test is currently quarantined.' : 'This test blocks CI when it fails.'
 const action = item.quarantined ? button('unquarantine', item.test_key, 'Restore test') : button('quarantine', item.test_key, 'Quarantine test')
 return `${keyValues(values)}<h3>Quarantine</h3><p>${status}</p><div class="drawer-actions">${action}</div>`
}

function fieldMarkup(field) {
 const required = field.required ? ' required' : ''
 if (field.type === 'select') {
  const options = field.options.map(option => `<option value="${esc(option.value)}"${option.value === field.value ? ' selected' : ''}>${esc(option.label)}</option>`).join('')
  return `<label>${esc(field.label)}<select name="${esc(field.name)}"${required}>${options}</select></label>`
 }
 if (field.type === 'textarea') {
  return `<label>${esc(field.label)}<textarea name="${esc(field.name)}"${required}>${esc(field.value || '')}</textarea></label>`
 }
 return `<label>${esc(field.label)}<input name="${esc(field.name)}" type="${esc(field.type || 'text')}" value="${esc(field.value || '')}"${required}></label>`
}

function openActionDialog(config) {
 actionContext = config
 $('action-kind').textContent = config.kind || 'Action'
 $('action-title').textContent = config.title
 $('action-description').textContent = config.description || ''
 $('action-submit').textContent = config.submitLabel || 'Save'
 $('action-fields').innerHTML = (config.fields || []).map(fieldMarkup).join('')
 $('action-dialog').showModal()
 const first = $('action-fields').querySelector('input,select,textarea')
 if (first) first.focus()
}

function closeActionDialog() {
 actionContext = null
 $('action-dialog').close()
}

async function submitAction(event) {
 event.preventDefault()
 if (!actionContext) return
 const formData = new FormData(event.currentTarget)
 const values = Object.fromEntries(formData.entries())
 $('action-submit').disabled = true
 try {
  await actionContext.submit(values)
  closeActionDialog()
  closeDrawer()
  await load(true)
 } catch (error) {
  setError(error.message)
 } finally {
  $('action-submit').disabled = false
 }
}

async function load(force = false) {
 if (state.loading && !force) return
 setLoading(true)
 setError()
 try {
  const range = encodeURIComponent($('range').value)
  const [dashboard, repositories, deliveries, tests, analyses, incidents, status] = await Promise.all([
   api(`/api/v1/dashboard?range=${range}`),
   api('/api/v1/repositories'),
   api('/api/v1/notifications/deliveries?limit=100'),
   api('/api/v1/tests?limit=500'),
   api('/api/v1/analyses?limit=500'),
   api('/api/v1/incidents?limit=500'),
   api('/api/v1/status')
  ])
  state.dashboard = dashboard
  state.repositories = repositories.repositories || []
  state.deliveries = deliveries.deliveries || []
  state.tests = tests.tests || []
  state.analyses = analyses.analyses || analyses || []
  state.incidents = incidents.incidents || incidents || []
  state.providers = status.connectors_enabled || []
  renderOverview(dashboard)
  renderIncidentTable()
  renderAnalysisFilters()
  renderAnalysisTable()
  renderTestTable()
  renderOperations()
  renderNavigationCounts()
  $('updated-at').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
  setConnection('Connected', 'online')
 } catch (error) {
  const message = error.status === 401 ? 'Sign in with an admin token, API key or SSO to load this dashboard.' : error.message
  setError(message)
  setConnection('Unavailable', 'offline')
  if (error.status === 401) $('session-panel')?.setAttribute('open', '')
 } finally {
  setLoading(false)
 }
}

async function incidentState(id, action) {
 await api(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: '{}' })
 closeDrawer()
 await load(true)
}

async function feedback(id, verdict) {
 if (verdict !== 'incorrect') {
  await api(`/api/v1/analyses/${encodeURIComponent(id)}/feedback`, {
   method: 'POST',
   body: JSON.stringify({ verdict })
  })
  await load(true)
  return
 }
 openActionDialog({
  kind: 'Diagnosis feedback',
  title: 'Mark diagnosis as wrong',
  description: 'Select the cause that should have been assigned.',
  submitLabel: 'Submit feedback',
  fields: [{
   name: 'actual_cause',
   label: 'Actual cause',
   type: 'select',
   value: 'CODE',
   required: true,
   options: ['EXTERNAL', 'CODE', 'MIXED', 'TOOLCHAIN', 'UNKNOWN'].map(value => ({ value, label: value }))
  }],
  submit: values => api(`/api/v1/analyses/${encodeURIComponent(id)}/feedback`, {
   method: 'POST',
   body: JSON.stringify({ verdict, actual_cause: values.actual_cause })
  })
 })
}

function quarantine(key) {
 openActionDialog({
  kind: 'Test quarantine',
  title: 'Quarantine test',
  description: 'Keep the owner and reason specific so the quarantine can be reviewed.',
  submitLabel: 'Quarantine',
  fields: [
   { name: 'owner', label: 'Owner', value: 'platform', required: true },
   { name: 'reason', label: 'Reason', type: 'textarea', value: 'Known flaky test under investigation', required: true },
   { name: 'days', label: 'Expires after days', type: 'number', value: '7', required: true }
  ],
  submit: values => {
   const days = Math.max(1, Math.min(365, Number(values.days) || 7))
   return api(`/api/v1/tests/${encodeURIComponent(key)}/quarantine`, {
    method: 'POST',
    body: JSON.stringify({
     owner: values.owner,
     reason: values.reason,
     expires_at: new Date(Date.now() + days * 864e5).toISOString()
    })
   })
  }
 })
}

async function unquarantine(key) {
 await api(`/api/v1/tests/${encodeURIComponent(key)}/quarantine`, { method: 'DELETE' })
 closeDrawer()
 await load(true)
}

async function githubIssue(id) {
 let result
 try {
  result = await api(`/api/v1/analyses/${encodeURIComponent(id)}/github-issue`)
 } catch (error) {
  if (error.status !== 404) throw error
  result = await api(`/api/v1/analyses/${encodeURIComponent(id)}/github-issue`, { method: 'POST', body: '{}' })
 }
 const url = result?.issue?.html_url || result?.link?.url
 if (url) window.open(url, '_blank', 'noopener,noreferrer')
}

async function act(buttonElement) {
 const action = buttonElement.dataset.action
 const id = buttonElement.dataset.id
 if (action === 'incident-ack') return incidentState(id, 'acknowledge')
 if (action === 'incident-resolve') return incidentState(id, 'resolve')
 if (action === 'feedback-correct') return feedback(id, 'correct')
 if (action === 'feedback-partial') return feedback(id, 'partial')
 if (action === 'feedback-incorrect') return feedback(id, 'incorrect')
 if (action === 'quarantine') return quarantine(id)
 if (action === 'unquarantine') return unquarantine(id)
 if (action === 'github-issue') return githubIssue(id)
}

function handleOpen(row) {
 const kind = row.dataset.open
 const id = row.dataset.id
 if (kind === 'analysis') {
  const item = state.analyses.find(value => value.id === id)
  if (item) openDrawer(kind, item)
 }
 if (kind === 'incident') {
  const item = state.incidents.find(value => value.fingerprint === id)
  if (item) openDrawer(kind, item)
 }
 if (kind === 'test') {
  const item = state.tests.find(value => value.test_key === id)
  if (item) openDrawer(kind, item)
 }
}

document.addEventListener('click', event => {
 const action = event.target.closest('button[data-action]')
 if (action) {
  event.stopPropagation()
  act(action).catch(error => setError(error.message))
  return
 }
 const tab = event.target.closest('[data-tab]')
 if (tab) {
  switchTab(tab.dataset.tab)
  return
 }
 const jump = event.target.closest('[data-tab-jump]')
 if (jump) {
  switchTab(jump.dataset.tabJump)
  return
 }
 const row = event.target.closest('tr[data-open]')
 if (row) handleOpen(row)
})

for (const id of ['incident-search', 'incident-state', 'incident-severity']) $(id).addEventListener('input', renderIncidentTable)
for (const id of ['analysis-search', 'analysis-attribution', 'analysis-category', 'analysis-provider']) $(id).addEventListener('input', renderAnalysisTable)
for (const id of ['test-search', 'test-state', 'test-cause']) $(id).addEventListener('input', renderTestTable)

$('drawer-close').addEventListener('click', closeDrawer)
$('backdrop').addEventListener('click', closeDrawer)
$('action-close').addEventListener('click', closeActionDialog)
$('action-cancel').addEventListener('click', closeActionDialog)
$('action-form').addEventListener('submit', submitAction)
$('secure-login').addEventListener('click', () => secureLogin().catch(error => setError(error.message)))
$('sso-login').addEventListener('click', () => location.assign('/auth/login?return_to=/'))
$('logout').addEventListener('click', () => location.assign('/auth/logout'))
$('refresh').addEventListener('click', () => load(true))
$('range').addEventListener('change', () => load(true))

window.addEventListener('keydown', event => {
 if (event.key === 'Escape' && !$('action-dialog').open) closeDrawer()
})

document.addEventListener('visibilitychange', () => {
 if (!document.hidden) load()
})

switchTab(location.hash.slice(1) || 'overview')
setInterval(() => {
 if (!document.hidden) load()
}, 30000)
load()
