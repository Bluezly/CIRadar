const $ = id => document.getElementById(id)

const state = {
 dashboard: null,
 repositories: [],
 deliveries: [],
 tests: [],
 analyses: [],
 incidents: [],
 providers: [],
 identity: null,
 authenticated: false,
 loading: false
}

const pageMeta = {
 overview: ['Overview', 'Work that is slowing delivery right now.'],
 incidents: ['Incidents', 'Correlated failures that need an owner and a resolution.'],
 diagnoses: ['Diagnoses', 'Evidence behind CI failure attribution.'],
 tests: ['Tests', 'History, impact and quarantine decisions.'],
 operations: ['Operations', 'Delivery health, routing and provider status.']
}

let actionContext = null
let bootstrapping = false

$('tenant').value = sessionStorage.ciradarTenant || 'default'

function loginError(message = '') {
 $('login-error').textContent = message
 $('login-error').hidden = !message
}

function clearData() {
 state.dashboard = null
 state.repositories = []
 state.deliveries = []
 state.tests = []
 state.analyses = []
 state.incidents = []
 state.providers = []
}

function identityName(identity) {
 if (!identity) return 'Session'
 if (identity.name) return identity.name
 if (identity.root) return 'root'
 return 'CI Radar user'
}

function renderIdentity(identity) {
 const name = identityName(identity)
 const role = identity?.role || 'viewer'
 const tenant = identity?.tenant_id || 'default'
 $('session-name').textContent = name
 $('session-role').textContent = role
 $('session-menu-name').textContent = name
 $('session-menu-role').textContent = role
 $('session-tenant').textContent = `Tenant · ${tenant}`
}

function showLogin(message = '') {
 state.authenticated = false
 state.identity = null
 clearData()
 $('app-shell').hidden = true
 $('login-screen').hidden = false
 $('session-menu').hidden = true
 $('session-open').setAttribute('aria-expanded', 'false')
 setError()
 loginError(message)
 document.title = 'Sign in · CI Radar'
 requestAnimationFrame(() => $('token').focus())
}

function showApp(identity) {
 state.identity = identity
 state.authenticated = true
 renderIdentity(identity)
 $('login-screen').hidden = true
 $('app-shell').hidden = false
 loginError()
 document.title = 'CI Radar'
}

async function authIdentity() {
 const response = await fetch('/api/v1/auth/me', { headers: { 'Accept': 'application/json' } })
 if (response.status === 401) return null
 if (!response.ok) throw new Error('Could not verify the dashboard session.')
 return response.json()
}

async function api(path, options = {}) {
 const tenant = $('tenant').value.trim() || state.identity?.tenant_id || 'default'
 sessionStorage.ciradarTenant = tenant
 const headers = { ...(options.headers || {}), 'X-CI-Radar-Tenant': tenant }
 if (options.body !== undefined) headers['Content-Type'] = 'application/json'
 const response = await fetch(path, { ...options, headers })
 if (!response.ok) {
  const payload = await response.json().catch(() => ({ error: response.statusText }))
  const error = new Error(payload.error || response.statusText)
  error.status = response.status
  if (response.status === 401 && state.authenticated) showLogin('Your session ended. Sign in again to continue.')
  throw error
 }
 return response.status === 204 ? null : response.json()
}

async function secureLogin() {
 const token = $('token').value.trim()
 const tenant = $('tenant').value.trim() || 'default'
 if (!token) throw new Error('Enter an admin token or API key.')
 loginError()
 $('secure-login').disabled = true
 try {
  const response = await fetch('/auth/token', {
   method: 'POST',
   headers: { 'Content-Type': 'application/json' },
   body: JSON.stringify({ token, tenant })
  })
  if (!response.ok) {
   const payload = await response.json().catch(() => ({ error: response.statusText }))
   const error = new Error(payload.error || response.statusText)
   error.status = response.status
   throw error
  }
  $('token').value = ''
  sessionStorage.ciradarTenant = tenant
  const identity = await authIdentity()
  if (!identity) throw new Error('The session was created but could not be verified.')
  showApp(identity)
  switchTab(location.hash.slice(1) || 'overview')
  await load(true)
 } finally {
  $('secure-login').disabled = false
 }
}

function startSSO() {
 const target = `/${location.hash || '#overview'}`
 location.assign(`/auth/login?return_to=${encodeURIComponent(target)}`)
}

function esc(value) {
 return String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
 }[character]))
}

function slug(value) {
 return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]+/g, '_')
}

function safeHTTPURL(value) {
 try {
  const parsed = new URL(String(value || ''))
  return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : ''
 } catch {
  return ''
 }
}

function lower(value) {
 return String(value ?? '').toLowerCase()
}

function empty(columns, message) {
 return `<tr><td colspan="${columns}" class="empty">${esc(message)}</td></tr>`
}

function button(action, id, label, kind = '') {
 return `<button type="button" class="compact ${esc(kind)}" data-action="${esc(action)}" data-id="${esc(id)}">${esc(label)}</button>`
}

function fmtDate(value) {
 if (!value) return '—'
 const date = new Date(value)
 if (Number.isNaN(date.getTime())) return '—'
 return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function fmtRelative(value) {
 if (!value) return '—'
 const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000)
 const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
 const ranges = [[31536000, 'year'], [2592000, 'month'], [604800, 'week'], [86400, 'day'], [3600, 'hour'], [60, 'minute']]
 for (const [size, unit] of ranges) {
  if (Math.abs(seconds) >= size) return formatter.format(Math.round(seconds / size), unit)
 }
 return formatter.format(seconds, 'second')
}

function formatMinutes(value) {
 const minutes = Number(value) || 0
 if (minutes >= 60) return `${(minutes / 60).toFixed(minutes >= 600 ? 0 : 1)}h`
 return `${minutes.toFixed(minutes >= 10 ? 0 : 1)}m`
}

function formatPercent(value) {
 return `${(Number(value || 0) * 100).toFixed(1)}%`
}

function pill(value, extra = '') {
 const className = extra ? `tag-${extra}` : `tag-${slug(value)}`
 return `<span class="tag ${className}">${esc(String(value || 'unknown').replaceAll('_', ' '))}</span>`
}

function scoreBar(value) {
 const score = Math.max(0, Math.min(100, Math.round(Number(value) || 0)))
 return `<div class="score"><span>${score}</span><progress max="100" value="${score}" aria-label="Score ${score} out of 100"></progress></div>`
}

function repositoryFilter() {
 return $('repository-filter').value
}

function repositoryMatches(item) {
 const selected = repositoryFilter()
 return !selected || lower(item.repository) === lower(selected)
}

function currentTests() {
 return state.tests.filter(repositoryMatches)
}

function currentAnalyses() {
 return state.analyses.filter(repositoryMatches)
}

function currentIncidents() {
 const selected = repositoryFilter()
 if (!selected) return state.incidents
 const fingerprints = new Set(currentAnalyses().map(item => item.fingerprint).filter(Boolean))
 return state.incidents.filter(item => fingerprints.has(item.fingerprint))
}

function setLoading(loading) {
 state.loading = loading
 document.body.classList.toggle('loading', loading)
 $('refresh').disabled = loading
}

function setError(message = '') {
 $('error').textContent = message
 $('error').hidden = !message
}

function switchTab(tab) {
 if (!pageMeta[tab]) tab = 'overview'
 document.querySelectorAll('.view').forEach(view => view.classList.toggle('active', view.id === tab))
 document.querySelectorAll('[data-tab]').forEach(buttonElement => buttonElement.classList.toggle('active', buttonElement.dataset.tab === tab))
 $('page-title').textContent = pageMeta[tab][0]
 $('page-description').textContent = pageMeta[tab][1]
 if (location.hash !== `#${tab}`) history.replaceState(null, '', `#${tab}`)
}

function metric(label, value, detail) {
 return `<article class="metric"><span>${esc(label)}</span><b>${esc(value)}</b><small>${esc(detail)}</small></article>`
}

function impactScore(test) {
 return Number(test.estimated_engineering_minutes_lost || 0) * 10 + Number(test.pull_requests_impacted || 0) * 30 + Number(test.flake_score || 0)
}

function unstable(test) {
 return ['flaky', 'suspected_flaky', 'consistently_failing', 'mixed'].includes(test.classification)
}

function renderRepositoryFilter() {
 const selected = $('repository-filter').value
 const names = new Set()
 state.repositories.forEach(item => item.repository && names.add(item.repository))
 state.tests.forEach(item => item.repository && names.add(item.repository))
 state.analyses.forEach(item => item.repository && names.add(item.repository))
 const options = [...names].sort((a, b) => a.localeCompare(b)).map(name => `<option value="${esc(name)}"${name === selected ? ' selected' : ''}>${esc(name)}</option>`).join('')
 $('repository-filter').innerHTML = `<option value="">All repositories</option>${options}`
}

function renderOverviewMetrics() {
 const tests = currentTests()
 const unresolved = currentIncidents().filter(item => item.state !== 'resolved')
 const engineeringMinutes = tests.reduce((total, item) => total + Number(item.estimated_engineering_minutes_lost || 0), 0)
 const impactedPRs = new Set(tests.flatMap(item => item.impacted_pull_requests || [])).size
 const unstableCount = tests.filter(unstable).length
 const critical = tests.filter(item => item.critical).length
 $('overview-metrics').innerHTML = [
  metric('Unresolved incidents', unresolved.length, `${unresolved.filter(item => item.severity === 'critical').length} critical`),
  metric('PRs impacted', impactedPRs, 'Unique pull requests'),
  metric('Engineering time lost', formatMinutes(engineeringMinutes), 'Conservative estimate'),
  metric('Unstable tests', unstableCount, `${critical} marked critical`)
 ].join('')
}

function attentionItems() {
 const severityWeight = { critical: 500, major: 400, high: 300, medium: 150, minor: 100, low: 60 }
 const incidents = currentIncidents().filter(item => item.state !== 'resolved').map(item => ({
  kind: 'incident',
  id: item.fingerprint,
  title: item.title || item.error_family || 'Unresolved incident',
  detail: `${item.provider || 'provider unknown'} · ${item.repository_count || 0} repositories · ${item.occurrence_count || 0} events`,
  impact: `${item.severity || 'unknown'} severity`,
  score: (severityWeight[item.severity] || 20) + Number(item.occurrence_count || 0)
 }))
 const tests = currentTests().filter(unstable).map(item => ({
  kind: 'test',
  id: item.test_key,
  title: item.display_name || item.name,
  detail: `${item.repository || 'unknown repository'} · ${String(item.classification || '').replaceAll('_', ' ')}`,
  impact: `${item.pull_requests_impacted || 0} PRs · ${formatMinutes(item.estimated_engineering_minutes_lost)}`,
  score: impactScore(item)
 }))
 return [...incidents, ...tests].sort((a, b) => b.score - a.score).slice(0, 10)
}

function renderAttention() {
 const items = attentionItems()
 $('attention-count').textContent = `${items.length} prioritized`
 $('attention-list').innerHTML = items.map((item, index) => `<div class="attention-item" data-open="${esc(item.kind)}" data-id="${esc(item.id)}" tabindex="0"><span class="attention-rank">${index + 1}</span><div><h3>${esc(item.title)}</h3><p>${esc(item.detail)}</p></div><div class="impact-value"><b>${esc(item.impact)}</b><span>Open details</span></div></div>`).join('') || '<div class="empty">No unresolved work in the selected scope.</div>'
}

function mergeDates(...maps) {
 const dates = new Set()
 maps.forEach(map => Object.keys(map || {}).forEach(key => dates.add(key)))
 return [...dates].sort()
}

function renderReliabilityTrend() {
 const incidents = state.dashboard?.daily_incidents || {}
 const tests = state.dashboard?.daily_test_failures || {}
 const dates = mergeDates(incidents, tests)
 const container = $('reliability-trend')
 if (!dates.length) {
  container.innerHTML = '<div class="empty">No trend data in this period.</div>'
  return
 }
 const width = 720
 const height = 230
 const padX = 36
 const padY = 25
 const incidentValues = dates.map(date => Number(incidents[date] || 0))
 const testValues = dates.map(date => Number(tests[date] || 0))
 const maximum = Math.max(1, ...incidentValues, ...testValues)
 const x = index => padX + (width - padX * 2) * (dates.length === 1 ? .5 : index / (dates.length - 1))
 const y = value => height - padY - (height - padY * 2) * value / maximum
 const points = values => values.map((value, index) => `${x(index)},${y(value)}`).join(' ')
 const grid = [0, .5, 1].map(position => {
  const value = Math.round(maximum * (1 - position))
  const gy = padY + (height - padY * 2) * position
  return `<line class="gridline" x1="${padX}" y1="${gy}" x2="${width - padX}" y2="${gy}"></line><text x="3" y="${gy + 3}">${value}</text>`
 }).join('')
 const labels = [0, Math.floor((dates.length - 1) / 2), dates.length - 1].filter((value, index, values) => values.indexOf(value) === index).map(index => `<text x="${x(index)}" y="${height - 4}" text-anchor="middle">${esc(dates[index].slice(5))}</text>`).join('')
 const incidentDots = incidentValues.map((value, index) => `<circle class="point-incidents" cx="${x(index)}" cy="${y(value)}" r="3"><title>${esc(dates[index])}: ${value} incidents</title></circle>`).join('')
 const testDots = testValues.map((value, index) => `<circle class="point-tests" cx="${x(index)}" cy="${y(value)}" r="3"><title>${esc(dates[index])}: ${value} test failures</title></circle>`).join('')
 container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img">${grid}<polyline class="line-incidents" points="${points(incidentValues)}"></polyline><polyline class="line-tests" points="${points(testValues)}"></polyline>${incidentDots}${testDots}${labels}</svg><div class="chart-legend"><span class="legend-key legend-incidents">Incidents</span><span class="legend-key legend-tests">Test failures</span></div>`
}

function renderTestImpactPreview() {
 const items = [...currentTests()].filter(unstable).sort((a, b) => impactScore(b) - impactScore(a)).slice(0, 8)
 $('test-impact-preview').innerHTML = items.map(item => `<tr data-open="test" data-id="${esc(item.test_key)}"><td><b>${esc(item.display_name || item.name)}</b><small>${esc(item.repository)}${item.critical ? ' · critical test' : ''}</small></td><td><b>${item.pull_requests_impacted || 0} PRs</b><small>${formatMinutes(item.estimated_engineering_minutes_lost)} engineering time</small></td><td>${pill(item.classification)}${item.quarantined ? '<small>Quarantined</small>' : ''}</td></tr>`).join('') || empty(3, 'No unstable tests in this scope.')
}

function renderRepositoryHealth() {
 const names = new Set()
 state.repositories.forEach(item => item.repository && names.add(item.repository))
 state.tests.forEach(item => item.repository && names.add(item.repository))
 state.analyses.forEach(item => item.repository && names.add(item.repository))
 const rows = [...names].map(repository => {
  const tests = state.tests.filter(item => lower(item.repository) === lower(repository))
  const analyses = state.analyses.filter(item => lower(item.repository) === lower(repository))
  return {
   repository,
   diagnoses: analyses.length,
   unstable: tests.filter(unstable).length,
   lost: tests.reduce((total, item) => total + Number(item.estimated_engineering_minutes_lost || 0), 0)
  }
 }).sort((a, b) => b.lost + b.unstable * 10 - (a.lost + a.unstable * 10)).slice(0, 10)
 $('repository-health').innerHTML = rows.map(row => `<tr><td><b>${esc(row.repository)}</b></td><td>${row.diagnoses}</td><td>${row.unstable}</td><td>${formatMinutes(row.lost)}</td></tr>`).join('') || empty(4, 'No repository data available.')
}

function renderOverview() {
 renderOverviewMetrics()
 renderAttention()
 renderReliabilityTrend()
 renderTestImpactPreview()
 renderRepositoryHealth()
}

function incidentRow(item) {
 return `<tr data-open="incident" data-id="${esc(item.fingerprint)}"><td><b>${esc(item.title)}</b><small>${esc(item.provider || 'Unknown provider')} · ${esc(item.severity || 'unknown')} · ${esc(item.attribution || '')}</small></td><td>${pill(item.state)}</td><td>${Number(item.repository_count || 0)}</td><td>${Number(item.occurrence_count || 0)}</td><td>${fmtRelative(item.last_seen_at || item.last_seen)}</td><td class="actions">${item.state === 'open' ? button('incident-ack', item.fingerprint, 'Acknowledge') : ''}${item.state !== 'resolved' ? button('incident-resolve', item.fingerprint, 'Resolve', 'danger') : ''}</td></tr>`
}

function renderIncidentTable() {
 const query = lower($('incident-search').value)
 const selectedState = $('incident-state').value
 const severity = $('incident-severity').value
 const items = currentIncidents().filter(item => (!query || lower(`${item.title} ${item.provider} ${item.category} ${item.attribution}`).includes(query)) && (!selectedState || item.state === selectedState) && (!severity || item.severity === severity))
 $('incident-count').textContent = `${items.length} incidents`
 $('incident-table').innerHTML = items.map(incidentRow).join('') || empty(6, 'No incidents match these filters.')
}

function evidenceValue(item) {
 const explicit = Number(item.evidence_strength)
 return explicit > 0 ? explicit : Math.abs(Number(item.score || item.externality_score || 0))
}

function renderAnalysisFilters() {
 const selected = $('analysis-category').value
 const categories = [...new Set(state.analyses.map(item => item.category).filter(Boolean))].sort()
 $('analysis-category').innerHTML = `<option value="">All categories</option>${categories.map(value => `<option value="${esc(value)}"${value === selected ? ' selected' : ''}>${esc(value)}</option>`).join('')}`
}

function analysisRow(item) {
 return `<tr data-open="analysis" data-id="${esc(item.id)}"><td><b>${esc(item.repository || 'Local')}</b><small>${esc(item.workflow || '')}${item.job ? ` · ${esc(item.job)}` : ''}${item.pull_request_number ? ` · PR #${item.pull_request_number}` : ''}</small></td><td>${pill(item.attribution)}<small>${esc(item.category || '')}</small></td><td><b>${esc(item.summary || 'No summary')}</b><small>${esc(item.decision_reason || '')}</small></td><td>${scoreBar(evidenceValue(item))}</td><td>${fmtRelative(item.created_at)}</td><td class="actions">${button('feedback-correct', item.id, 'Correct')}${button('feedback-incorrect', item.id, 'Wrong')}${button('github-issue', item.id, 'Issue')}</td></tr>`
}

function renderAnalysisTable() {
 const query = lower($('analysis-search').value)
 const attribution = $('analysis-attribution').value
 const category = $('analysis-category').value
 const items = currentAnalyses().filter(item => (!query || lower(`${item.repository} ${item.workflow} ${item.job} ${item.summary} ${item.category}`).includes(query)) && (!attribution || item.attribution === attribution) && (!category || item.category === category))
 $('analysis-count').textContent = `${items.length} diagnoses`
 $('analysis-table').innerHTML = items.map(analysisRow).join('') || empty(6, 'No diagnoses match these filters.')
}

function sortedTests(items) {
 const sort = $('test-sort').value
 return [...items].sort((a, b) => {
  if (sort === 'prs') return Number(b.pull_requests_impacted || 0) - Number(a.pull_requests_impacted || 0)
  if (sort === 'flake') return Number(b.flake_score || 0) - Number(a.flake_score || 0)
  if (sort === 'recent') return new Date(b.last_seen_at || b.last_seen || 0) - new Date(a.last_seen_at || a.last_seen || 0)
  return impactScore(b) - impactScore(a)
 })
}

function renderTestMetrics() {
 const tests = currentTests()
 const impacted = new Set(tests.flatMap(item => item.impacted_pull_requests || [])).size
 const lost = tests.reduce((total, item) => total + Number(item.estimated_engineering_minutes_lost || 0), 0)
 const quarantinedFailures = tests.reduce((total, item) => total + Number(item.quarantined_failures || 0), 0)
 const warming = tests.filter(item => item.cold_start).length
 $('test-metrics').innerHTML = [
  metric('PRs impacted', impacted, 'Unique pull requests'),
  metric('Engineering time lost', formatMinutes(lost), 'Estimated from reruns'),
  metric('Failures ignored', quarantinedFailures, 'While quarantined'),
  metric('Cold-start tests', warming, 'History still limited')
 ].join('')
}

function testRow(item) {
 const identity = [item.file, item.variant].filter(Boolean).join(' · ')
 const criticalTag = item.critical ? pill('Critical', 'critical-test') : ''
 const quarantineAction = item.quarantined ? button('unquarantine', item.test_key, 'Restore') : button('quarantine', item.test_key, 'Quarantine')
 return `<tr data-open="test" data-id="${esc(item.test_key)}"><td><b>${esc(item.display_name || item.name)}</b><small>${esc(item.repository)}${identity ? ` · ${esc(identity)}` : ''}</small></td><td>${criticalTag}${pill(item.classification)}${item.quarantined ? '<small>Quarantined</small>' : ''}</td><td><b>${Number(item.pull_requests_impacted || 0)}</b><small>${(item.impacted_pull_requests || []).slice(-3).map(value => `#${value}`).join(', ') || 'No linked PRs'}</small></td><td><b>${formatMinutes(item.estimated_engineering_minutes_lost)}</b><small>${formatMinutes(item.estimated_compute_minutes_lost)} compute</small></td><td>${formatPercent(item.failure_rate)}<small>${item.failures || 0} of ${item.executed_runs || 0}</small></td><td>${fmtRelative(item.last_seen_at || item.last_seen)}</td><td class="actions">${quarantineAction}</td></tr>`
}

function renderTestTable() {
 const query = lower($('test-search').value)
 const classification = $('test-state').value
 const criticalOnly = $('test-critical').checked
 const filtered = currentTests().filter(item => (!query || lower(`${item.display_name} ${item.name} ${item.repository} ${item.file} ${item.variant}`).includes(query)) && (!classification || item.classification === classification) && (!criticalOnly || item.critical))
 const items = sortedTests(filtered)
 $('test-count').textContent = `${items.length} tests`
 $('test-table').innerHTML = items.map(testRow).join('') || empty(7, 'No tests match these filters.')
 renderTestMetrics()
}

function renderOperations() {
 const dora = state.dashboard?.dora || {}
 const metrics = [
  ['Deployment frequency', `${Number(dora.deployment_frequency_per_day || 0).toFixed(2)} / day`],
  ['Lead time for changes', formatMinutes(dora.lead_time_for_changes_minutes)],
  ['Mean time to restore', formatMinutes(dora.mean_time_to_restore_minutes)],
  ['Change failure rate', `${Number(dora.change_failure_rate_percent || 0).toFixed(1)}%`]
 ]
 $('dora').innerHTML = metrics.map(([label, value]) => `<span>${esc(label)}</span><b>${esc(value)}</b>`).join('')
 $('providers').innerHTML = state.providers.map(provider => `<div class="provider"><b>${esc(provider)}</b><span>Configured</span></div>`).join('') || '<div class="empty">No external providers configured.</div>'
 $('provider-count').textContent = `${state.providers.length} configured`
 $('repositories').innerHTML = state.repositories.map(item => `<tr><td><b>${esc(item.repository)}</b></td><td>${esc(item.team || item.owner || '—')}</td><td>${pill(item.criticality || 'standard')}</td><td>${esc((item.notification_channels || []).join(', ') || '—')}</td></tr>`).join('') || empty(4, 'No repository profiles configured.')
 $('deliveries').innerHTML = state.deliveries.map(item => `<tr><td><b>${esc(item.channel || item.channel_type || '—')}</b></td><td>${pill(item.status)}</td><td>${Number(item.attempts || 0)}</td><td>${esc(item.last_error || item.suppressed_reason || '—')}</td></tr>`).join('') || empty(4, 'No notification deliveries recorded.')
}

function renderNavigationCounts() {
 $('nav-overview-count').textContent = attentionItems().length || ''
 $('nav-incident-count').textContent = currentIncidents().filter(item => item.state !== 'resolved').length || ''
 $('nav-diagnosis-count').textContent = currentAnalyses().length || ''
 $('nav-test-count').textContent = currentTests().filter(unstable).length || ''
 $('nav-provider-count').textContent = state.providers.length || ''
}

function keyValues(values) {
 return `<dl class="key-values">${values.map(([label, value]) => `<dt>${esc(label)}</dt><dd>${value === undefined || value === null || value === '' ? '—' : esc(value)}</dd>`).join('')}</dl>`
}

function openDrawerShell(kind, title, body) {
 $('drawer-kind').textContent = kind
 $('drawer-title').textContent = title
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

function incidentDrawer(item) {
 const values = [
  ['State', item.state], ['Severity', item.severity], ['Provider', item.provider], ['Attribution', item.attribution],
  ['Repositories affected', item.repository_count], ['Occurrences', item.occurrence_count], ['First seen', fmtDate(item.first_seen_at)], ['Last seen', fmtDate(item.last_seen_at)]
 ]
 const actions = `${item.state === 'open' ? button('incident-ack', item.fingerprint, 'Acknowledge') : ''}${item.state !== 'resolved' ? button('incident-resolve', item.fingerprint, 'Resolve', 'danger') : ''}`
 return `${keyValues(values)}<h3>Recommended actions</h3>${(item.suggested_actions || []).map(action => `<p><b>${esc(action.title)}</b><br>${esc(action.description)}</p>`).join('') || '<p>No automatic recommendation recorded.</p>'}<div class="drawer-actions">${actions}</div>`
}

function analysisDrawer(item) {
 const values = [
  ['Repository', item.repository], ['Workflow', item.workflow], ['Job', item.job], ['Attribution', item.attribution], ['Category', item.category],
  ['Confidence', item.confidence], ['Evidence strength', evidenceValue(item)], ['PR', item.pull_request_number ? `#${item.pull_request_number}` : '—'], ['Created', fmtDate(item.created_at)]
 ]
 const evidence = (item.evidence || []).map(entry => `<div class="failure-item"><span>${pill(entry.kind || 'evidence')}</span><div><b>${esc(entry.message || entry.description || '')}</b><p>${esc(entry.source || '')}</p></div><span>${esc(entry.weight || '')}</span></div>`).join('')
 return `<p>${esc(item.summary || '')}</p>${keyValues(values)}<h3>Decision</h3><p>${esc(item.decision_reason || item.recommendation || 'No decision note recorded.')}</p><h3>Evidence</h3><div class="failure-list">${evidence || '<div class="empty">No evidence items recorded.</div>'}</div><h3>Actions</h3><div class="drawer-actions">${button('feedback-correct', item.id, 'Diagnosis correct')}${button('feedback-incorrect', item.id, 'Diagnosis wrong')}${button('github-issue', item.id, 'Open GitHub issue')}</div>`
}

function historyMarkup(history) {
 return history.map(item => {
  const runURL = safeHTTPURL(item.run_url)
  const runLink = runURL ? `<a href="${esc(runURL)}" target="_blank" rel="noopener noreferrer">Run</a>` : fmtRelative(item.occurred_at)
  return `<div class="history-item"><span>${pill(item.status)}</span><div><b>${esc(item.job || item.workflow || 'Test run')}</b><p>${esc(item.message || item.commit_sha || 'No failure message')}</p></div><span>${runLink}</span></div>`
 }).join('') || '<div class="empty">No execution history retained.</div>'
}

function failureTypesMarkup(items) {
 return items.map(item => `<div class="failure-item"><span>${item.count}</span><div><b>${esc(item.message)}</b><p>First ${fmtRelative(item.first_seen_at)} · last ${fmtRelative(item.last_seen_at)}</p></div><span>${esc(item.signature)}</span></div>`).join('') || '<div class="empty">No grouped failures found.</div>'
}

function auditMarkup(items) {
 return items.map(item => `<div class="audit-item"><span>${esc(item.action)}</span><div><b>${esc(item.actor || 'system')}</b><p>${fmtDate(item.created_at)}</p></div><span>${esc(item.role || '')}</span></div>`).join('') || '<div class="empty">No test policy changes recorded.</div>'
}

async function openTestDrawer(testKey) {
 openDrawerShell('Test reliability', 'Loading test…', '<div class="empty">Loading history…</div>')
 try {
  const detail = await api(`/api/v1/tests/${encodeURIComponent(testKey)}?limit=200`)
  const item = detail.test
  const values = [
   ['Repository', item.repository], ['Variant', item.variant], ['Classification', String(item.classification || '').replaceAll('_', ' ')], ['Critical test', item.critical ? 'Yes' : 'No'],
   ['Executed runs', item.executed_runs], ['Pass / fail / skip', `${item.passes || 0} / ${item.failures || 0} / ${item.skipped || 0}`], ['Failure rate', formatPercent(item.failure_rate)],
   ['95% interval', `${formatPercent(item.failure_rate_low)} – ${formatPercent(item.failure_rate_high)}`], ['History confidence', formatPercent(item.history_confidence)],
   ['PRs impacted', item.pull_requests_impacted], ['Engineering time lost', formatMinutes(item.estimated_engineering_minutes_lost)], ['Compute time lost', formatMinutes(item.estimated_compute_minutes_lost)],
   ['Rerun recoveries', item.rerun_recoveries], ['Failures ignored while quarantined', item.quarantined_failures], ['Likely cause', item.primary_flake_cause], ['Last seen', fmtDate(item.last_seen_at)]
  ]
  const quarantineAction = item.quarantined ? button('unquarantine', item.test_key, 'Restore test') : button('quarantine', item.test_key, 'Quarantine test')
  const criticalAction = button('critical', item.test_key, item.critical ? 'Remove critical flag' : 'Mark as critical')
  $('drawer-title').textContent = item.display_name || item.name
  $('drawer-body').innerHTML = `${keyValues(values)}<h3>Policy</h3><p>${item.critical ? 'Automatic quarantine is disabled for this test.' : 'This test can be automatically quarantined when configured thresholds are met.'}</p><div class="drawer-actions">${criticalAction}${quarantineAction}</div><h3>Failure types</h3><div class="failure-list">${failureTypesMarkup(detail.failure_types || [])}</div><h3>Execution history</h3><div class="history-list">${historyMarkup(detail.history || [])}</div><h3>Audit history</h3><div class="audit-list">${auditMarkup(detail.audit || [])}</div>`
 } catch (error) {
  $('drawer-title').textContent = 'Test unavailable'
  $('drawer-body').innerHTML = `<div class="empty">${esc(error.message)}</div>`
 }
}

function openActionDialog(config) {
 actionContext = config
 $('action-kind').textContent = config.kind || 'Action'
 $('action-title').textContent = config.title
 $('action-description').textContent = config.description || ''
 $('action-submit').textContent = config.submitLabel || 'Save'
 $('action-fields').innerHTML = (config.fields || []).map(field => {
  const required = field.required ? ' required' : ''
  if (field.type === 'textarea') return `<label>${esc(field.label)}<textarea name="${esc(field.name)}"${required}>${esc(field.value || '')}</textarea></label>`
  if (field.type === 'select') return `<label>${esc(field.label)}<select name="${esc(field.name)}"${required}>${field.options.map(option => `<option value="${esc(option.value)}"${option.value === field.value ? ' selected' : ''}>${esc(option.label)}</option>`).join('')}</select></label>`
  return `<label>${esc(field.label)}<input name="${esc(field.name)}" type="${esc(field.type || 'text')}" value="${esc(field.value || '')}"${required}></label>`
 }).join('')
 $('action-dialog').showModal()
 $('action-fields').querySelector('input,select,textarea')?.focus()
}

function closeActionDialog() {
 actionContext = null
 $('action-dialog').close()
}

async function submitAction(event) {
 event.preventDefault()
 if (!actionContext) return
 const values = Object.fromEntries(new FormData(event.currentTarget).entries())
 $('action-submit').disabled = true
 try {
  await actionContext.submit(values)
  closeActionDialog()
  closeDrawer()
  await load(true)
 } catch (error) {
  if (error.status !== 401) setError(error.message)
 } finally {
  $('action-submit').disabled = false
 }
}

async function incidentState(id, action) {
 await api(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`, { method: 'POST', body: '{}' })
 closeDrawer()
 await load(true)
}

async function feedback(id, verdict) {
 if (verdict !== 'incorrect') {
  await api(`/api/v1/analyses/${encodeURIComponent(id)}/feedback`, { method: 'POST', body: JSON.stringify({ verdict }) })
  await load(true)
  return
 }
 openActionDialog({
  kind: 'Diagnosis feedback', title: 'Correct the diagnosis', description: 'Choose the attribution that should have been assigned.', submitLabel: 'Submit feedback',
  fields: [{ name: 'actual_cause', label: 'Actual cause', type: 'select', value: 'CODE', required: true, options: ['EXTERNAL', 'CODE', 'MIXED', 'TOOLCHAIN', 'UNKNOWN'].map(value => ({ value, label: value })) }],
  submit: values => api(`/api/v1/analyses/${encodeURIComponent(id)}/feedback`, { method: 'POST', body: JSON.stringify({ verdict, actual_cause: values.actual_cause }) })
 })
}

function quarantine(key) {
 openActionDialog({
  kind: 'Test quarantine', title: 'Quarantine test', description: 'Quarantine should have a named owner, a specific reason and a short expiry.', submitLabel: 'Quarantine',
  fields: [
   { name: 'owner', label: 'Owner', value: 'platform', required: true },
   { name: 'reason', label: 'Reason', type: 'textarea', value: 'Known flaky test under investigation', required: true },
   { name: 'days', label: 'Expires after days', type: 'number', value: '7', required: true }
  ],
  submit: values => {
   const days = Math.max(1, Math.min(90, Number(values.days) || 7))
   return api(`/api/v1/tests/${encodeURIComponent(key)}/quarantine`, { method: 'POST', body: JSON.stringify({ owner: values.owner, reason: values.reason, expires_at: new Date(Date.now() + days * 864e5).toISOString() }) })
  }
 })
}

async function unquarantine(key) {
 await api(`/api/v1/tests/${encodeURIComponent(key)}/quarantine`, { method: 'DELETE' })
 closeDrawer()
 await load(true)
}

async function toggleCritical(key) {
 const item = state.tests.find(test => test.test_key === key)
 const critical = !item?.critical
 await api(`/api/v1/tests/${encodeURIComponent(key)}/critical`, { method: 'PUT', body: JSON.stringify({ critical }) })
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
 const url = safeHTTPURL(result?.issue?.html_url || result?.link?.url)
 if (url) window.open(url, '_blank', 'noopener,noreferrer')
}

async function act(buttonElement) {
 const action = buttonElement.dataset.action
 const id = buttonElement.dataset.id
 if (action === 'incident-ack') return incidentState(id, 'acknowledge')
 if (action === 'incident-resolve') return incidentState(id, 'resolve')
 if (action === 'feedback-correct') return feedback(id, 'correct')
 if (action === 'feedback-incorrect') return feedback(id, 'incorrect')
 if (action === 'quarantine') return quarantine(id)
 if (action === 'unquarantine') return unquarantine(id)
 if (action === 'critical') return toggleCritical(id)
 if (action === 'github-issue') return githubIssue(id)
}

function handleOpen(element) {
 const kind = element.dataset.open
 const id = element.dataset.id
 if (kind === 'test') return openTestDrawer(id)
 if (kind === 'incident') {
  const item = state.incidents.find(value => value.fingerprint === id)
  if (item) openDrawerShell('Incident', item.title || 'Incident', incidentDrawer(item))
 }
 if (kind === 'analysis') {
  const item = state.analyses.find(value => value.id === id)
  if (item) openDrawerShell('Diagnosis', item.summary || 'Diagnosis', analysisDrawer(item))
 }
}

function renderAll() {
 renderRepositoryFilter()
 renderOverview()
 renderIncidentTable()
 renderAnalysisFilters()
 renderAnalysisTable()
 renderTestTable()
 renderOperations()
 renderNavigationCounts()
 $('updated-at').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
}

async function load(force = false) {
 if (!state.authenticated) return
 if (state.loading && !force) return
 setLoading(true)
 setError()
 try {
  const range = encodeURIComponent($('range').value)
  const [dashboard, repositories, deliveries, tests, analyses, incidents, status] = await Promise.all([
   api(`/api/v1/dashboard?range=${range}`), api('/api/v1/repositories'), api('/api/v1/notifications/deliveries?limit=100'),
   api('/api/v1/tests?limit=1000'), api('/api/v1/analyses?limit=1000'), api('/api/v1/incidents?limit=1000'), api('/api/v1/status')
  ])
  if (!state.authenticated) return
  state.dashboard = dashboard
  state.repositories = repositories.repositories || []
  state.deliveries = deliveries.deliveries || []
  state.tests = tests.tests || []
  state.analyses = analyses.analyses || analyses || []
  state.incidents = incidents.incidents || incidents || []
  state.providers = status.connectors_enabled || []
  renderAll()
 } catch (error) {
  if (error.status !== 401) setError(error.message)
 } finally {
  setLoading(false)
 }
}

function applyTheme(theme) {
 const light = theme === 'light'
 document.body.classList.toggle('light', light)
 localStorage.ciradarTheme = light ? 'light' : 'dark'
}

function toggleTheme() {
 applyTheme(document.body.classList.contains('light') ? 'dark' : 'light')
}

function toggleSessionMenu(force) {
 const menu = $('session-menu')
 const open = force === undefined ? menu.hidden : force
 menu.hidden = !open
 $('session-open').setAttribute('aria-expanded', String(open))
}

async function bootstrap() {
 if (bootstrapping) return
 bootstrapping = true
 applyTheme(localStorage.ciradarTheme === 'light' ? 'light' : 'dark')
 try {
  const identity = await authIdentity()
  if (!identity) {
   showLogin()
   return
  }
  showApp(identity)
  if (identity.tenant_id) {
   $('tenant').value = identity.tenant_id
   sessionStorage.ciradarTenant = identity.tenant_id
  }
  switchTab(location.hash.slice(1) || 'overview')
  await load(true)
 } catch (error) {
  showLogin(error.message)
 } finally {
  bootstrapping = false
 }
}

document.addEventListener('click', event => {
 const action = event.target.closest('button[data-action]')
 if (action) {
  event.stopPropagation()
  act(action).catch(error => {
   if (error.status !== 401) setError(error.message)
  })
  return
 }
 const tab = event.target.closest('[data-tab]')
 if (tab) return switchTab(tab.dataset.tab)
 const jump = event.target.closest('[data-tab-jump]')
 if (jump) return switchTab(jump.dataset.tabJump)
 const open = event.target.closest('[data-open]')
 if (open) return handleOpen(open)
 if (!event.target.closest('.session-control')) toggleSessionMenu(false)
})

document.addEventListener('keydown', event => {
 if (event.key === 'Enter' && event.target.matches('[data-open]')) handleOpen(event.target)
 if (event.key === 'Escape' && !$('action-dialog').open) {
  toggleSessionMenu(false)
  closeDrawer()
 }
})

for (const id of ['incident-search', 'incident-state', 'incident-severity']) $(id).addEventListener('input', renderIncidentTable)
for (const id of ['analysis-search', 'analysis-attribution', 'analysis-category']) $(id).addEventListener('input', renderAnalysisTable)
for (const id of ['test-search', 'test-state', 'test-sort', 'test-critical']) $(id).addEventListener('input', renderTestTable)

$('repository-filter').addEventListener('change', renderAll)
$('range').addEventListener('change', () => load(true))
$('refresh').addEventListener('click', () => load(true))
$('theme-toggle').addEventListener('click', toggleTheme)
$('session-open').addEventListener('click', () => toggleSessionMenu())
$('token-login-form').addEventListener('submit', event => {
 event.preventDefault()
 secureLogin().catch(error => loginError(error.message))
})
$('sso-login').addEventListener('click', startSSO)
$('logout').addEventListener('click', () => location.assign('/auth/logout'))
$('drawer-close').addEventListener('click', closeDrawer)
$('backdrop').addEventListener('click', closeDrawer)
$('action-close').addEventListener('click', closeActionDialog)
$('action-cancel').addEventListener('click', closeActionDialog)
$('action-form').addEventListener('submit', submitAction)

window.addEventListener('hashchange', () => {
 if (state.authenticated) switchTab(location.hash.slice(1) || 'overview')
})

document.addEventListener('visibilitychange', () => {
 if (!document.hidden && state.authenticated) load()
})

setInterval(() => {
 if (!document.hidden && state.authenticated) load()
}, 30000)

bootstrap()
