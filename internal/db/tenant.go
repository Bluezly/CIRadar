package db

import (
	"context"
	"crypto/subtle"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
)

var tenantIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func (s *Store) CreateTenant(ctx context.Context, id, name string) (model.Tenant, error) {
	_ = ctx
	id = strings.ToLower(strings.TrimSpace(id))
	name = strings.TrimSpace(name)
	if id == "" || name == "" {
		return model.Tenant{}, fmt.Errorf("tenant id and name are required")
	}
	if !tenantIDPattern.MatchString(id) {
		return model.Tenant{}, fmt.Errorf("tenant id must match %s", tenantIDPattern.String())
	}
	if len(name) > 120 {
		return model.Tenant{}, fmt.Errorf("tenant name is too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Tenants[id]; ok {
		return model.Tenant{}, fmt.Errorf("tenant %q already exists", id)
	}
	now := time.Now().UTC()
	t := model.Tenant{ID: id, Name: name, Enabled: true, CreatedAt: now, UpdatedAt: now}
	s.state.Tenants[id] = t
	return t, s.persistLocked()
}

func (s *Store) ListTenants(ctx context.Context) ([]model.Tenant, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Tenant, 0, len(s.state.Tenants))
	for _, t := range s.state.Tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) GetTenant(ctx context.Context, id string) (*model.Tenant, error) {
	_ = ctx
	id = normalizeTenant(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tenants[id]
	if !ok {
		return nil, nil
	}
	out := t
	return &out, nil
}

func (s *Store) SetTenantEnabled(ctx context.Context, id string, enabled bool) error {
	_ = ctx
	id = normalizeTenant(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tenants[id]
	if !ok {
		return fmt.Errorf("tenant %q not found", id)
	}
	if !enabled && t.Enabled {
		enabledCount := 0
		for _, tenant := range s.state.Tenants {
			if tenant.Enabled {
				enabledCount++
			}
		}
		if enabledCount <= 1 {
			return fmt.Errorf("cannot disable the last enabled tenant")
		}
	}
	t.Enabled = enabled
	t.UpdatedAt = time.Now().UTC()
	s.state.Tenants[id] = t
	return s.persistLocked()
}

func (s *Store) CreateAPIKey(ctx context.Context, tenantID, name string, role model.Role) (model.APIKey, string, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	name = strings.TrimSpace(name)
	if name == "" {
		return model.APIKey{}, "", fmt.Errorf("key name is required")
	}
	if !validRole(role) {
		return model.APIKey{}, "", fmt.Errorf("invalid role %q", role)
	}
	secret, err := randomText(32)
	if err != nil {
		return model.APIKey{}, "", err
	}
	idPart, err := randomText(9)
	if err != nil {
		return model.APIKey{}, "", err
	}
	id := "key_" + idPart
	token := "cir_" + tenantID + "_" + secret
	prefix := token
	if len(prefix) > 18 {
		prefix = prefix[:18]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.state.Tenants[tenantID]; !ok || !t.Enabled {
		return model.APIKey{}, "", fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	now := time.Now().UTC()
	key := model.APIKey{ID: id, TenantID: tenantID, Name: name, Prefix: prefix, Role: role, CreatedAt: now}
	s.state.APIKeys[id] = apiKeyRecord{Key: key, Hash: hashToken(token)}
	if err := s.persistLocked(); err != nil {
		return model.APIKey{}, "", err
	}
	return key, token, nil
}

func (s *Store) AuthenticateAPIKey(ctx context.Context, token string) (*model.Principal, error) {
	_ = ctx
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	h := hashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, rec := range s.state.APIKeys {
		if !rec.Key.RevokedAt.IsZero() {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(rec.Hash), []byte(h)) != 1 {
			continue
		}
		t, ok := s.state.Tenants[rec.Key.TenantID]
		if !ok || !t.Enabled {
			return nil, nil
		}
		if rec.Key.LastUsedAt.IsZero() || now.Sub(rec.Key.LastUsedAt) >= 5*time.Minute {
			rec.Key.LastUsedAt = now
			s.state.APIKeys[id] = rec
			_ = s.persistLocked()
		}
		return &model.Principal{TenantID: rec.Key.TenantID, Name: rec.Key.Name, Role: rec.Key.Role, APIKeyID: id}, nil
	}
	return nil, nil
}

func (s *Store) ListAPIKeys(ctx context.Context, tenantID string) ([]model.APIKey, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.APIKey{}
	for _, rec := range s.state.APIKeys {
		if rec.Key.TenantID == tenantID {
			out = append(out, rec.Key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, tenantID, id string) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.APIKeys[id]
	if !ok || rec.Key.TenantID != tenantID {
		return fmt.Errorf("api key not found")
	}
	if rec.Key.RevokedAt.IsZero() {
		rec.Key.RevokedAt = time.Now().UTC()
		s.state.APIKeys[id] = rec
	}
	return s.persistLocked()
}

func (s *Store) BindInstallation(ctx context.Context, tenantID string, installationID int64) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenant, ok := s.state.Tenants[tenantID]; !ok || !tenant.Enabled {
		return fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	s.state.InstallationTenants[strconv.FormatInt(installationID, 10)] = tenantID
	return s.persistLocked()
}

func (s *Store) UnbindInstallation(ctx context.Context, installationID int64) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strconv.FormatInt(installationID, 10)
	if _, ok := s.state.InstallationTenants[key]; !ok {
		return fmt.Errorf("GitHub installation %d is not bound", installationID)
	}
	delete(s.state.InstallationTenants, key)
	return s.persistLocked()
}

func (s *Store) ResolveInstallationTenant(ctx context.Context, installationID int64) (string, bool) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.state.InstallationTenants[strconv.FormatInt(installationID, 10)]; t != "" {
		return normalizeTenant(t), true
	}
	return model.DefaultTenantID, false
}
func (s *Store) TenantForInstallation(ctx context.Context, installationID int64) string {
	t, _ := s.ResolveInstallationTenant(ctx, installationID)
	return t
}

func (s *Store) ListInstallationBindings(ctx context.Context) map[string]string {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.state.InstallationTenants {
		out[k] = v
	}
	return out
}

func (s *Store) RecordAudit(ctx context.Context, event model.AuditEvent) error {
	_ = ctx
	event.TenantID = normalizeTenant(event.TenantID)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.ID == "" {
		r, _ := randomText(12)
		event.ID = "audit_" + r
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.AuditEvents[event.ID]; !ok {
		s.state.AuditOrder = append(s.state.AuditOrder, event.ID)
	}
	s.state.AuditEvents[event.ID] = event
	return s.persistLocked()
}

func (s *Store) ListAudit(ctx context.Context, tenantID string, limit int) ([]model.AuditEvent, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.AuditEvent, 0, limit)
	for i := len(s.state.AuditOrder) - 1; i >= 0 && len(out) < limit; i-- {
		if e, ok := s.state.AuditEvents[s.state.AuditOrder[i]]; ok && e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) UpsertRepositoryProfile(ctx context.Context, p model.RepositoryProfile) (model.RepositoryProfile, error) {
	_ = ctx
	p.TenantID = normalizeTenant(p.TenantID)
	p.Repository = strings.TrimSpace(p.Repository)
	if p.Repository == "" || !validRepositoryName(p.Repository) {
		return model.RepositoryProfile{}, fmt.Errorf("repository must be in owner/name form")
	}
	p.Criticality = strings.ToLower(strings.TrimSpace(p.Criticality))
	if p.Criticality == "" {
		p.Criticality = "normal"
	}
	if !validCriticality(p.Criticality) {
		return model.RepositoryProfile{}, fmt.Errorf("criticality must be low, normal, high, or critical")
	}
	p.Team = trimField(p.Team, 120)
	p.Owner = trimField(p.Owner, 120)
	p.NotificationChannels = uniqueNonEmpty(p.NotificationChannels)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.state.Tenants[p.TenantID]; !ok || !t.Enabled {
		return model.RepositoryProfile{}, fmt.Errorf("tenant %q not found or disabled", p.TenantID)
	}
	key := profileKey(p.TenantID, p.Repository)
	if old, ok := s.state.RepositoryProfiles[key]; ok {
		p.CreatedAt = old.CreatedAt
	} else {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p.NotificationChannels = append([]string(nil), p.NotificationChannels...)
	s.state.RepositoryProfiles[key] = p
	return p, s.persistLocked()
}

func (s *Store) GetRepositoryProfile(ctx context.Context, tenantID, repository string) (*model.RepositoryProfile, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.RepositoryProfiles[profileKey(tenantID, repository)]
	if !ok {
		return nil, nil
	}
	out := p
	return &out, nil
}

func (s *Store) ListRepositoryProfiles(ctx context.Context, tenantID string) ([]model.RepositoryProfile, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.RepositoryProfile{}
	for _, p := range s.state.RepositoryProfiles {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out, nil
}

func (s *Store) UpdateIncidentState(ctx context.Context, tenantID, fingerprint, state, actor, note string) (*model.Incident, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	state = strings.ToLower(strings.TrimSpace(state))
	if state != "open" && state != "acknowledged" && state != "resolved" {
		return nil, fmt.Errorf("invalid incident state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := incidentKey(tenantID, fingerprint)
	inc, ok := s.state.Incidents[key]
	if !ok {
		return nil, nil
	}
	now := time.Now().UTC()
	inc.State = state
	switch state {
	case "acknowledged":
		inc.AcknowledgedAt = now
		inc.AcknowledgedBy = actor
	case "resolved":
		inc.ResolvedAt = now
		inc.ResolvedBy = actor
		inc.ResolutionNote = strings.TrimSpace(note)
	case "open":
		inc.ResolvedAt = time.Time{}
		inc.ResolvedBy = ""
		inc.ResolutionNote = ""
	}
	s.state.Incidents[key] = inc
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	out := inc
	return &out, nil
}

func (s *Store) Dashboard(ctx context.Context, tenantID string, since time.Time) (model.DashboardSummary, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	d := model.DashboardSummary{TenantID: tenantID, Since: since.UTC(), GeneratedAt: time.Now().UTC(), Categories: map[string]int{}, Providers: map[string]int{}, RepositoryFailures: map[string]int{}, DailyAnalyses: map[string]int{}, DailyIncidents: map[string]int{}, DailyTestFailures: map[string]int{}, DailyCost: map[string]float64{}}
	for _, rec := range s.state.Analyses {
		if normalizeTenant(rec.TenantID) != tenantID || rec.Result.CreatedAt.Before(since) {
			continue
		}
		r := rec.Result
		d.TotalAnalyses++
		switch r.Attribution {
		case model.AttributionExternal:
			d.ExternalAnalyses++
		case model.AttributionCode:
			d.CodeAnalyses++
		case model.AttributionMixed:
			d.MixedAnalyses++
		case model.AttributionToolchain:
			d.ToolchainAnalyses++
		default:
			d.UnknownAnalyses++
		}
		d.Categories[string(r.Category)]++
		d.Providers[r.Provider]++
		if rec.Input.Repository != "" {
			d.RepositoryFailures[rec.Input.Repository]++
		}
		d.DailyAnalyses[r.CreatedAt.UTC().Format("2006-01-02")]++
	}
	repos := map[string]struct{}{}
	for _, rec := range s.state.Analyses {
		if normalizeTenant(rec.TenantID) == tenantID && rec.Input.Repository != "" {
			repos[rec.Input.Repository] = struct{}{}
		}
	}
	d.Repositories = len(repos)
	for _, inc := range s.state.Incidents {
		if normalizeTenant(inc.TenantID) != tenantID {
			continue
		}
		if !inc.FirstSeenAt.Before(since) {
			d.DailyIncidents[inc.FirstSeenAt.UTC().Format("2006-01-02")]++
		}
		if inc.State == "open" {
			d.OpenIncidents++
		}
		if inc.State == "acknowledged" {
			d.AcknowledgedIncidents++
		}
		if inc.Severity == "critical" && (inc.State == "open" || inc.State == "acknowledged") {
			d.CriticalIncidents++
		}
		d.RecentIncidents = append(d.RecentIncidents, inc)
	}
	for _, nd := range s.state.NotificationDeliveries {
		if normalizeTenant(nd.TenantID) == tenantID && nd.Status == "failed" {
			d.NotificationFailures++
		}
	}
	for _, f := range s.state.DiagnosisFeedback {
		if f.TenantID != tenantID {
			continue
		}
		d.DiagnosisFeedback.Total++
		switch f.Verdict {
		case "correct":
			d.DiagnosisFeedback.Correct++
		case "partial":
			d.DiagnosisFeedback.Partial++
		case "incorrect":
			d.DiagnosisFeedback.Incorrect++
		}
	}
	if d.DiagnosisFeedback.Total > 0 {
		d.DiagnosisFeedback.PrecisionPercent = (float64(d.DiagnosisFeedback.Correct) + 0.5*float64(d.DiagnosisFeedback.Partial)) * 100 / float64(d.DiagnosisFeedback.Total)
	}
	now := time.Now().UTC()
	for _, observation := range s.state.TestObservations {
		if normalizeTenant(observation.TenantID) != tenantID || observation.OccurredAt.Before(since) {
			continue
		}
		if observation.Status == "failed" || observation.Status == "error" {
			d.DailyTestFailures[observation.OccurredAt.UTC().Format("2006-01-02")]++
		}
	}
	for _, st := range s.state.TestCaseStats {
		if st.TenantID != tenantID {
			continue
		}
		d.TestCasesTracked++
		if st.Classification == "flaky" {
			d.FlakyTests++
		}
		if q, ok := s.state.TestQuarantines[quarantineKey(tenantID, st.TestKey)]; ok && q.Active && q.ExpiresAt.After(now) {
			d.QuarantinedTests++
		}
	}
	sort.Slice(d.RecentIncidents, func(i, j int) bool { return d.RecentIncidents[i].LastSeenAt.After(d.RecentIncidents[j].LastSeenAt) })
	if len(d.RecentIncidents) > 10 {
		d.RecentIncidents = d.RecentIncidents[:10]
	}
	for i := len(s.state.AnalysisOrder) - 1; i >= 0 && len(d.RecentAnalyses) < 20; i-- {
		if rec, ok := s.state.Analyses[s.state.AnalysisOrder[i]]; ok && normalizeTenant(rec.TenantID) == tenantID {
			d.RecentAnalyses = append(d.RecentAnalyses, rec.Result)
		}
	}
	return d, nil
}

func validCriticality(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low", "normal", "high", "critical":
		return true
	default:
		return false
	}
}

func validRepositoryName(v string) bool {
	parts := strings.Split(v, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || len(part) > 100 || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func trimField(v string, max int) string {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return v[:max]
	}
	return v
}

func uniqueNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
