package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ciradar/internal/model"
)

type Store struct {
	mu     sync.Mutex
	path   string
	state  state
	closed bool
}

type state struct {
	Version                int                                   `json:"version"`
	NextJobID              int64                                 `json:"next_job_id"`
	Deliveries             map[string]deliveryRecord             `json:"deliveries"`
	Jobs                   []jobRecord                           `json:"jobs"`
	Analyses               map[string]analysisRecord             `json:"analyses"`
	AnalysisOrder          []string                              `json:"analysis_order"`
	Environments           []environmentRecord                   `json:"environments"`
	Incidents              map[string]model.Incident             `json:"incidents"`
	ProviderStatuses       map[string]model.ProviderStatus       `json:"provider_statuses"`
	NotificationDeliveries map[string]model.NotificationDelivery `json:"notification_deliveries"`
	NotificationOrder      []string                              `json:"notification_order"`
	Tenants                map[string]model.Tenant               `json:"tenants"`
	APIKeys                map[string]apiKeyRecord               `json:"api_keys"`
	AuditEvents            map[string]model.AuditEvent           `json:"audit_events"`
	AuditOrder             []string                              `json:"audit_order"`
	InstallationTenants    map[string]string                     `json:"installation_tenants"`
	RepositoryProfiles     map[string]model.RepositoryProfile    `json:"repository_profiles"`
	DiagnosisFeedback      map[string]model.DiagnosisFeedback    `json:"diagnosis_feedback"`
	TestObservations       map[string]model.TestObservation      `json:"test_observations"`
	TestObservationOrder   []string                              `json:"test_observation_order"`
	TestCaseStats          map[string]model.TestCaseStats        `json:"test_case_stats"`
	TestQuarantines        map[string]model.TestQuarantine       `json:"test_quarantines"`
	Extensions             map[string]ExtensionObject            `json:"extensions"`
}

type apiKeyRecord struct {
	Key  model.APIKey `json:"key"`
	Hash string       `json:"hash"`
}

type deliveryRecord struct {
	EventType  string    `json:"event_type"`
	ReceivedAt time.Time `json:"received_at"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}
type jobRecord struct {
	TenantID    string          `json:"tenant_id,omitempty"`
	ID          int64           `json:"id"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	AvailableAt time.Time       `json:"available_at"`
	LockedAt    time.Time       `json:"locked_at,omitempty"`
	LockedBy    string          `json:"locked_by,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}
type analysisRecord struct {
	TenantID string               `json:"tenant_id,omitempty"`
	Input    model.AnalysisInput  `json:"input"`
	Result   model.AnalysisResult `json:"result"`
}
type environmentRecord struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	Repository  string            `json:"repository"`
	Workflow    string            `json:"workflow"`
	Job         string            `json:"job"`
	CommitSHA   string            `json:"commit_sha"`
	Successful  bool              `json:"successful"`
	Environment model.Environment `json:"environment"`
	CreatedAt   time.Time         `json:"created_at"`
}

type Job struct {
	TenantID string
	ID       int64
	Type     string
	Payload  json.RawMessage
	Attempts int
}
type CorrelationStats struct {
	Repositories  int
	Organizations int
	Occurrences   int
}
type Stats struct {
	Analyses               int `json:"analyses"`
	Incidents              int `json:"incidents"`
	OpenIncidents          int `json:"open_incidents"`
	QueuedJobs             int `json:"queued_jobs"`
	Repositories           int `json:"repositories"`
	NotificationDeliveries int `json:"notification_deliveries"`
	NotificationFailures   int `json:"notification_failures"`
}

func Open(path string) (*Store, error) {
	if path == "" {
		path = filepath.Join(".ciradar", "ciradar-state.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	s := &Store{path: path, state: newState()}
	b, err := os.ReadFile(path)
	if err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &s.state); err != nil {
			backup, backupErr := os.ReadFile(path + ".bak")
			if backupErr != nil || json.Unmarshal(backup, &s.state) != nil {
				return nil, fmt.Errorf("decode state file: %w", err)
			}
		}
		s.normalize()
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func newState() state {
	now := time.Now().UTC()
	return state{Version: 3, NextJobID: 1, Deliveries: map[string]deliveryRecord{}, Analyses: map[string]analysisRecord{}, Incidents: map[string]model.Incident{}, ProviderStatuses: map[string]model.ProviderStatus{}, NotificationDeliveries: map[string]model.NotificationDelivery{}, Tenants: map[string]model.Tenant{model.DefaultTenantID: {ID: model.DefaultTenantID, Name: "Default", Enabled: true, CreatedAt: now, UpdatedAt: now}}, APIKeys: map[string]apiKeyRecord{}, AuditEvents: map[string]model.AuditEvent{}, InstallationTenants: map[string]string{}, RepositoryProfiles: map[string]model.RepositoryProfile{}, DiagnosisFeedback: map[string]model.DiagnosisFeedback{}, TestObservations: map[string]model.TestObservation{}, TestCaseStats: map[string]model.TestCaseStats{}, TestQuarantines: map[string]model.TestQuarantine{}, Extensions: map[string]ExtensionObject{}}
}
func (s *Store) normalize() {
	if s.state.Version < 3 {
		s.state.Version = 3
	}
	if s.state.NextJobID < 1 {
		s.state.NextJobID = 1
	}
	if s.state.Deliveries == nil {
		s.state.Deliveries = map[string]deliveryRecord{}
	}
	if s.state.Analyses == nil {
		s.state.Analyses = map[string]analysisRecord{}
	}
	if s.state.Incidents == nil {
		s.state.Incidents = map[string]model.Incident{}
	}
	if s.state.ProviderStatuses == nil {
		s.state.ProviderStatuses = map[string]model.ProviderStatus{}
	}
	if s.state.NotificationDeliveries == nil {
		s.state.NotificationDeliveries = map[string]model.NotificationDelivery{}
	}
	if s.state.Tenants == nil {
		s.state.Tenants = map[string]model.Tenant{}
	}
	if _, ok := s.state.Tenants[model.DefaultTenantID]; !ok {
		now := time.Now().UTC()
		s.state.Tenants[model.DefaultTenantID] = model.Tenant{ID: model.DefaultTenantID, Name: "Default", Enabled: true, CreatedAt: now, UpdatedAt: now}
	}
	if s.state.APIKeys == nil {
		s.state.APIKeys = map[string]apiKeyRecord{}
	}
	if s.state.AuditEvents == nil {
		s.state.AuditEvents = map[string]model.AuditEvent{}
	}
	if s.state.InstallationTenants == nil {
		s.state.InstallationTenants = map[string]string{}
	}
	if s.state.RepositoryProfiles == nil {
		s.state.RepositoryProfiles = map[string]model.RepositoryProfile{}
	}
	if s.state.DiagnosisFeedback == nil {
		s.state.DiagnosisFeedback = map[string]model.DiagnosisFeedback{}
	}
	if s.state.TestObservations == nil {
		s.state.TestObservations = map[string]model.TestObservation{}
	}
	if s.state.TestCaseStats == nil {
		s.state.TestCaseStats = map[string]model.TestCaseStats{}
	}
	if s.state.TestQuarantines == nil {
		s.state.TestQuarantines = map[string]model.TestQuarantine{}
	}
	if s.state.Extensions == nil {
		s.state.Extensions = map[string]ExtensionObject{}
	}
	for id, rec := range s.state.Analyses {
		t := normalizeTenant(rec.TenantID)
		rec.TenantID = t
		rec.Input.TenantID = t
		rec.Result.TenantID = t
		s.state.Analyses[id] = rec
	}
	for i := range s.state.Environments {
		s.state.Environments[i].TenantID = normalizeTenant(s.state.Environments[i].TenantID)
	}
	for i := range s.state.Jobs {
		s.state.Jobs[i].TenantID = normalizeTenant(s.state.Jobs[i].TenantID)
	}
	for key, inc := range s.state.Incidents {
		inc.TenantID = normalizeTenant(inc.TenantID)
		newKey := incidentKey(inc.TenantID, inc.Fingerprint)
		if key != newKey {
			delete(s.state.Incidents, key)
			s.state.Incidents[newKey] = inc
		} else {
			s.state.Incidents[key] = inc
		}
	}
	newNotifications := make(map[string]model.NotificationDelivery, len(s.state.NotificationDeliveries))
	newNotificationOrder := make([]string, 0, len(s.state.NotificationOrder))
	seenNotification := map[string]struct{}{}
	for _, oldKey := range s.state.NotificationOrder {
		d, ok := s.state.NotificationDeliveries[oldKey]
		if !ok {
			continue
		}
		d.TenantID = normalizeTenant(d.TenantID)
		key := notificationKey(d.TenantID, d.EventID, d.Channel)
		d.ID = key
		newNotifications[key] = d
		if _, ok := seenNotification[key]; !ok {
			newNotificationOrder = append(newNotificationOrder, key)
			seenNotification[key] = struct{}{}
		}
	}
	for _, d := range s.state.NotificationDeliveries {
		d.TenantID = normalizeTenant(d.TenantID)
		key := notificationKey(d.TenantID, d.EventID, d.Channel)
		d.ID = key
		newNotifications[key] = d
		if _, ok := seenNotification[key]; !ok {
			newNotificationOrder = append(newNotificationOrder, key)
			seenNotification[key] = struct{}{}
		}
	}
	s.state.NotificationDeliveries = newNotifications
	s.state.NotificationOrder = newNotificationOrder
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.persistLocked()
}
func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if current, err := os.ReadFile(s.path); err == nil && len(current) > 0 {
		_ = os.WriteFile(s.path+".bak", current, 0o600)
	}
	if runtimeWindows() {
		_ = os.Remove(s.path)
	}
	return os.Rename(tmp, s.path)
}

func runtimeWindows() bool { return filepath.Separator == '\\' }

func normalizeTenant(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return model.DefaultTenantID
	}
	return v
}
func incidentKey(tenantID, fingerprint string) string {
	return normalizeTenant(tenantID) + "|" + fingerprint
}
func profileKey(tenantID, repository string) string {
	return normalizeTenant(tenantID) + "|" + strings.ToLower(strings.TrimSpace(repository))
}
func notificationKey(tenantID, eventID, channel string) string {
	return normalizeTenant(tenantID) + "|" + eventID + "|" + channel
}
func randomText(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func validRole(role model.Role) bool {
	return role == model.RoleViewer || role == model.RoleOperator || role == model.RoleAdmin
}
func incidentSeverityRank(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return 4
	case "major":
		return 3
	case "minor":
		return 2
	default:
		return 1
	}
}

func (s *Store) RecordDelivery(ctx context.Context, id, eventType string) (bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Deliveries[id]; ok {
		return false, nil
	}
	s.state.Deliveries[id] = deliveryRecord{EventType: eventType, ReceivedAt: time.Now().UTC(), Status: "received"}
	return true, s.persistLocked()
}
func (s *Store) UpdateDelivery(ctx context.Context, id, status, errText string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.state.Deliveries[id]
	if !ok {
		return nil
	}
	d.Status = status
	d.Error = errText
	s.state.Deliveries[id] = d
	return s.persistLocked()
}
func (s *Store) Enqueue(ctx context.Context, typ string, payload any, availableAt time.Time) error {
	tenantID := model.DefaultTenantID
	switch v := payload.(type) {
	case model.NotificationEvent:
		tenantID = normalizeTenant(v.TenantID)
	case *model.NotificationEvent:
		if v != nil {
			tenantID = normalizeTenant(v.TenantID)
		}
	case model.GitHubWorkflowRunEvent:
		tenantID = normalizeTenant(v.TenantID)
	case *model.GitHubWorkflowRunEvent:
		if v != nil {
			tenantID = normalizeTenant(v.TenantID)
		}
	}
	return s.EnqueueForTenant(ctx, tenantID, typ, payload, availableAt)
}
func (s *Store) EnqueueForTenant(ctx context.Context, tenantID, typ string, payload any, availableAt time.Time) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenant, ok := s.state.Tenants[tenantID]; !ok || !tenant.Enabled {
		return fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	now := time.Now().UTC()
	j := jobRecord{TenantID: tenantID, ID: s.state.NextJobID, Type: typ, Payload: b, Status: "queued", AvailableAt: availableAt.UTC(), CreatedAt: now, UpdatedAt: now}
	s.state.NextJobID++
	s.state.Jobs = append(s.state.Jobs, j)
	return s.persistLocked()
}
func (s *Store) ClaimJob(ctx context.Context, workerID string) (*Job, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	idx := -1
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		tenant, exists := s.state.Tenants[normalizeTenant(j.TenantID)]
		if !exists || !tenant.Enabled {
			continue
		}
		if j.Status == "queued" && !j.AvailableAt.After(now) {
			if idx < 0 || j.ID < s.state.Jobs[idx].ID {
				idx = i
			}
		}
	}
	if idx < 0 {
		return nil, nil
	}
	j := &s.state.Jobs[idx]
	j.Status = "running"
	j.LockedAt = now
	j.LockedBy = workerID
	j.Attempts++
	j.UpdatedAt = now
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &Job{TenantID: normalizeTenant(j.TenantID), ID: j.ID, Type: j.Type, Payload: append(json.RawMessage(nil), j.Payload...), Attempts: j.Attempts}, nil
}
func (s *Store) CompleteJob(ctx context.Context, id int64) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Jobs {
		if s.state.Jobs[i].ID == id {
			s.state.Jobs[i].Status = "done"
			s.state.Jobs[i].LockedAt = time.Time{}
			s.state.Jobs[i].LockedBy = ""
			s.state.Jobs[i].UpdatedAt = time.Now().UTC()
			break
		}
	}
	return s.persistLocked()
}
func (s *Store) FailJob(ctx context.Context, id int64, attempts int, errText string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		if j.ID == id {
			j.Status = "queued"
			if attempts >= 8 {
				j.Status = "failed"
			}
			j.LastError = trim(errText, 4000)
			j.AvailableAt = time.Now().UTC().Add(time.Duration(attempts*attempts) * 10 * time.Second)
			j.LockedAt = time.Time{}
			j.LockedBy = ""
			j.UpdatedAt = time.Now().UTC()
			break
		}
	}
	return s.persistLocked()
}
func (s *Store) RequeueStaleJobs(ctx context.Context, olderThan time.Duration) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().UTC().Add(-olderThan)
	changed := false
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		if j.Status == "running" && !j.LockedAt.IsZero() && j.LockedAt.Before(cut) {
			j.Status = "queued"
			j.LockedAt = time.Time{}
			j.LockedBy = ""
			j.UpdatedAt = time.Now().UTC()
			changed = true
		}
	}
	if changed {
		return s.persistLocked()
	}
	return nil
}

func (s *Store) RecordAnalysis(ctx context.Context, in model.AnalysisInput, r model.AnalysisResult, storeExcerpt, storeRaw bool) error {
	return s.RecordAnalysisForTenant(ctx, normalizeTenant(in.TenantID), in, r, storeExcerpt, storeRaw)
}

func (s *Store) RecordAnalysisForTenant(ctx context.Context, tenantID string, in model.AnalysisInput, r model.AnalysisResult, storeExcerpt, storeRaw bool) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Tenants[tenantID]; !ok {
		return fmt.Errorf("tenant %q not found", tenantID)
	}
	in.TenantID = tenantID
	r.TenantID = tenantID
	r.Repository = in.Repository
	r.Organization = in.Organization
	r.Workflow = in.Workflow
	r.Job = in.Job
	r.RunID = in.RunID
	r.CommitSHA = in.CommitSHA
	r.SourceProvider = in.SourceProvider
	r.SourceRunURL = in.SourceRunURL
	r.PullRequestNumber = in.PullRequestNumber
	r.MergeRequestNumber = in.MergeRequestNumber
	if !storeExcerpt {
		r.RedactedExcerpt = ""
	}
	if !storeRaw {
		in.Log = ""
	}
	if _, ok := s.state.Analyses[r.ID]; !ok {
		s.state.AnalysisOrder = append(s.state.AnalysisOrder, r.ID)
	}
	s.state.Analyses[r.ID] = analysisRecord{TenantID: tenantID, Input: in, Result: r}
	s.state.Environments = append(s.state.Environments, environmentRecord{TenantID: tenantID, Repository: in.Repository, Workflow: in.Workflow, Job: in.Job, CommitSHA: in.CommitSHA, Successful: false, Environment: r.Environment, CreatedAt: r.CreatedAt})
	return s.persistLocked()
}
func (s *Store) RecordSuccessfulEnvironment(ctx context.Context, repository, workflow, job, sha string, env model.Environment, at time.Time) error {
	return s.RecordSuccessfulEnvironmentForTenant(ctx, model.DefaultTenantID, repository, workflow, job, sha, env, at)
}

func (s *Store) RecordSuccessfulEnvironmentForTenant(ctx context.Context, tenantID, repository, workflow, job, sha string, env model.Environment, at time.Time) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Environments = append(s.state.Environments, environmentRecord{TenantID: tenantID, Repository: repository, Workflow: workflow, Job: job, CommitSHA: sha, Successful: true, Environment: env, CreatedAt: at.UTC()})
	return s.persistLocked()
}
func (s *Store) LastSuccessfulEnvironment(ctx context.Context, repository, workflow, job string) (*model.Environment, error) {
	return s.LastSuccessfulEnvironmentForTenant(ctx, model.DefaultTenantID, repository, workflow, job)
}

func (s *Store) LastSuccessfulEnvironmentForTenant(ctx context.Context, tenantID, repository, workflow, job string) (*model.Environment, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.state.Environments) - 1; i >= 0; i-- {
		e := s.state.Environments[i]
		if e.TenantID == tenantID && e.Successful && e.Repository == repository && (workflow == "" || e.Workflow == workflow) && (job == "" || e.Job == job) {
			env := e.Environment
			return &env, nil
		}
	}
	return nil, nil
}
func (s *Store) Correlation(ctx context.Context, fingerprint string, since time.Time) (CorrelationStats, error) {
	return s.CorrelationForTenant(ctx, model.DefaultTenantID, fingerprint, since, false)
}

func (s *Store) CorrelationForTenant(ctx context.Context, tenantID, fingerprint string, since time.Time, crossTenant bool) (CorrelationStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	repos := map[string]struct{}{}
	orgs := map[string]struct{}{}
	var c CorrelationStats
	for _, id := range s.state.AnalysisOrder {
		a, ok := s.state.Analyses[id]
		if !ok || a.Result.Fingerprint != fingerprint || a.Result.CreatedAt.Before(since) {
			continue
		}
		if !crossTenant && normalizeTenant(a.TenantID) != tenantID {
			continue
		}
		c.Occurrences++
		repoKey := normalizeTenant(a.TenantID) + "|" + a.Input.Repository
		orgKey := normalizeTenant(a.TenantID) + "|" + a.Input.Organization
		if a.Input.Repository != "" {
			repos[repoKey] = struct{}{}
		}
		if a.Input.Organization != "" {
			orgs[orgKey] = struct{}{}
		}
	}
	c.Repositories = len(repos)
	c.Organizations = len(orgs)
	return c, nil
}
func (s *Store) UpsertIncident(ctx context.Context, i model.Incident) error {
	return s.UpsertIncidentForTenant(ctx, normalizeTenant(i.TenantID), i)
}

func (s *Store) UpsertIncidentForTenant(ctx context.Context, tenantID string, i model.Incident) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	i.TenantID = tenantID
	s.mu.Lock()
	defer s.mu.Unlock()
	key := incidentKey(tenantID, i.Fingerprint)
	if old, ok := s.state.Incidents[key]; ok {
		if old.FirstSeenAt.Before(i.FirstSeenAt) {
			i.FirstSeenAt = old.FirstSeenAt
		}
		if incidentSeverityRank(old.Severity) > incidentSeverityRank(i.Severity) {
			i.Severity = old.Severity
		}
		if old.RepositoryCount > i.RepositoryCount {
			i.RepositoryCount = old.RepositoryCount
		}
		if old.OrganizationCount > i.OrganizationCount {
			i.OrganizationCount = old.OrganizationCount
		}
		if old.OccurrenceCount > i.OccurrenceCount {
			i.OccurrenceCount = old.OccurrenceCount
		}
		if old.State == "acknowledged" && i.State == "open" {
			i.State = old.State
			i.AcknowledgedAt = old.AcknowledgedAt
			i.AcknowledgedBy = old.AcknowledgedBy
		}
		if old.State == "resolved" && i.LastSeenAt.After(old.ResolvedAt) {
			i.State = "open"
			i.ResolvedAt = time.Time{}
			i.ResolvedBy = ""
			i.ResolutionNote = ""
		}
	}
	s.state.Incidents[key] = i
	return s.persistLocked()
}
func (s *Store) ListIncidents(ctx context.Context, limit int, stateFilter string) ([]model.Incident, error) {
	return s.ListIncidentsForTenant(ctx, model.DefaultTenantID, limit, stateFilter)
}

func (s *Store) ListIncidentsForTenant(ctx context.Context, tenantID string, limit int, stateFilter string) ([]model.Incident, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 100
	}
	out := make([]model.Incident, 0)
	for _, i := range s.state.Incidents {
		if normalizeTenant(i.TenantID) == tenantID && (stateFilter == "" || i.State == stateFilter) {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *Store) RecordProviderStatus(ctx context.Context, p model.ProviderStatus) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.ProviderStatuses[strings.ToLower(p.Provider)] = p
	return s.persistLocked()
}
func (s *Store) GetProviderStatus(ctx context.Context, provider string) (*model.ProviderStatus, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.state.ProviderStatuses[strings.ToLower(provider)]
	if !ok {
		return nil, nil
	}
	return &p, nil
}
func (s *Store) ListProviderStatuses(ctx context.Context) ([]model.ProviderStatus, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.ProviderStatus, 0, len(s.state.ProviderStatuses))
	for _, p := range s.state.ProviderStatuses {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	return s.StatsForTenant(ctx, model.DefaultTenantID)
}

func (s *Store) StatsForTenant(ctx context.Context, tenantID string) (Stats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{}
	repos := map[string]struct{}{}
	for _, a := range s.state.Analyses {
		if normalizeTenant(a.TenantID) != tenantID {
			continue
		}
		st.Analyses++
		if a.Input.Repository != "" {
			repos[a.Input.Repository] = struct{}{}
		}
	}
	st.Repositories = len(repos)
	for _, i := range s.state.Incidents {
		if normalizeTenant(i.TenantID) != tenantID {
			continue
		}
		st.Incidents++
		if i.State == "open" || i.State == "acknowledged" {
			st.OpenIncidents++
		}
	}
	for _, d := range s.state.NotificationDeliveries {
		if normalizeTenant(d.TenantID) != tenantID {
			continue
		}
		st.NotificationDeliveries++
		if d.Status == "failed" {
			st.NotificationFailures++
		}
	}
	for _, j := range s.state.Jobs {
		if normalizeTenant(j.TenantID) == tenantID && j.Status == "queued" {
			st.QueuedJobs++
		}
	}
	return st, nil
}
func (s *Store) GetAnalysis(ctx context.Context, id string) (*model.AnalysisResult, error) {
	return s.GetAnalysisForTenant(ctx, model.DefaultTenantID, id)
}

func (s *Store) GetAnalysisForTenant(ctx context.Context, tenantID, id string) (*model.AnalysisResult, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Analyses[id]
	if !ok || normalizeTenant(a.TenantID) != tenantID {
		return nil, nil
	}
	r := a.Result
	return &r, nil
}
func (s *Store) ListAnalyses(ctx context.Context, limit int) ([]model.AnalysisResult, error) {
	return s.ListAnalysesForTenant(ctx, model.DefaultTenantID, limit)
}

func (s *Store) ListAnalysesForTenant(ctx context.Context, tenantID string, limit int) ([]model.AnalysisResult, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 50
	}
	out := make([]model.AnalysisResult, 0, limit)
	for i := len(s.state.AnalysisOrder) - 1; i >= 0 && len(out) < limit; i-- {
		if a, ok := s.state.Analyses[s.state.AnalysisOrder[i]]; ok && normalizeTenant(a.TenantID) == tenantID {
			out = append(out, a.Result)
		}
	}
	return out, nil
}
func (s *Store) Cleanup(ctx context.Context, retentionDays int) error {
	_ = ctx
	if retentionDays < 1 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	newOrder := s.state.AnalysisOrder[:0]
	for _, id := range s.state.AnalysisOrder {
		a, ok := s.state.Analyses[id]
		if !ok {
			continue
		}
		if a.Result.CreatedAt.Before(cut) {
			delete(s.state.Analyses, id)
		} else {
			newOrder = append(newOrder, id)
		}
	}
	s.state.AnalysisOrder = newOrder
	envs := s.state.Environments[:0]
	for _, e := range s.state.Environments {
		if !e.CreatedAt.Before(cut) {
			envs = append(envs, e)
		}
	}
	s.state.Environments = envs
	jobs := s.state.Jobs[:0]
	for _, j := range s.state.Jobs {
		if j.Status == "queued" || j.Status == "running" || j.UpdatedAt.After(cut) {
			jobs = append(jobs, j)
		}
	}
	s.state.Jobs = jobs
	auditOrder := s.state.AuditOrder[:0]
	for _, id := range s.state.AuditOrder {
		a, ok := s.state.AuditEvents[id]
		if !ok {
			continue
		}
		if a.CreatedAt.Before(cut) {
			delete(s.state.AuditEvents, id)
		} else {
			auditOrder = append(auditOrder, id)
		}
	}
	s.state.AuditOrder = auditOrder
	notifyOrder := s.state.NotificationOrder[:0]
	for _, id := range s.state.NotificationOrder {
		d, ok := s.state.NotificationDeliveries[id]
		if !ok {
			continue
		}
		if d.UpdatedAt.Before(cut) {
			delete(s.state.NotificationDeliveries, id)
		} else {
			notifyOrder = append(notifyOrder, id)
		}
	}
	s.state.NotificationOrder = notifyOrder
	for key, incident := range s.state.Incidents {
		if incident.State == "resolved" && !incident.ResolvedAt.IsZero() && incident.ResolvedAt.Before(cut) {
			delete(s.state.Incidents, key)
		}
	}
	for id, delivery := range s.state.Deliveries {
		if delivery.ReceivedAt.Before(cut) {
			delete(s.state.Deliveries, id)
		}
	}
	return s.persistLocked()
}
func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Store) ResolveStaleIncidents(ctx context.Context, cutoff time.Time) (int, error) {
	items, err := s.ResolveStaleIncidentsDetailed(ctx, cutoff)
	return len(items), err
}

func (s *Store) ResolveStaleIncidentsDetailed(ctx context.Context, cutoff time.Time) ([]model.Incident, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := []model.Incident{}
	for key, incident := range s.state.Incidents {
		if (incident.State == "open" || incident.State == "acknowledged") && incident.LastSeenAt.Before(cutoff) {
			incident.State = "resolved"
			incident.ResolvedAt = now
			incident.ResolvedBy = "system"
			incident.ResolutionNote = "Automatically resolved after inactivity"
			s.state.Incidents[key] = incident
			out = append(out, incident)
		}
	}
	if len(out) > 0 {
		return out, s.persistLocked()
	}
	return out, nil
}

func (s *Store) GetIncident(ctx context.Context, fingerprint string) (*model.Incident, error) {
	return s.GetIncidentForTenant(ctx, model.DefaultTenantID, fingerprint)
}

func (s *Store) GetIncidentForTenant(ctx context.Context, tenantID, fingerprint string) (*model.Incident, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.state.Incidents[incidentKey(tenantID, fingerprint)]
	if !ok {
		return nil, nil
	}
	out := i
	return &out, nil
}

func (s *Store) RecordNotificationDelivery(ctx context.Context, d model.NotificationDelivery) error {
	_ = ctx
	d.TenantID = normalizeTenant(d.TenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = notificationKey(d.TenantID, d.EventID, d.Channel)
	}
	if old, ok := s.state.NotificationDeliveries[d.ID]; ok {
		if d.CreatedAt.IsZero() {
			d.CreatedAt = old.CreatedAt
		}
	} else {
		s.state.NotificationOrder = append(s.state.NotificationOrder, d.ID)
	}
	s.state.NotificationDeliveries[d.ID] = d
	return s.persistLocked()
}

func (s *Store) GetNotificationDelivery(ctx context.Context, eventID, channel string) (*model.NotificationDelivery, error) {
	return s.GetNotificationDeliveryForTenant(ctx, model.DefaultTenantID, eventID, channel)
}

func (s *Store) GetNotificationDeliveryForTenant(ctx context.Context, tenantID, eventID, channel string) (*model.NotificationDelivery, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.state.NotificationDeliveries[notificationKey(tenantID, eventID, channel)]
	if !ok {
		return nil, nil
	}
	out := d
	return &out, nil
}

func (s *Store) RecentlySentNotification(ctx context.Context, channel, dedupeKey string, since time.Time) (bool, error) {
	return s.RecentlySentNotificationForTenant(ctx, model.DefaultTenantID, channel, dedupeKey, since)
}

func (s *Store) RecentlySentNotificationForTenant(ctx context.Context, tenantID, channel, dedupeKey string, since time.Time) (bool, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.state.NotificationDeliveries {
		if normalizeTenant(d.TenantID) == tenantID && d.Channel == channel && d.DedupeKey == dedupeKey && d.Status == "sent" && !d.SentAt.Before(since) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) ListNotificationDeliveries(ctx context.Context, limit int) ([]model.NotificationDelivery, error) {
	return s.ListNotificationDeliveriesForTenant(ctx, model.DefaultTenantID, limit)
}

func (s *Store) ListNotificationDeliveriesForTenant(ctx context.Context, tenantID string, limit int) ([]model.NotificationDelivery, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 100
	}
	out := make([]model.NotificationDelivery, 0, limit)
	for i := len(s.state.NotificationOrder) - 1; i >= 0 && len(out) < limit; i-- {
		if d, ok := s.state.NotificationDeliveries[s.state.NotificationOrder[i]]; ok && normalizeTenant(d.TenantID) == tenantID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *Store) BeginNotificationDelivery(ctx context.Context, eventID, channel, channelType, dedupeKey string, cooldown time.Duration, maxAttempts int) (string, model.NotificationDelivery, error) {
	return s.BeginNotificationDeliveryForTenant(ctx, model.DefaultTenantID, eventID, channel, channelType, dedupeKey, cooldown, maxAttempts)
}

func (s *Store) BeginNotificationDeliveryForTenant(ctx context.Context, tenantID, eventID, channel, channelType, dedupeKey string, cooldown time.Duration, maxAttempts int) (string, model.NotificationDelivery, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	id := notificationKey(tenantID, eventID, channel)
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if old, ok := s.state.NotificationDeliveries[id]; ok {
		switch old.Status {
		case "sent", "suppressed", "failed":
			return "skip", old, nil
		case "sending":
			if old.UpdatedAt.After(now.Add(-2 * time.Minute)) {
				return "skip", old, nil
			}
		}
		if old.Attempts >= maxAttempts {
			old.Status = "failed"
			old.UpdatedAt = now
			s.state.NotificationDeliveries[id] = old
			return "skip", old, s.persistLocked()
		}
	}
	if cooldown > 0 && dedupeKey != "" {
		cut := now.Add(-cooldown)
		for _, existing := range s.state.NotificationDeliveries {
			if existing.ID == id || normalizeTenant(existing.TenantID) != tenantID || existing.Channel != channel || existing.DedupeKey != dedupeKey {
				continue
			}
			reason := ""
			if existing.Status == "sent" && !existing.SentAt.Before(cut) {
				reason = "cooldown"
			}
			if (existing.Status == "sending" || existing.Status == "retrying") && existing.UpdatedAt.After(now.Add(-2*time.Minute)) {
				reason = "in_flight"
			}
			if reason != "" {
				d := model.NotificationDelivery{ID: id, TenantID: tenantID, EventID: eventID, DedupeKey: dedupeKey, Channel: channel, ChannelType: channelType, Status: "suppressed", SuppressedReason: reason, CreatedAt: now, UpdatedAt: now}
				if _, exists := s.state.NotificationDeliveries[id]; !exists {
					s.state.NotificationOrder = append(s.state.NotificationOrder, id)
				}
				s.state.NotificationDeliveries[id] = d
				return "suppressed", d, s.persistLocked()
			}
		}
	}
	d, exists := s.state.NotificationDeliveries[id]
	if !exists {
		d = model.NotificationDelivery{ID: id, TenantID: tenantID, EventID: eventID, DedupeKey: dedupeKey, Channel: channel, ChannelType: channelType, CreatedAt: now}
		s.state.NotificationOrder = append(s.state.NotificationOrder, id)
	}
	d.Status = "sending"
	d.Attempts++
	d.UpdatedAt = now
	d.LastError = ""
	d.HTTPStatus = 0
	s.state.NotificationDeliveries[id] = d
	if err := s.persistLocked(); err != nil {
		return "", model.NotificationDelivery{}, err
	}
	return "send", d, nil
}
