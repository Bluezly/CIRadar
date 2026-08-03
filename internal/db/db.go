package db

import (
	"context"
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
	Version          int                             `json:"version"`
	NextJobID        int64                           `json:"next_job_id"`
	Deliveries       map[string]deliveryRecord       `json:"deliveries"`
	Jobs             []jobRecord                     `json:"jobs"`
	Analyses         map[string]analysisRecord       `json:"analyses"`
	AnalysisOrder    []string                        `json:"analysis_order"`
	Environments     []environmentRecord             `json:"environments"`
	Incidents        map[string]model.Incident       `json:"incidents"`
	ProviderStatuses map[string]model.ProviderStatus `json:"provider_statuses"`
}

type deliveryRecord struct {
	EventType  string    `json:"event_type"`
	ReceivedAt time.Time `json:"received_at"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}
type jobRecord struct {
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
	Input  model.AnalysisInput  `json:"input"`
	Result model.AnalysisResult `json:"result"`
}
type environmentRecord struct {
	Repository  string            `json:"repository"`
	Workflow    string            `json:"workflow"`
	Job         string            `json:"job"`
	CommitSHA   string            `json:"commit_sha"`
	Successful  bool              `json:"successful"`
	Environment model.Environment `json:"environment"`
	CreatedAt   time.Time         `json:"created_at"`
}

type Job struct {
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
	Analyses      int `json:"analyses"`
	Incidents     int `json:"incidents"`
	OpenIncidents int `json:"open_incidents"`
	QueuedJobs    int `json:"queued_jobs"`
	Repositories  int `json:"repositories"`
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
	return state{Version: 1, NextJobID: 1, Deliveries: map[string]deliveryRecord{}, Analyses: map[string]analysisRecord{}, Incidents: map[string]model.Incident{}, ProviderStatuses: map[string]model.ProviderStatus{}}
}
func (s *Store) normalize() {
	if s.state.Version == 0 {
		s.state.Version = 1
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
	_ = ctx
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	j := jobRecord{ID: s.state.NextJobID, Type: typ, Payload: b, Status: "queued", AvailableAt: availableAt.UTC(), CreatedAt: now, UpdatedAt: now}
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
	return &Job{ID: j.ID, Type: j.Type, Payload: append(json.RawMessage(nil), j.Payload...), Attempts: j.Attempts}, nil
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
			if attempts >= 5 {
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
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if !storeExcerpt {
		r.RedactedExcerpt = ""
	}
	if !storeRaw {
		in.Log = ""
	}
	if _, ok := s.state.Analyses[r.ID]; !ok {
		s.state.AnalysisOrder = append(s.state.AnalysisOrder, r.ID)
	}
	s.state.Analyses[r.ID] = analysisRecord{Input: in, Result: r}
	s.state.Environments = append(s.state.Environments, environmentRecord{Repository: in.Repository, Workflow: in.Workflow, Job: in.Job, CommitSHA: in.CommitSHA, Successful: false, Environment: r.Environment, CreatedAt: r.CreatedAt})
	return s.persistLocked()
}
func (s *Store) RecordSuccessfulEnvironment(ctx context.Context, repository, workflow, job, sha string, env model.Environment, at time.Time) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Environments = append(s.state.Environments, environmentRecord{Repository: repository, Workflow: workflow, Job: job, CommitSHA: sha, Successful: true, Environment: env, CreatedAt: at.UTC()})
	return s.persistLocked()
}
func (s *Store) LastSuccessfulEnvironment(ctx context.Context, repository, workflow, job string) (*model.Environment, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.state.Environments) - 1; i >= 0; i-- {
		e := s.state.Environments[i]
		if e.Successful && e.Repository == repository && (workflow == "" || e.Workflow == workflow) && (job == "" || e.Job == job) {
			env := e.Environment
			return &env, nil
		}
	}
	return nil, nil
}
func (s *Store) Correlation(ctx context.Context, fingerprint string, since time.Time) (CorrelationStats, error) {
	_ = ctx
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
		c.Occurrences++
		if a.Input.Repository != "" {
			repos[a.Input.Repository] = struct{}{}
		}
		if a.Input.Organization != "" {
			orgs[a.Input.Organization] = struct{}{}
		}
	}
	c.Repositories = len(repos)
	c.Organizations = len(orgs)
	return c, nil
}
func (s *Store) UpsertIncident(ctx context.Context, i model.Incident) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.state.Incidents[i.Fingerprint]; ok {
		if old.FirstSeenAt.Before(i.FirstSeenAt) {
			i.FirstSeenAt = old.FirstSeenAt
		}
	}
	s.state.Incidents[i.Fingerprint] = i
	return s.persistLocked()
}
func (s *Store) ListIncidents(ctx context.Context, limit int, stateFilter string) ([]model.Incident, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 100
	}
	out := make([]model.Incident, 0, len(s.state.Incidents))
	for _, i := range s.state.Incidents {
		if stateFilter == "" || i.State == stateFilter {
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
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Analyses: len(s.state.Analyses), Incidents: len(s.state.Incidents)}
	repos := map[string]struct{}{}
	for _, a := range s.state.Analyses {
		if a.Input.Repository != "" {
			repos[a.Input.Repository] = struct{}{}
		}
	}
	st.Repositories = len(repos)
	for _, i := range s.state.Incidents {
		if i.State == "open" {
			st.OpenIncidents++
		}
	}
	for _, j := range s.state.Jobs {
		if j.Status == "queued" {
			st.QueuedJobs++
		}
	}
	return st, nil
}
func (s *Store) GetAnalysis(ctx context.Context, id string) (*model.AnalysisResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.state.Analyses[id]
	if !ok {
		return nil, nil
	}
	r := a.Result
	return &r, nil
}
func (s *Store) ListAnalyses(ctx context.Context, limit int) ([]model.AnalysisResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 500 {
		limit = 50
	}
	out := make([]model.AnalysisResult, 0, limit)
	for i := len(s.state.AnalysisOrder) - 1; i >= 0 && len(out) < limit; i-- {
		if a, ok := s.state.Analyses[s.state.AnalysisOrder[i]]; ok {
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
	return s.persistLocked()
}
func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Store) ResolveStaleIncidents(ctx context.Context, cutoff time.Time) (int, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	resolved := 0
	for key, incident := range s.state.Incidents {
		if incident.State == "open" && incident.LastSeenAt.Before(cutoff) {
			incident.State = "resolved"
			s.state.Incidents[key] = incident
			resolved++
		}
	}
	if resolved > 0 {
		return resolved, s.persistLocked()
	}
	return 0, nil
}
