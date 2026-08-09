package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

	"github.com/Bluezly/CIRadar/internal/model"
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

var ErrJobLeaseLost = errors.New("job lease is no longer owned by this worker")

type Job struct {
	TenantID   string
	ID         int64
	Type       string
	Payload    json.RawMessage
	Attempts   int
	LeaseToken string
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
	RunningJobs            int `json:"running_jobs"`
	FailedJobs             int `json:"failed_jobs"`
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
	recoveredFromBackup := false
	mainExists := err == nil
	if err == nil {
		if decodeErr := decodeStateFile(b, &s.state, "state file"); decodeErr != nil {
			if backupErr := loadBackupState(path, &s.state); backupErr != nil {
				return nil, fmt.Errorf("decode state file: %w; backup recovery failed: %v", decodeErr, backupErr)
			}
			recoveredFromBackup = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		_, backupStatErr := os.Stat(path + ".bak")
		switch {
		case backupStatErr == nil:
			if backupErr := loadBackupState(path, &s.state); backupErr != nil {
				return nil, fmt.Errorf("recover missing state file from backup: %w", backupErr)
			}
			recoveredFromBackup = true
		case !errors.Is(backupStatErr, os.ErrNotExist):
			return nil, backupStatErr
		}
	}
	if recoveredFromBackup && mainExists {
		if err := quarantineCorruptState(path); err != nil {
			return nil, fmt.Errorf("quarantine corrupt state: %w", err)
		}
	}
	s.normalize()
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func loadBackupState(path string, target *state) error {
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		return err
	}
	return decodeStateFile(backup, target, "state backup")
}

func decodeStateFile(body []byte, target *state, label string) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%s is empty", label)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	if target.Version < 1 {
		return fmt.Errorf("%s has no valid schema version", label)
	}
	return nil
}

func quarantineCorruptState(path string) error {
	quarantine := path + ".corrupt"
	if err := os.Remove(quarantine); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, quarantine); err != nil {
		return err
	}
	_ = syncParentDirectory(path)
	return nil
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
	if err := s.persistLocked(); err != nil {
		return err
	}
	s.closed = true
	return nil
}
func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) persistLocked() (returnErr error) {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	defer func() {
		if returnErr != nil {
			_ = os.Remove(tmp)
		}
	}()
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
		backupTemp := s.path + ".bak.tmp"
		if err := writeSyncedFile(backupTemp, current, 0o600); err != nil {
			_ = os.Remove(backupTemp)
			return fmt.Errorf("write state backup: %w", err)
		}
		if err := replacePersistedFile(backupTemp, s.path+".bak"); err != nil {
			_ = os.Remove(backupTemp)
			return fmt.Errorf("install state backup: %w", err)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read current state for backup: %w", err)
	}
	if err := replacePersistedFile(tmp, s.path); err != nil {
		return fmt.Errorf("install persisted state: %w", err)
	}
	_ = syncParentDirectory(s.path)
	return nil
}

func syncParentDirectory(path string) error {
	if runtimeWindows() {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func runtimeWindows() bool { return filepath.Separator == '\\' }

func writeSyncedFile(path string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func replacePersistedFile(tempPath, targetPath string) error {
	if !runtimeWindows() {
		return os.Rename(tempPath, targetPath)
	}
	return replaceFileWithRollback(tempPath, targetPath)
}

func replaceFileWithRollback(tempPath, targetPath string) error {
	if _, err := os.Lstat(targetPath); errors.Is(err, os.ErrNotExist) {
		return os.Rename(tempPath, targetPath)
	} else if err != nil {
		return err
	}
	rollbackPath := targetPath + ".replace-old"
	if err := os.Remove(rollbackPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(targetPath, rollbackPath); err != nil {
		return err
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		if rollbackErr := os.Rename(rollbackPath, targetPath); rollbackErr != nil {
			return fmt.Errorf("replace failed: %v; rollback failed: %w", err, rollbackErr)
		}
		return err
	}
	if err := os.Remove(rollbackPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replacement succeeded but rollback cleanup failed: %w", err)
	}
	return nil
}

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
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("delivery ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Deliveries[id]; ok {
		return false, nil
	}
	s.state.Deliveries[id] = deliveryRecord{EventType: strings.TrimSpace(eventType), ReceivedAt: time.Now().UTC(), Status: "received"}
	if err := s.persistLocked(); err != nil {
		delete(s.state.Deliveries, id)
		return false, err
	}
	return true, nil
}

func (s *Store) RecordTerminalDelivery(ctx context.Context, id, eventType, status, errText string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	status = strings.TrimSpace(status)
	if id == "" {
		return false, errors.New("delivery ID is required")
	}
	if status == "" {
		return false, errors.New("delivery status is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Deliveries[id]; ok {
		return false, nil
	}
	s.state.Deliveries[id] = deliveryRecord{EventType: strings.TrimSpace(eventType), ReceivedAt: time.Now().UTC(), Status: status, Error: trim(errText, 4000)}
	if err := s.persistLocked(); err != nil {
		delete(s.state.Deliveries, id)
		return false, err
	}
	return true, nil
}

func (s *Store) ClaimDelivery(ctx context.Context, id, eventType string, staleAfter time.Duration) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("delivery ID is required")
	}
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.state.Deliveries[id]
	if existed {
		switch old.Status {
		case "processed", "queued", "ignored", "invalid", "unbound":
			return false, nil
		case "processing":
			if now.Sub(old.ReceivedAt) < staleAfter {
				return false, nil
			}
		}
	}
	s.state.Deliveries[id] = deliveryRecord{EventType: strings.TrimSpace(eventType), ReceivedAt: now, Status: "processing"}
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Deliveries[id] = old
		} else {
			delete(s.state.Deliveries, id)
		}
		return false, err
	}
	return true, nil
}

func (s *Store) EnqueueDeliveryForTenant(ctx context.Context, deliveryID, eventType, tenantID, typ string, payload any, availableAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" {
		return false, errors.New("delivery ID is required")
	}
	tenantID = normalizeTenant(tenantID)
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return false, errors.New("job type is required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if availableAt.IsZero() {
		availableAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Deliveries[deliveryID]; ok {
		return false, nil
	}
	if tenant, ok := s.state.Tenants[tenantID]; !ok || !tenant.Enabled {
		return false, fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	now := time.Now().UTC()
	oldNext := s.state.NextJobID
	oldJobsLen := len(s.state.Jobs)
	s.state.Deliveries[deliveryID] = deliveryRecord{EventType: strings.TrimSpace(eventType), ReceivedAt: now, Status: "queued"}
	s.state.Jobs = append(s.state.Jobs, jobRecord{TenantID: tenantID, ID: s.state.NextJobID, Type: typ, Payload: body, Status: "queued", AvailableAt: availableAt.UTC(), CreatedAt: now, UpdatedAt: now})
	s.state.NextJobID++
	if err := s.persistLocked(); err != nil {
		delete(s.state.Deliveries, deliveryID)
		s.state.Jobs = s.state.Jobs[:oldJobsLen]
		s.state.NextJobID = oldNext
		return false, err
	}
	return true, nil
}

func (s *Store) UpdateDelivery(ctx context.Context, id, status, errText string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.state.Deliveries[id]
	if !ok {
		return nil
	}
	old := d
	d.Status = strings.TrimSpace(status)
	d.Error = trim(errText, 4000)
	s.state.Deliveries[id] = d
	if err := s.persistLocked(); err != nil {
		s.state.Deliveries[id] = old
		return err
	}
	return nil
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
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantID = normalizeTenant(tenantID)
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return errors.New("job type is required")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if availableAt.IsZero() {
		availableAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenant, ok := s.state.Tenants[tenantID]; !ok || !tenant.Enabled {
		return fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	now := time.Now().UTC()
	oldNext := s.state.NextJobID
	oldLen := len(s.state.Jobs)
	j := jobRecord{TenantID: tenantID, ID: s.state.NextJobID, Type: typ, Payload: b, Status: "queued", AvailableAt: availableAt.UTC(), CreatedAt: now, UpdatedAt: now}
	s.state.NextJobID++
	s.state.Jobs = append(s.state.Jobs, j)
	if err := s.persistLocked(); err != nil {
		s.state.NextJobID = oldNext
		s.state.Jobs = s.state.Jobs[:oldLen]
		return err
	}
	return nil
}

func (s *Store) ClaimJob(ctx context.Context, workerID string) (*Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, errors.New("worker ID is required")
	}
	random, err := randomText(18)
	if err != nil {
		return nil, err
	}
	lease := workerID + ":" + random
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
	old := s.state.Jobs[idx]
	j := &s.state.Jobs[idx]
	j.Status = "running"
	j.LockedAt = now
	j.LockedBy = lease
	j.Attempts++
	j.UpdatedAt = now
	if err := s.persistLocked(); err != nil {
		s.state.Jobs[idx] = old
		return nil, err
	}
	return &Job{TenantID: normalizeTenant(j.TenantID), ID: j.ID, Type: j.Type, Payload: append(json.RawMessage(nil), j.Payload...), Attempts: j.Attempts, LeaseToken: lease}, nil
}

func (s *Store) RenewJobLease(ctx context.Context, id int64, leaseToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		if j.ID != id {
			continue
		}
		if j.Status != "running" || !secureEqualText(j.LockedBy, leaseToken) {
			return ErrJobLeaseLost
		}
		oldLockedAt, oldUpdatedAt := j.LockedAt, j.UpdatedAt
		now := time.Now().UTC()
		j.LockedAt = now
		j.UpdatedAt = now
		if err := s.persistLocked(); err != nil {
			j.LockedAt, j.UpdatedAt = oldLockedAt, oldUpdatedAt
			return err
		}
		return nil
	}
	return ErrJobLeaseLost
}

func (s *Store) CompleteJob(ctx context.Context, id int64, leaseToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		if j.ID != id {
			continue
		}
		if j.Status != "running" || !secureEqualText(j.LockedBy, leaseToken) {
			return ErrJobLeaseLost
		}
		old := *j
		j.Status = "done"
		j.LockedAt = time.Time{}
		j.LockedBy = ""
		j.UpdatedAt = time.Now().UTC()
		if err := s.persistLocked(); err != nil {
			*j = old
			return err
		}
		return nil
	}
	return ErrJobLeaseLost
}

func (s *Store) FailJob(ctx context.Context, id int64, leaseToken string, attempts int, errText string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Jobs {
		j := &s.state.Jobs[i]
		if j.ID != id {
			continue
		}
		if j.Status != "running" || !secureEqualText(j.LockedBy, leaseToken) {
			return ErrJobLeaseLost
		}
		old := *j
		j.Status = "queued"
		if attempts >= 8 {
			j.Status = "failed"
		}
		j.LastError = trim(errText, 4000)
		j.AvailableAt = time.Now().UTC().Add(time.Duration(attempts*attempts) * 10 * time.Second)
		j.LockedAt = time.Time{}
		j.LockedBy = ""
		j.UpdatedAt = time.Now().UTC()
		if err := s.persistLocked(); err != nil {
			*j = old
			return err
		}
		return nil
	}
	return ErrJobLeaseLost
}

func secureEqualText(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Store) RequeueStaleJobs(ctx context.Context, olderThan time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if olderThan <= 0 {
		return errors.New("stale job duration must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().UTC().Add(-olderThan)
	changed := false
	old := append([]jobRecord(nil), s.state.Jobs...)
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
	if !changed {
		return nil
	}
	if err := s.persistLocked(); err != nil {
		s.state.Jobs = old
		return err
	}
	return nil
}

func (s *Store) RecordAnalysis(ctx context.Context, in model.AnalysisInput, r model.AnalysisResult, storeExcerpt, storeRaw bool) error {
	return s.RecordAnalysisForTenant(ctx, normalizeTenant(in.TenantID), in, r, storeExcerpt, storeRaw)
}

func (s *Store) RecordAnalysisForTenant(ctx context.Context, tenantID string, in model.AnalysisInput, r model.AnalysisResult, storeExcerpt, storeRaw bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	r = cloneAnalysisResult(r)
	if !storeRaw {
		in.Log = ""
	}
	oldRecord, existed := s.state.Analyses[r.ID]
	oldOrderLen := len(s.state.AnalysisOrder)
	oldEnvironmentLen := len(s.state.Environments)
	if !existed {
		s.state.AnalysisOrder = append(s.state.AnalysisOrder, r.ID)
	}
	s.state.Analyses[r.ID] = analysisRecord{TenantID: tenantID, Input: in, Result: r}
	s.state.Environments = append(s.state.Environments, environmentRecord{TenantID: tenantID, Repository: in.Repository, Workflow: in.Workflow, Job: in.Job, CommitSHA: in.CommitSHA, Successful: false, Environment: cloneEnvironment(r.Environment), CreatedAt: r.CreatedAt})
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Analyses[r.ID] = oldRecord
		} else {
			delete(s.state.Analyses, r.ID)
		}
		s.state.AnalysisOrder = s.state.AnalysisOrder[:oldOrderLen]
		s.state.Environments = s.state.Environments[:oldEnvironmentLen]
		return err
	}
	return nil
}
func (s *Store) RecordSuccessfulEnvironment(ctx context.Context, repository, workflow, job, sha string, env model.Environment, at time.Time) error {
	return s.RecordSuccessfulEnvironmentForTenant(ctx, model.DefaultTenantID, repository, workflow, job, sha, env, at)
}

func (s *Store) RecordSuccessfulEnvironmentForTenant(ctx context.Context, tenantID, repository, workflow, job, sha string, env model.Environment, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	oldLen := len(s.state.Environments)
	s.state.Environments = append(s.state.Environments, environmentRecord{TenantID: tenantID, Repository: repository, Workflow: workflow, Job: job, CommitSHA: sha, Successful: true, Environment: cloneEnvironment(env), CreatedAt: at.UTC()})
	if err := s.persistLocked(); err != nil {
		s.state.Environments = s.state.Environments[:oldLen]
		return err
	}
	return nil
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
			env := cloneEnvironment(e.Environment)
			return &env, nil
		}
	}
	return nil, nil
}
func (s *Store) Correlation(ctx context.Context, fingerprint string, since time.Time) (CorrelationStats, error) {
	return s.CorrelationForTenant(ctx, model.DefaultTenantID, fingerprint, "", "", since, false)
}

func (s *Store) CorrelationForTenant(ctx context.Context, tenantID, fingerprint, repository, organization string, since time.Time, crossTenant bool) (CorrelationStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	repository = strings.TrimSpace(repository)
	organization = strings.TrimSpace(organization)
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
		repoKey := normalizeTenant(a.TenantID) + "|" + strings.TrimSpace(a.Input.Repository)
		orgKey := normalizeTenant(a.TenantID) + "|" + strings.TrimSpace(a.Input.Organization)
		if strings.TrimSpace(a.Input.Repository) != "" {
			repos[repoKey] = struct{}{}
		}
		if strings.TrimSpace(a.Input.Organization) != "" {
			orgs[orgKey] = struct{}{}
		}
	}
	if repository != "" || organization != "" {
		c.Occurrences++
	}
	if repository != "" {
		repos[tenantID+"|"+repository] = struct{}{}
	}
	if organization != "" {
		orgs[tenantID+"|"+organization] = struct{}{}
	}
	c.Repositories = len(repos)
	c.Organizations = len(orgs)
	return c, nil
}
func (s *Store) UpsertIncident(ctx context.Context, i model.Incident) error {
	return s.UpsertIncidentForTenant(ctx, normalizeTenant(i.TenantID), i)
}

func (s *Store) UpsertIncidentForTenant(ctx context.Context, tenantID string, i model.Incident) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantID = normalizeTenant(tenantID)
	i.TenantID = tenantID
	i = cloneIncident(i)
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
	old, existed := s.state.Incidents[key]
	s.state.Incidents[key] = i
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Incidents[key] = old
		} else {
			delete(s.state.Incidents, key)
		}
		return err
	}
	return nil
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
			out = append(out, cloneIncident(i))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *Store) RecordProviderStatus(ctx context.Context, p model.ProviderStatus) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(p.Provider))
	old, existed := s.state.ProviderStatuses[key]
	s.state.ProviderStatuses[key] = p
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.ProviderStatuses[key] = old
		} else {
			delete(s.state.ProviderStatuses, key)
		}
		return err
	}
	return nil
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
		if normalizeTenant(j.TenantID) != tenantID {
			continue
		}
		switch j.Status {
		case "queued":
			st.QueuedJobs++
		case "running":
			st.RunningJobs++
		case "failed":
			st.FailedJobs++
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
	r := cloneAnalysisResult(a.Result)
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
	out := make([]model.AnalysisResult, 0)
	for i := len(s.state.AnalysisOrder) - 1; i >= 0 && len(out) < limit; i-- {
		if a, ok := s.state.Analyses[s.state.AnalysisOrder[i]]; ok && normalizeTenant(a.TenantID) == tenantID {
			out = append(out, cloneAnalysisResult(a.Result))
		}
	}
	return out, nil
}
func (s *Store) Cleanup(ctx context.Context, retentionDays int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if retentionDays < 1 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldAnalyses := cloneMap(s.state.Analyses)
	oldAnalysisOrder := append([]string(nil), s.state.AnalysisOrder...)
	oldEnvironments := append([]environmentRecord(nil), s.state.Environments...)
	oldJobs := append([]jobRecord(nil), s.state.Jobs...)
	oldAuditEvents := cloneMap(s.state.AuditEvents)
	oldAuditOrder := append([]string(nil), s.state.AuditOrder...)
	oldNotifications := cloneMap(s.state.NotificationDeliveries)
	oldNotificationOrder := append([]string(nil), s.state.NotificationOrder...)
	oldIncidents := cloneMap(s.state.Incidents)
	oldDeliveries := cloneMap(s.state.Deliveries)
	oldExtensions := cloneMap(s.state.Extensions)
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
	now := time.Now().UTC()
	for key, object := range s.state.Extensions {
		switch {
		case object.TenantID == "__system__" && object.Kind == ssoReplayExtensionKind:
			var record ssoReplayRecord
			if json.Unmarshal(object.Value, &record) != nil || !record.ExpiresAt.After(now) {
				delete(s.state.Extensions, key)
			}
		case object.Kind == "oauth_revocation":
			var record struct {
				ExpiresAt time.Time `json:"expires_at"`
			}
			decodeErr := json.Unmarshal(object.Value, &record)
			expired := !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now)
			legacyExpired := record.ExpiresAt.IsZero() && object.UpdatedAt.Before(now.Add(-2*time.Hour))
			if decodeErr != nil || expired || legacyExpired {
				delete(s.state.Extensions, key)
			}
		}
	}
	if err := s.persistLocked(); err != nil {
		s.state.Analyses = oldAnalyses
		s.state.AnalysisOrder = oldAnalysisOrder
		s.state.Environments = oldEnvironments
		s.state.Jobs = oldJobs
		s.state.AuditEvents = oldAuditEvents
		s.state.AuditOrder = oldAuditOrder
		s.state.NotificationDeliveries = oldNotifications
		s.state.NotificationOrder = oldNotificationOrder
		s.state.Incidents = oldIncidents
		s.state.Deliveries = oldDeliveries
		s.state.Extensions = oldExtensions
		return err
	}
	return nil
}

func cloneEnvironment(value model.Environment) model.Environment {
	if value.ToolVersions != nil {
		value.ToolVersions = cloneMap(value.ToolVersions)
	}
	value.ContainerRefs = append([]string(nil), value.ContainerRefs...)
	value.ActionVersions = append([]string(nil), value.ActionVersions...)
	return value
}

func cloneSuggestedActions(values []model.SuggestedAction) []model.SuggestedAction {
	if values == nil {
		return nil
	}
	cloned := make([]model.SuggestedAction, len(values))
	for i, value := range values {
		value.Commands = append([]string(nil), value.Commands...)
		value.References = append([]string(nil), value.References...)
		cloned[i] = value
	}
	return cloned
}

func cloneAnalysisResult(value model.AnalysisResult) model.AnalysisResult {
	value.Evidence = append([]model.Evidence(nil), value.Evidence...)
	value.Environment = cloneEnvironment(value.Environment)
	value.MatchedRules = append([]string(nil), value.MatchedRules...)
	value.EnvironmentChanges = append([]string(nil), value.EnvironmentChanges...)
	value.SuggestedActions = cloneSuggestedActions(value.SuggestedActions)
	return value
}

func cloneIncident(value model.Incident) model.Incident {
	value.SuggestedActions = cloneSuggestedActions(value.SuggestedActions)
	return value
}

func cloneAuditEvent(value model.AuditEvent) model.AuditEvent {
	if value.Metadata != nil {
		value.Metadata = cloneMap(value.Metadata)
	}
	return value
}

func cloneRepositoryProfile(value model.RepositoryProfile) model.RepositoryProfile {
	value.NotificationChannels = append([]string(nil), value.NotificationChannels...)
	return value
}

func cloneTestObservation(value model.TestObservation) model.TestObservation {
	value.Environment = cloneEnvironment(value.Environment)
	return value
}

func cloneTestCaseStats(value model.TestCaseStats) model.TestCaseStats {
	value.ImpactedPullRequests = append([]int(nil), value.ImpactedPullRequests...)
	value.Aliases = append([]string(nil), value.Aliases...)
	if value.CauseCounts != nil {
		value.CauseCounts = cloneMap(value.CauseCounts)
	}
	return value
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	cloned := make(map[K]V, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := []model.Incident{}
	previous := map[string]model.Incident{}
	for key, incident := range s.state.Incidents {
		if (incident.State == "open" || incident.State == "acknowledged") && incident.LastSeenAt.Before(cutoff) {
			previous[key] = incident
			incident.State = "resolved"
			incident.ResolvedAt = now
			incident.ResolvedBy = "system"
			incident.ResolutionNote = "Automatically resolved after inactivity"
			s.state.Incidents[key] = incident
			out = append(out, cloneIncident(incident))
		}
	}
	if len(out) > 0 {
		if err := s.persistLocked(); err != nil {
			for key, incident := range previous {
				s.state.Incidents[key] = incident
			}
			return nil, err
		}
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
	out := cloneIncident(i)
	return &out, nil
}

func (s *Store) RecordNotificationDelivery(ctx context.Context, d model.NotificationDelivery) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.TenantID = normalizeTenant(d.TenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = notificationKey(d.TenantID, d.EventID, d.Channel)
	}
	old, existed := s.state.NotificationDeliveries[d.ID]
	oldOrderLen := len(s.state.NotificationOrder)
	if existed {
		if d.CreatedAt.IsZero() {
			d.CreatedAt = old.CreatedAt
		}
	} else {
		s.state.NotificationOrder = append(s.state.NotificationOrder, d.ID)
	}
	s.state.NotificationDeliveries[d.ID] = d
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.NotificationDeliveries[d.ID] = old
		} else {
			delete(s.state.NotificationDeliveries, d.ID)
		}
		s.state.NotificationOrder = s.state.NotificationOrder[:oldOrderLen]
		return err
	}
	return nil
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
	out := make([]model.NotificationDelivery, 0)
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
	if err := ctx.Err(); err != nil {
		return "", model.NotificationDelivery{}, err
	}
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	id := notificationKey(tenantID, eventID, channel)
	original, originallyExisted := s.state.NotificationDeliveries[id]
	originalOrderLen := len(s.state.NotificationOrder)
	persist := func() error {
		if err := s.persistLocked(); err != nil {
			if originallyExisted {
				s.state.NotificationDeliveries[id] = original
			} else {
				delete(s.state.NotificationDeliveries, id)
			}
			s.state.NotificationOrder = s.state.NotificationOrder[:originalOrderLen]
			return err
		}
		return nil
	}
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
			return "skip", old, persist()
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
				return "suppressed", d, persist()
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
	if err := persist(); err != nil {
		return "", model.NotificationDelivery{}, err
	}
	return "send", d, nil
}
