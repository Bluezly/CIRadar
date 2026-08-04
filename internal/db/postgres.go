package db

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/pgwire"
)

// PostgresBackend persists the complete CI Radar state in a transactionally
// locked JSONB document. It is intentionally compatibility-first: every
// single-node capability works unchanged while PostgreSQL provides durable,
// multi-process transactions and backups. High-volume installations can later
// split this contract into normalized tables without touching callers.
type PostgresBackend struct{ dsn string }

func OpenPostgres(ctx context.Context, dsn string) (*PostgresBackend, error) {
	p := &PostgresBackend{dsn: strings.TrimSpace(dsn)}
	if p.dsn == "" {
		return nil, errors.New("postgres dsn is required")
	}
	if err := p.Migrate(ctx); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *PostgresBackend) Close() error { return nil }
func (p *PostgresBackend) Migrate(ctx context.Context) error {
	c, err := pgwire.Connect(ctx, p.dsn)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer c.Close()
	if err = c.Exec(ctx, `CREATE TABLE IF NOT EXISTS ciradar_state (
        id text PRIMARY KEY,
        version bigint NOT NULL DEFAULT 1,
        payload jsonb NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )`); err != nil {
		return fmt.Errorf("migrate postgres: %w", err)
	}
	initial, err := newMemoryStore(nil)
	if err != nil {
		return err
	}
	b, err := initial.snapshotJSON()
	if err != nil {
		return err
	}
	q := `INSERT INTO ciradar_state(id,payload) VALUES ('global',` + jsonExpr(b) + `) ON CONFLICT (id) DO NOTHING`
	if err = c.Exec(ctx, q); err != nil {
		return fmt.Errorf("initialize postgres: %w", err)
	}
	return nil
}

func jsonExpr(b []byte) string {
	return `convert_from(decode('` + base64.StdEncoding.EncodeToString(b) + `','base64'),'UTF8')::jsonb`
}
func decodePGBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(s)
}

type pgCall[T any] func(*Store) (T, error)

func pgWith[T any](ctx context.Context, p *PostgresBackend, write bool, fn pgCall[T]) (out T, err error) {
	c, e := pgwire.Connect(ctx, p.dsn)
	if e != nil {
		return out, e
	}
	defer c.Close()
	if write {
		if e = c.Exec(ctx, "BEGIN"); e != nil {
			return out, e
		}
		defer func() {
			if err != nil {
				_ = c.Exec(context.Background(), "ROLLBACK")
			}
		}()
	}
	q := `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_state WHERE id='global'`
	if write {
		q += ` FOR UPDATE`
	}
	rows, e := c.Query(ctx, q)
	if e != nil {
		return out, e
	}
	if len(rows.Values) != 1 || len(rows.Values[0]) != 1 || rows.Values[0][0] == nil {
		return out, errors.New("postgres state row missing")
	}
	payload, e := decodePGBase64(*rows.Values[0][0])
	if e != nil {
		return out, e
	}
	s, e := newMemoryStore(payload)
	if e != nil {
		return out, e
	}
	out, e = fn(s)
	if e != nil {
		return out, e
	}
	if write {
		b, e := s.snapshotJSON()
		if e != nil {
			return out, e
		}
		if e = c.Exec(ctx, `UPDATE ciradar_state SET payload=`+jsonExpr(b)+`,version=version+1,updated_at=now() WHERE id='global'`); e != nil {
			return out, e
		}
		if e = c.Exec(ctx, "COMMIT"); e != nil {
			return out, e
		}
	}
	return out, nil
}
func pgErr(ctx context.Context, p *PostgresBackend, write bool, fn func(*Store) error) error {
	_, err := pgWith(ctx, p, write, func(s *Store) (struct{}, error) { return struct{}{}, fn(s) })
	return err
}

func (p *PostgresBackend) ClaimJob(ctx context.Context, w string) (*Job, error) {
	return pgWith(ctx, p, true, func(s *Store) (*Job, error) { return s.ClaimJob(ctx, w) })
}
func (p *PostgresBackend) CompleteJob(ctx context.Context, id int64) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.CompleteJob(ctx, id) })
}
func (p *PostgresBackend) FailJob(ctx context.Context, id int64, a int, e string) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.FailJob(ctx, id, a, e) })
}
func (p *PostgresBackend) RequeueStaleJobs(ctx context.Context, d time.Duration) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RequeueStaleJobs(ctx, d) })
}
func (p *PostgresBackend) Enqueue(ctx context.Context, t string, v any, a time.Time) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.Enqueue(ctx, t, v, a) })
}
func (p *PostgresBackend) EnqueueForTenant(ctx context.Context, tenant, t string, v any, a time.Time) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.EnqueueForTenant(ctx, tenant, t, v, a) })
}

type boolErr struct{ V bool }

func (p *PostgresBackend) RecordDelivery(ctx context.Context, id, t string) (bool, error) {
	r, e := pgWith(ctx, p, true, func(s *Store) (boolErr, error) { v, e := s.RecordDelivery(ctx, id, t); return boolErr{v}, e })
	return r.V, e
}
func (p *PostgresBackend) UpdateDelivery(ctx context.Context, id, st, et string) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.UpdateDelivery(ctx, id, st, et) })
}
func (p *PostgresBackend) RecordAnalysisForTenant(ctx context.Context, t string, i model.AnalysisInput, r model.AnalysisResult, se, sr bool) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RecordAnalysisForTenant(ctx, t, i, r, se, sr) })
}
func (p *PostgresBackend) GetAnalysisForTenant(ctx context.Context, t, id string) (*model.AnalysisResult, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.AnalysisResult, error) { return s.GetAnalysisForTenant(ctx, t, id) })
}
func (p *PostgresBackend) ListAnalysesForTenant(ctx context.Context, t string, l int) ([]model.AnalysisResult, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.AnalysisResult, error) { return s.ListAnalysesForTenant(ctx, t, l) })
}
func (p *PostgresBackend) CorrelationForTenant(ctx context.Context, t, f string, since time.Time, cross bool) (CorrelationStats, error) {
	return pgWith(ctx, p, false, func(s *Store) (CorrelationStats, error) { return s.CorrelationForTenant(ctx, t, f, since, cross) })
}
func (p *PostgresBackend) RecordSuccessfulEnvironmentForTenant(ctx context.Context, t, r, w, j, sha string, e model.Environment, at time.Time) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RecordSuccessfulEnvironmentForTenant(ctx, t, r, w, j, sha, e, at) })
}
func (p *PostgresBackend) LastSuccessfulEnvironmentForTenant(ctx context.Context, t, r, w, j string) (*model.Environment, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.Environment, error) {
		return s.LastSuccessfulEnvironmentForTenant(ctx, t, r, w, j)
	})
}
func (p *PostgresBackend) GetIncidentForTenant(ctx context.Context, t, f string) (*model.Incident, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.Incident, error) { return s.GetIncidentForTenant(ctx, t, f) })
}
func (p *PostgresBackend) ListIncidentsForTenant(ctx context.Context, t string, l int, st string) ([]model.Incident, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.Incident, error) { return s.ListIncidentsForTenant(ctx, t, l, st) })
}
func (p *PostgresBackend) UpsertIncidentForTenant(ctx context.Context, t string, i model.Incident) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.UpsertIncidentForTenant(ctx, t, i) })
}
func (p *PostgresBackend) UpdateIncidentState(ctx context.Context, t, f, st, a, n string) (*model.Incident, error) {
	return pgWith(ctx, p, true, func(s *Store) (*model.Incident, error) { return s.UpdateIncidentState(ctx, t, f, st, a, n) })
}
func (p *PostgresBackend) ResolveStaleIncidentsDetailed(ctx context.Context, c time.Time) ([]model.Incident, error) {
	return pgWith(ctx, p, true, func(s *Store) ([]model.Incident, error) { return s.ResolveStaleIncidentsDetailed(ctx, c) })
}
func (p *PostgresBackend) RecordProviderStatus(ctx context.Context, v model.ProviderStatus) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RecordProviderStatus(ctx, v) })
}
func (p *PostgresBackend) ListProviderStatuses(ctx context.Context) ([]model.ProviderStatus, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.ProviderStatus, error) { return s.ListProviderStatuses(ctx) })
}

type beginNotificationResult struct {
	Status   string
	Delivery model.NotificationDelivery
}

func (p *PostgresBackend) BeginNotificationDeliveryForTenant(ctx context.Context, t, e, ch, ct, d string, cd time.Duration, m int) (string, model.NotificationDelivery, error) {
	r, x := pgWith(ctx, p, true, func(s *Store) (beginNotificationResult, error) {
		st, v, e := s.BeginNotificationDeliveryForTenant(ctx, t, e, ch, ct, d, cd, m)
		return beginNotificationResult{st, v}, e
	})
	return r.Status, r.Delivery, x
}
func (p *PostgresBackend) GetNotificationDeliveryForTenant(ctx context.Context, t, e, ch string) (*model.NotificationDelivery, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.NotificationDelivery, error) {
		return s.GetNotificationDeliveryForTenant(ctx, t, e, ch)
	})
}
func (p *PostgresBackend) RecordNotificationDelivery(ctx context.Context, d model.NotificationDelivery) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RecordNotificationDelivery(ctx, d) })
}
func (p *PostgresBackend) ListNotificationDeliveriesForTenant(ctx context.Context, t string, l int) ([]model.NotificationDelivery, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.NotificationDelivery, error) {
		return s.ListNotificationDeliveriesForTenant(ctx, t, l)
	})
}
func (p *PostgresBackend) CreateTenant(ctx context.Context, id, n string) (model.Tenant, error) {
	return pgWith(ctx, p, true, func(s *Store) (model.Tenant, error) { return s.CreateTenant(ctx, id, n) })
}
func (p *PostgresBackend) GetTenant(ctx context.Context, id string) (*model.Tenant, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.Tenant, error) { return s.GetTenant(ctx, id) })
}
func (p *PostgresBackend) ListTenants(ctx context.Context) ([]model.Tenant, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.Tenant, error) { return s.ListTenants(ctx) })
}
func (p *PostgresBackend) SetTenantEnabled(ctx context.Context, id string, e bool) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.SetTenantEnabled(ctx, id, e) })
}

type apiKeyCreate struct {
	Key   model.APIKey
	Token string
}

func (p *PostgresBackend) CreateAPIKey(ctx context.Context, t, n string, r model.Role) (model.APIKey, string, error) {
	v, e := pgWith(ctx, p, true, func(s *Store) (apiKeyCreate, error) {
		k, tok, e := s.CreateAPIKey(ctx, t, n, r)
		return apiKeyCreate{k, tok}, e
	})
	return v.Key, v.Token, e
}
func (p *PostgresBackend) AuthenticateAPIKey(ctx context.Context, t string) (*model.Principal, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.Principal, error) { return s.AuthenticateAPIKey(ctx, t) })
}
func (p *PostgresBackend) ListAPIKeys(ctx context.Context, t string) ([]model.APIKey, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.APIKey, error) { return s.ListAPIKeys(ctx, t) })
}
func (p *PostgresBackend) RevokeAPIKey(ctx context.Context, t, id string) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RevokeAPIKey(ctx, t, id) })
}
func (p *PostgresBackend) RecordAudit(ctx context.Context, e model.AuditEvent) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RecordAudit(ctx, e) })
}
func (p *PostgresBackend) ListAudit(ctx context.Context, t string, l int) ([]model.AuditEvent, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.AuditEvent, error) { return s.ListAudit(ctx, t, l) })
}
func (p *PostgresBackend) BindInstallation(ctx context.Context, t string, id int64) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.BindInstallation(ctx, t, id) })
}
func (p *PostgresBackend) UnbindInstallation(ctx context.Context, id int64) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.UnbindInstallation(ctx, id) })
}
func (p *PostgresBackend) ResolveInstallationTenant(ctx context.Context, id int64) (string, bool) {
	v, e := pgWith(ctx, p, false, func(s *Store) (struct {
		T string
		B bool
	}, error) {
		t, b := s.ResolveInstallationTenant(ctx, id)
		return struct {
			T string
			B bool
		}{t, b}, nil
	})
	if e != nil {
		return "", false
	}
	return v.T, v.B
}
func (p *PostgresBackend) ListInstallationBindings(ctx context.Context) map[string]string {
	v, e := pgWith(ctx, p, false, func(s *Store) (map[string]string, error) { return s.ListInstallationBindings(ctx), nil })
	if e != nil {
		return map[string]string{}
	}
	return v
}
func (p *PostgresBackend) UpsertRepositoryProfile(ctx context.Context, v model.RepositoryProfile) (model.RepositoryProfile, error) {
	return pgWith(ctx, p, true, func(s *Store) (model.RepositoryProfile, error) { return s.UpsertRepositoryProfile(ctx, v) })
}
func (p *PostgresBackend) GetRepositoryProfile(ctx context.Context, t, r string) (*model.RepositoryProfile, error) {
	return pgWith(ctx, p, false, func(s *Store) (*model.RepositoryProfile, error) { return s.GetRepositoryProfile(ctx, t, r) })
}
func (p *PostgresBackend) ListRepositoryProfiles(ctx context.Context, t string) ([]model.RepositoryProfile, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.RepositoryProfile, error) { return s.ListRepositoryProfiles(ctx, t) })
}
func (p *PostgresBackend) Stats(ctx context.Context) (Stats, error) {
	return pgWith(ctx, p, false, func(s *Store) (Stats, error) { return s.Stats(ctx) })
}
func (p *PostgresBackend) StatsForTenant(ctx context.Context, t string) (Stats, error) {
	return pgWith(ctx, p, false, func(s *Store) (Stats, error) { return s.StatsForTenant(ctx, t) })
}
func (p *PostgresBackend) Dashboard(ctx context.Context, t string, since time.Time) (model.DashboardSummary, error) {
	return pgWith(ctx, p, false, func(s *Store) (model.DashboardSummary, error) { return s.Dashboard(ctx, t, since) })
}
func (p *PostgresBackend) UpsertDiagnosisFeedback(ctx context.Context, v model.DiagnosisFeedback) (model.DiagnosisFeedback, error) {
	return pgWith(ctx, p, true, func(s *Store) (model.DiagnosisFeedback, error) { return s.UpsertDiagnosisFeedback(ctx, v) })
}
func (p *PostgresBackend) ListDiagnosisFeedback(ctx context.Context, t string, l int) ([]model.DiagnosisFeedback, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.DiagnosisFeedback, error) { return s.ListDiagnosisFeedback(ctx, t, l) })
}
func (p *PostgresBackend) FeedbackMetrics(ctx context.Context, t string) (model.FeedbackMetrics, error) {
	return pgWith(ctx, p, false, func(s *Store) (model.FeedbackMetrics, error) { return s.FeedbackMetrics(ctx, t) })
}
func (p *PostgresBackend) RecordTestObservations(ctx context.Context, t string, v []model.TestObservation) ([]model.TestCaseStats, error) {
	return pgWith(ctx, p, true, func(s *Store) ([]model.TestCaseStats, error) { return s.RecordTestObservations(ctx, t, v) })
}
func (p *PostgresBackend) ListTestCaseStats(ctx context.Context, t, r, c string, l int) ([]model.TestCaseStats, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.TestCaseStats, error) { return s.ListTestCaseStats(ctx, t, r, c, l) })
}
func (p *PostgresBackend) SetTestQuarantine(ctx context.Context, q model.TestQuarantine) (model.TestQuarantine, error) {
	return pgWith(ctx, p, true, func(s *Store) (model.TestQuarantine, error) { return s.SetTestQuarantine(ctx, q) })
}
func (p *PostgresBackend) RemoveTestQuarantine(ctx context.Context, t, k string) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.RemoveTestQuarantine(ctx, t, k) })
}
func (p *PostgresBackend) ListTestQuarantines(ctx context.Context, t string) ([]model.TestQuarantine, error) {
	return pgWith(ctx, p, false, func(s *Store) ([]model.TestQuarantine, error) { return s.ListTestQuarantines(ctx, t) })
}
func (p *PostgresBackend) Cleanup(ctx context.Context, d int) error {
	return pgErr(ctx, p, true, func(s *Store) error { return s.Cleanup(ctx, d) })
}

var _ Backend = (*PostgresBackend)(nil)
