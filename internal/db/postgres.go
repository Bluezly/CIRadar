package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
	"github.com/Bluezly/CIRadar/internal/pgwire"
)

type PostgresBackend struct {
	dsn  string
	pool *postgresPool
}

func OpenPostgres(ctx context.Context, dsn string) (*PostgresBackend, error) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return nil, errors.New("postgres dsn is required")
	}
	cfg, err := pgwire.ParseDSN(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	p := &PostgresBackend{dsn: trimmed, pool: newPostgresPool(trimmed, cfg.PoolMaxConns)}
	if err := p.Migrate(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (p *PostgresBackend) Close() error {
	if p == nil || p.pool == nil {
		return nil
	}
	return p.pool.close()
}

func (p *PostgresBackend) connect(ctx context.Context) (*pgwire.Client, error) {
	if p.pool == nil {
		return nil, errors.New("postgres connection pool is unavailable")
	}
	return p.pool.acquire(ctx)
}

func (p *PostgresBackend) release(c *pgwire.Client) {
	if p != nil && p.pool != nil {
		p.pool.release(c)
	}
}

func rollbackPostgres(c *pgwire.Client) {
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.Exec(ctx, "ROLLBACK")
}

func unlockPostgresMigration(c *pgwire.Client) error {
	if c == nil {
		return errors.New("postgres migration connection is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := c.QueryParams(ctx, `SELECT pg_advisory_unlock($1::bigint)::text`, advisoryLockKey("ciradar:schema:migrate"))
	if err != nil {
		_ = c.Close()
		return err
	}
	row, err := requireRow(rows, 1)
	if err != nil {
		_ = c.Close()
		return err
	}
	if !pgBool(row[0]) {
		_ = c.Close()
		return errors.New("postgres migration advisory lock was not held during unlock")
	}
	return nil
}

func (p *PostgresBackend) Migrate(ctx context.Context) (err error) {
	c, err := p.connect(ctx)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer p.release(c)
	lockCtx, cancelLock := context.WithTimeout(ctx, time.Minute)
	lockErr := c.ExecParams(lockCtx, `SELECT pg_advisory_lock($1::bigint)`, advisoryLockKey("ciradar:schema:migrate"))
	cancelLock()
	if lockErr != nil {
		return fmt.Errorf("lock postgres migration: %w", lockErr)
	}
	defer func() {
		if unlockErr := unlockPostgresMigration(c); unlockErr != nil && err == nil {
			err = fmt.Errorf("unlock postgres migration: %w", unlockErr)
		}
	}()
	if err := p.migrateRelational(ctx, c); err != nil {
		return fmt.Errorf("migrate postgres: %w", err)
	}
	return nil
}

func (p *PostgresBackend) Enqueue(ctx context.Context, typ string, payload any, availableAt time.Time) error {
	tenantID := model.DefaultTenantID
	switch value := payload.(type) {
	case model.NotificationEvent:
		tenantID = normalizeTenant(value.TenantID)
	case *model.NotificationEvent:
		if value != nil {
			tenantID = normalizeTenant(value.TenantID)
		}
	case model.GitHubWorkflowRunEvent:
		tenantID = normalizeTenant(value.TenantID)
	case *model.GitHubWorkflowRunEvent:
		if value != nil {
			tenantID = normalizeTenant(value.TenantID)
		}
	}
	return p.EnqueueForTenant(ctx, tenantID, typ, payload, availableAt)
}

func (p *PostgresBackend) EnqueueForTenant(ctx context.Context, tenantID, typ string, payload any, availableAt time.Time) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantID = normalizeTenant(tenantID)
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return errors.New("job type is required")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if availableAt.IsZero() {
		availableAt = time.Now().UTC()
	}
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	if err = lockSpecs(ctx, c, []pgSpec{pgGlobal(pgKindTenant)}); err != nil {
		return err
	}
	rows, err := c.QueryParams(ctx, `SELECT status FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3 FOR SHARE`, pgSystemTenant, pgKindTenant, tenantID)
	if err != nil {
		return err
	}
	if len(rows.Values) != 1 || len(rows.Values[0]) < 1 || rows.Values[0][0] == nil || *rows.Values[0][0] != "enabled" {
		return fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	query := `INSERT INTO ciradar_jobs(tenant_id,type,payload,status,attempts,available_at,created_at,updated_at) VALUES ($1,$2,$3::jsonb,'queued',0,$4,now(),now())`
	if err = c.ExecParams(ctx, query, tenantID, typ, string(data), availableAt.UTC()); err != nil {
		return err
	}
	return c.Exec(ctx, "COMMIT")
}

func (p *PostgresBackend) ClaimJob(ctx context.Context, workerID string) (job *Job, err error) {
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
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	query := `SELECT j.id::text,j.tenant_id,j.type,encode(convert_to(j.payload::text,'UTF8'),'base64'),j.attempts::text FROM ciradar_jobs j JOIN ciradar_objects t ON t.tenant_id=$1 AND t.kind=$2 AND t.object_id=j.tenant_id AND t.status='enabled' WHERE j.status='queued' AND j.available_at<=now() ORDER BY j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED`
	rows, err := c.QueryParams(ctx, query, pgSystemTenant, pgKindTenant)
	if err != nil {
		return nil, err
	}
	if len(rows.Values) == 0 {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	row, err := requireRow(rows, 5)
	if err != nil {
		return nil, err
	}
	id, err := strconv.ParseInt(valueOf(row[0]), 10, 64)
	if err != nil {
		return nil, err
	}
	attempts, err := strconv.Atoi(valueOf(row[4]))
	if err != nil {
		return nil, err
	}
	payload, err := decodePGBase64(valueOf(row[3]))
	if err != nil {
		return nil, err
	}
	attempts++
	update := `UPDATE ciradar_jobs SET status='running',attempts=$1,locked_at=now(),locked_by=$2,updated_at=now() WHERE id=$3`
	if err = c.ExecParams(ctx, update, attempts, lease, id); err != nil {
		return nil, err
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return nil, err
	}
	return &Job{TenantID: normalizeTenant(valueOf(row[1])), ID: id, Type: valueOf(row[2]), Payload: append(json.RawMessage(nil), payload...), Attempts: attempts, LeaseToken: lease}, nil
}

func valueOf(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func parsePostgresInt(value *string, field string) (int, error) {
	raw := strings.TrimSpace(valueOf(value))
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse postgres %s %q: %w", field, raw, err)
	}
	return n, nil
}

func (p *PostgresBackend) RenewJobLease(ctx context.Context, id int64, leaseToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	query := `UPDATE ciradar_jobs SET locked_at=now(),updated_at=now() WHERE id=$1 AND status='running' AND locked_by=$2 RETURNING id::text`
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, query, id, leaseToken)
	if err != nil {
		return err
	}
	if len(rows.Values) != 1 {
		return ErrJobLeaseLost
	}
	return nil
}

func (p *PostgresBackend) CompleteJob(ctx context.Context, id int64, leaseToken string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	query := `UPDATE ciradar_jobs SET status='done',locked_at=NULL,locked_by=NULL,updated_at=now() WHERE id=$1 AND status='running' AND locked_by=$2 RETURNING id::text`
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, query, id, leaseToken)
	if err != nil {
		return err
	}
	if len(rows.Values) != 1 {
		return ErrJobLeaseLost
	}
	return nil
}

func (p *PostgresBackend) FailJob(ctx context.Context, id int64, leaseToken string, attempts int, errText string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status := "queued"
	if attempts >= 8 {
		status = "failed"
	}
	seconds := attempts * attempts * 10
	query := `UPDATE ciradar_jobs SET status=$1,last_error=$2,available_at=now()+($3::bigint * interval '1 second'),locked_at=NULL,locked_by=NULL,updated_at=now() WHERE id=$4 AND status='running' AND locked_by=$5 RETURNING id::text`
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, query, status, trim(errText, 4000), seconds, id, leaseToken)
	if err != nil {
		return err
	}
	if len(rows.Values) != 1 {
		return ErrJobLeaseLost
	}
	return nil
}

func (p *PostgresBackend) RequeueStaleJobs(ctx context.Context, olderThan time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if olderThan <= 0 {
		return errors.New("stale job duration must be positive")
	}
	seconds := int64(olderThan / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	query := `UPDATE ciradar_jobs SET status='queued',locked_at=NULL,locked_by=NULL,updated_at=now() WHERE status='running' AND locked_at<now()-($1::bigint * interval '1 second')`
	return p.execParams(ctx, query, seconds)
}

func (p *PostgresBackend) execParams(ctx context.Context, query string, args ...any) error {
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	return c.ExecParams(ctx, query, args...)
}

func (p *PostgresBackend) RecordDelivery(ctx context.Context, id, eventType string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, errors.New("delivery ID is required")
	}
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	query := `INSERT INTO ciradar_webhook_deliveries(id,event_type,status) VALUES ($1,$2,'received') ON CONFLICT (id) DO NOTHING RETURNING id`
	rows, err := c.QueryParams(ctx, query, id, eventType)
	if err != nil {
		return false, err
	}
	return len(rows.Values) == 1, nil
}

func (p *PostgresBackend) RecordTerminalDelivery(ctx context.Context, id, eventType, status, errText string) (bool, error) {
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
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	query := `INSERT INTO ciradar_webhook_deliveries(id,event_type,status,error) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING RETURNING id`
	rows, err := c.QueryParams(ctx, query, id, strings.TrimSpace(eventType), status, trim(errText, 4000))
	if err != nil {
		return false, err
	}
	return len(rows.Values) == 1, nil
}

func (p *PostgresBackend) ClaimDelivery(ctx context.Context, id, eventType string, staleAfter time.Duration) (claimed bool, err error) {
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
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	insert := `INSERT INTO ciradar_webhook_deliveries(id,event_type,status,error) VALUES ($1,$2,'processing','') ON CONFLICT (id) DO NOTHING RETURNING id`
	rows, err := c.QueryParams(ctx, insert, id, strings.TrimSpace(eventType))
	if err != nil {
		return false, err
	}
	if len(rows.Values) == 1 {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return false, err
		}
		return true, nil
	}
	seconds := int64(staleAfter / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	update := `UPDATE ciradar_webhook_deliveries SET event_type=$1,received_at=now(),status='processing',error='' WHERE id=$2 AND (status='error' OR ((status='processing' OR status='received') AND received_at<now()-($3::bigint * interval '1 second'))) RETURNING id`
	rows, err = c.QueryParams(ctx, update, strings.TrimSpace(eventType), id, seconds)
	if err != nil {
		return false, err
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return false, err
	}
	return len(rows.Values) == 1, nil
}

func (p *PostgresBackend) EnqueueDeliveryForTenant(ctx context.Context, deliveryID, eventType, tenantID, typ string, payload any, availableAt time.Time) (fresh bool, err error) {
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
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if availableAt.IsZero() {
		availableAt = time.Now().UTC()
	}
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	if err = lockSpecs(ctx, c, []pgSpec{pgGlobal(pgKindTenant)}); err != nil {
		return false, err
	}
	tenantRows, err := c.QueryParams(ctx, `SELECT status FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3 FOR SHARE`, pgSystemTenant, pgKindTenant, tenantID)
	if err != nil {
		return false, err
	}
	if len(tenantRows.Values) != 1 || len(tenantRows.Values[0]) < 1 || tenantRows.Values[0][0] == nil || *tenantRows.Values[0][0] != "enabled" {
		return false, fmt.Errorf("tenant %q not found or disabled", tenantID)
	}
	insertDelivery := `INSERT INTO ciradar_webhook_deliveries(id,event_type,status,error) VALUES ($1,$2,'queued','') ON CONFLICT (id) DO NOTHING RETURNING id`
	deliveryRows, err := c.QueryParams(ctx, insertDelivery, deliveryID, strings.TrimSpace(eventType))
	if err != nil {
		return false, err
	}
	if len(deliveryRows.Values) == 0 {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return false, err
		}
		return false, nil
	}
	insertJob := `INSERT INTO ciradar_jobs(tenant_id,type,payload,status,attempts,available_at,created_at,updated_at) VALUES ($1,$2,$3::jsonb,'queued',0,$4,now(),now())`
	if err = c.ExecParams(ctx, insertJob, tenantID, typ, string(data), availableAt.UTC()); err != nil {
		return false, err
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return false, err
	}
	return true, nil
}

func (p *PostgresBackend) UpdateDelivery(ctx context.Context, id, status, errText string) error {
	return p.execParams(ctx, `UPDATE ciradar_webhook_deliveries SET status=$1,error=$2 WHERE id=$3`, status, trim(errText, 4000), id)
}

func (p *PostgresBackend) RecordAnalysisForTenant(ctx context.Context, tenantID string, input model.AnalysisInput, result model.AnalysisResult, storeExcerpt, storeRaw bool) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgGlobalOne(pgKindTenant, normalizeTenant(tenantID)), pgTenant(tenantID, pgKindAnalysis)}, func(store *Store) error {
		return store.RecordAnalysisForTenant(ctx, tenantID, input, result, storeExcerpt, storeRaw)
	})
}

func (p *PostgresBackend) GetAnalysisForTenant(ctx context.Context, tenantID, id string) (*model.AnalysisResult, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAnalysis)}, func(store *Store) (*model.AnalysisResult, error) {
		return store.GetAnalysisForTenant(ctx, tenantID, id)
	})
}

func (p *PostgresBackend) ListAnalysesForTenant(ctx context.Context, tenantID string, limit int) ([]model.AnalysisResult, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAnalysis)}, func(store *Store) ([]model.AnalysisResult, error) {
		return store.ListAnalysesForTenant(ctx, tenantID, limit)
	})
}

func (p *PostgresBackend) CorrelationForTenant(ctx context.Context, tenantID, fingerprint, repository, organization string, since time.Time, crossTenant bool) (CorrelationStats, error) {
	tenantID = normalizeTenant(tenantID)
	repository = strings.TrimSpace(repository)
	organization = strings.TrimSpace(organization)
	c, err := p.connect(ctx)
	if err != nil {
		return CorrelationStats{}, err
	}
	defer p.release(c)
	query := `SELECT count(*)::text,count(DISTINCT CASE WHEN repository<>'' THEN tenant_id||'|'||repository END)::text,count(DISTINCT CASE WHEN organization<>'' THEN tenant_id||'|'||organization END)::text,count(*) FILTER (WHERE tenant_id=$1 AND repository=$2)::text,count(*) FILTER (WHERE tenant_id=$1 AND organization=$3)::text FROM ciradar_objects WHERE kind=$4 AND fingerprint=$5 AND event_time>=$6`
	args := []any{tenantID, repository, organization, pgKindAnalysis, strings.TrimSpace(fingerprint), since.UTC()}
	if !crossTenant {
		query += ` AND tenant_id=$7`
		args = append(args, tenantID)
	}
	rows, err := c.QueryParams(ctx, query, args...)
	if err != nil {
		return CorrelationStats{}, err
	}
	row, err := requireRow(rows, 5)
	if err != nil {
		return CorrelationStats{}, err
	}
	occurrences, err := parsePostgresInt(row[0], "correlation occurrence count")
	if err != nil {
		return CorrelationStats{}, err
	}
	repositories, err := parsePostgresInt(row[1], "correlation repository count")
	if err != nil {
		return CorrelationStats{}, err
	}
	organizations, err := parsePostgresInt(row[2], "correlation organization count")
	if err != nil {
		return CorrelationStats{}, err
	}
	repositorySeen, err := parsePostgresInt(row[3], "correlation repository membership")
	if err != nil {
		return CorrelationStats{}, err
	}
	organizationSeen, err := parsePostgresInt(row[4], "correlation organization membership")
	if err != nil {
		return CorrelationStats{}, err
	}
	if repository != "" || organization != "" {
		occurrences++
	}
	if repository != "" && repositorySeen == 0 {
		repositories++
	}
	if organization != "" && organizationSeen == 0 {
		organizations++
	}
	return CorrelationStats{Repositories: repositories, Organizations: organizations, Occurrences: occurrences}, nil
}

func (p *PostgresBackend) RecordSuccessfulEnvironmentForTenant(ctx context.Context, tenantID, repository, workflow, job, sha string, environment model.Environment, at time.Time) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgTenant(tenantID, pgKindEnvironment)}, func(store *Store) error {
		return store.RecordSuccessfulEnvironmentForTenant(ctx, tenantID, repository, workflow, job, sha, environment, at)
	})
}

func (p *PostgresBackend) LastSuccessfulEnvironmentForTenant(ctx context.Context, tenantID, repository, workflow, job string) (*model.Environment, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindEnvironment)}, func(store *Store) (*model.Environment, error) {
		return store.LastSuccessfulEnvironmentForTenant(ctx, tenantID, repository, workflow, job)
	})
}

func (p *PostgresBackend) GetIncidentForTenant(ctx context.Context, tenantID, fingerprint string) (*model.Incident, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindIncident)}, func(store *Store) (*model.Incident, error) {
		return store.GetIncidentForTenant(ctx, tenantID, fingerprint)
	})
}

func (p *PostgresBackend) ListIncidentsForTenant(ctx context.Context, tenantID string, limit int, state string) ([]model.Incident, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindIncident)}, func(store *Store) ([]model.Incident, error) {
		return store.ListIncidentsForTenant(ctx, tenantID, limit, state)
	})
}

func (p *PostgresBackend) UpsertIncidentForTenant(ctx context.Context, tenantID string, incident model.Incident) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgTenant(tenantID, pgKindIncident)}, func(store *Store) error {
		return store.UpsertIncidentForTenant(ctx, tenantID, incident)
	})
}

func (p *PostgresBackend) UpdateIncidentState(ctx context.Context, tenantID, fingerprint, state, actor, note string) (*model.Incident, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgTenant(tenantID, pgKindIncident)}, func(store *Store) (*model.Incident, error) {
		return store.UpdateIncidentState(ctx, tenantID, fingerprint, state, actor, note)
	})
}

func (p *PostgresBackend) ResolveStaleIncidentsDetailed(ctx context.Context, cutoff time.Time) ([]model.Incident, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgAll(pgKindIncident)}, func(store *Store) ([]model.Incident, error) {
		return store.ResolveStaleIncidentsDetailed(ctx, cutoff)
	})
}

func (p *PostgresBackend) RecordProviderStatus(ctx context.Context, status model.ProviderStatus) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgGlobal(pgKindProvider)}, func(store *Store) error { return store.RecordProviderStatus(ctx, status) })
}

func (p *PostgresBackend) ListProviderStatuses(ctx context.Context) ([]model.ProviderStatus, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgGlobal(pgKindProvider)}, func(store *Store) ([]model.ProviderStatus, error) { return store.ListProviderStatuses(ctx) })
}

type beginNotificationResult struct {
	Status   string
	Delivery model.NotificationDelivery
}

func (p *PostgresBackend) BeginNotificationDeliveryForTenant(ctx context.Context, tenantID, eventID, channel, channelType, dedupeKey string, cooldown time.Duration, maxAttempts int) (string, model.NotificationDelivery, error) {
	result, err := pgStateWith(ctx, p, true, []pgSpec{pgTenant(tenantID, pgKindNotification)}, func(store *Store) (beginNotificationResult, error) {
		status, delivery, err := store.BeginNotificationDeliveryForTenant(ctx, tenantID, eventID, channel, channelType, dedupeKey, cooldown, maxAttempts)
		return beginNotificationResult{Status: status, Delivery: delivery}, err
	})
	return result.Status, result.Delivery, err
}

func (p *PostgresBackend) GetNotificationDeliveryForTenant(ctx context.Context, tenantID, eventID, channel string) (*model.NotificationDelivery, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindNotification)}, func(store *Store) (*model.NotificationDelivery, error) {
		return store.GetNotificationDeliveryForTenant(ctx, tenantID, eventID, channel)
	})
}

func (p *PostgresBackend) RecordNotificationDelivery(ctx context.Context, delivery model.NotificationDelivery) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgTenant(delivery.TenantID, pgKindNotification)}, func(store *Store) error { return store.RecordNotificationDelivery(ctx, delivery) })
}

func (p *PostgresBackend) ListNotificationDeliveriesForTenant(ctx context.Context, tenantID string, limit int) ([]model.NotificationDelivery, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindNotification)}, func(store *Store) ([]model.NotificationDelivery, error) {
		return store.ListNotificationDeliveriesForTenant(ctx, tenantID, limit)
	})
}

func (p *PostgresBackend) CreateTenant(ctx context.Context, id, name string) (model.Tenant, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgGlobal(pgKindTenant)}, func(store *Store) (model.Tenant, error) { return store.CreateTenant(ctx, id, name) })
}

func (p *PostgresBackend) GetTenant(ctx context.Context, id string) (*model.Tenant, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgGlobalOne(pgKindTenant, normalizeTenant(id))}, func(store *Store) (*model.Tenant, error) { return store.GetTenant(ctx, id) })
}

func (p *PostgresBackend) ListTenants(ctx context.Context) ([]model.Tenant, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgGlobal(pgKindTenant)}, func(store *Store) ([]model.Tenant, error) { return store.ListTenants(ctx) })
}

func (p *PostgresBackend) SetTenantEnabled(ctx context.Context, id string, enabled bool) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgGlobal(pgKindTenant)}, func(store *Store) error { return store.SetTenantEnabled(ctx, id, enabled) })
}

type apiKeyCreate struct {
	Key   model.APIKey
	Token string
}

func (p *PostgresBackend) CreateAPIKey(ctx context.Context, tenantID, name string, role model.Role) (model.APIKey, string, error) {
	value, err := pgStateWith(ctx, p, true, []pgSpec{pgGlobalOne(pgKindTenant, normalizeTenant(tenantID)), pgTenant(tenantID, pgKindAPIKey)}, func(store *Store) (apiKeyCreate, error) {
		key, token, err := store.CreateAPIKey(ctx, tenantID, name, role)
		return apiKeyCreate{Key: key, Token: token}, err
	})
	return value.Key, value.Token, err
}

func (p *PostgresBackend) AuthenticateAPIKey(ctx context.Context, token string) (principal *model.Principal, err error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	fingerprint := hashToken(token)
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	query := `SELECT k.tenant_id,k.object_id,encode(convert_to(k.payload::text,'UTF8'),'base64') FROM ciradar_objects k JOIN ciradar_objects t ON t.tenant_id=$1 AND t.kind=$2 AND t.object_id=k.tenant_id AND t.status='enabled' WHERE k.kind=$3 AND k.fingerprint=$4 AND k.status='active' LIMIT 1 FOR UPDATE OF k`
	rows, err := c.QueryParams(ctx, query, pgSystemTenant, pgKindTenant, pgKindAPIKey, fingerprint)
	if err != nil {
		return nil, err
	}
	if len(rows.Values) == 0 {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	row, err := requireRow(rows, 3)
	if err != nil {
		return nil, err
	}
	payload, err := decodePGBase64(valueOf(row[2]))
	if err != nil {
		return nil, err
	}
	var record apiKeyRecord
	if err = json.Unmarshal(payload, &record); err != nil {
		return nil, err
	}
	if record.Hash != fingerprint || !record.Key.RevokedAt.IsZero() {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	now := time.Now().UTC()
	if record.Key.LastUsedAt.IsZero() || now.Sub(record.Key.LastUsedAt) >= 5*time.Minute {
		record.Key.LastUsedAt = now
		encoded, marshalErr := json.Marshal(record)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if err = c.ExecParams(ctx, `UPDATE ciradar_objects SET payload=$1::jsonb,updated_at=now() WHERE tenant_id=$2 AND kind=$3 AND object_id=$4`, string(encoded), valueOf(row[0]), pgKindAPIKey, valueOf(row[1])); err != nil {
			return nil, err
		}
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return nil, err
	}
	return &model.Principal{TenantID: record.Key.TenantID, Name: record.Key.Name, Role: record.Key.Role, APIKeyID: record.Key.ID}, nil
}

func (p *PostgresBackend) GetAPIKey(ctx context.Context, tenantID, id string) (*model.APIKey, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgOne(tenantID, pgKindAPIKey, id)}, func(store *Store) (*model.APIKey, error) {
		return store.GetAPIKey(ctx, tenantID, id)
	})
}

func (p *PostgresBackend) ListAPIKeys(ctx context.Context, tenantID string) ([]model.APIKey, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAPIKey)}, func(store *Store) ([]model.APIKey, error) { return store.ListAPIKeys(ctx, tenantID) })
}

func (p *PostgresBackend) RevokeAPIKey(ctx context.Context, tenantID, id string) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgTenant(tenantID, pgKindAPIKey)}, func(store *Store) error { return store.RevokeAPIKey(ctx, tenantID, id) })
}

func (p *PostgresBackend) RecordAudit(ctx context.Context, event model.AuditEvent) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgTenant(event.TenantID, pgKindAudit)}, func(store *Store) error { return store.RecordAudit(ctx, event) })
}

func (p *PostgresBackend) ListAudit(ctx context.Context, tenantID string, limit int) ([]model.AuditEvent, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAudit)}, func(store *Store) ([]model.AuditEvent, error) { return store.ListAudit(ctx, tenantID, limit) })
}

func (p *PostgresBackend) BindInstallation(ctx context.Context, tenantID string, installationID int64) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgGlobalOne(pgKindTenant, normalizeTenant(tenantID)), pgGlobal(pgKindInstallation)}, func(store *Store) error { return store.BindInstallation(ctx, tenantID, installationID) })
}

func (p *PostgresBackend) UnbindInstallation(ctx context.Context, installationID int64) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgGlobal(pgKindInstallation)}, func(store *Store) error { return store.UnbindInstallation(ctx, installationID) })
}

func (p *PostgresBackend) ResolveInstallationTenant(ctx context.Context, installationID int64) (string, bool) {
	value, err := pgStateWith(ctx, p, false, []pgSpec{pgGlobal(pgKindInstallation)}, func(store *Store) (struct {
		Tenant string
		Found  bool
	}, error) {
		tenant, found := store.ResolveInstallationTenant(ctx, installationID)
		return struct {
			Tenant string
			Found  bool
		}{Tenant: tenant, Found: found}, nil
	})
	if err != nil {
		return "", false
	}
	return value.Tenant, value.Found
}

func (p *PostgresBackend) ListInstallationBindings(ctx context.Context) map[string]string {
	value, err := pgStateWith(ctx, p, false, []pgSpec{pgGlobal(pgKindInstallation)}, func(store *Store) (map[string]string, error) { return store.ListInstallationBindings(ctx), nil })
	if err != nil {
		return map[string]string{}
	}
	return value
}

func (p *PostgresBackend) UpsertRepositoryProfile(ctx context.Context, profile model.RepositoryProfile) (model.RepositoryProfile, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgGlobalOne(pgKindTenant, normalizeTenant(profile.TenantID)), pgTenant(profile.TenantID, pgKindProfile)}, func(store *Store) (model.RepositoryProfile, error) {
		return store.UpsertRepositoryProfile(ctx, profile)
	})
}

func (p *PostgresBackend) GetRepositoryProfile(ctx context.Context, tenantID, repository string) (*model.RepositoryProfile, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindProfile)}, func(store *Store) (*model.RepositoryProfile, error) {
		return store.GetRepositoryProfile(ctx, tenantID, repository)
	})
}

func (p *PostgresBackend) ListRepositoryProfiles(ctx context.Context, tenantID string) ([]model.RepositoryProfile, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindProfile)}, func(store *Store) ([]model.RepositoryProfile, error) {
		return store.ListRepositoryProfiles(ctx, tenantID)
	})
}

func (p *PostgresBackend) Stats(ctx context.Context) (Stats, error) {
	return p.StatsForTenant(ctx, model.DefaultTenantID)
}

func (p *PostgresBackend) StatsForTenant(ctx context.Context, tenantID string) (Stats, error) {
	stats, err := pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAnalysis), pgTenant(tenantID, pgKindIncident), pgTenant(tenantID, pgKindNotification)}, func(store *Store) (Stats, error) { return store.StatsForTenant(ctx, tenantID) })
	if err != nil {
		return Stats{}, err
	}
	c, err := p.connect(ctx)
	if err != nil {
		return Stats{}, err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, `SELECT count(*) FILTER (WHERE status='queued')::text,count(*) FILTER (WHERE status='running')::text,count(*) FILTER (WHERE status='failed')::text FROM ciradar_jobs WHERE tenant_id=$1`, normalizeTenant(tenantID))
	if err != nil {
		return Stats{}, err
	}
	row, err := requireRow(rows, 3)
	if err != nil {
		return Stats{}, err
	}
	if stats.QueuedJobs, err = parsePostgresInt(row[0], "queued job count"); err != nil {
		return Stats{}, err
	}
	if stats.RunningJobs, err = parsePostgresInt(row[1], "running job count"); err != nil {
		return Stats{}, err
	}
	if stats.FailedJobs, err = parsePostgresInt(row[2], "failed job count"); err != nil {
		return Stats{}, err
	}
	return stats, nil
}

func (p *PostgresBackend) Dashboard(ctx context.Context, tenantID string, since time.Time) (model.DashboardSummary, error) {
	tenantID = normalizeTenant(tenantID)
	specs := []pgSpec{pgTenant(tenantID, pgKindAnalysis), pgTenant(tenantID, pgKindIncident), pgTenant(tenantID, pgKindNotification), pgTenant(tenantID, pgKindFeedback), pgTenant(tenantID, pgKindTestStats), pgTenant(tenantID, pgKindQuarantine)}
	dashboard, err := pgStateWith(ctx, p, false, specs, func(store *Store) (model.DashboardSummary, error) { return store.Dashboard(ctx, tenantID, since) })
	if err != nil {
		return model.DashboardSummary{}, err
	}
	c, err := p.connect(ctx)
	if err != nil {
		return model.DashboardSummary{}, err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, `SELECT occurred_at::date::text,count(*)::text FROM ciradar_test_observations WHERE tenant_id=$1 AND occurred_at>=$2 AND status IN ('failed','error') GROUP BY occurred_at::date ORDER BY occurred_at::date`, tenantID, since.UTC())
	if err != nil {
		return model.DashboardSummary{}, err
	}
	if dashboard.DailyTestFailures == nil {
		dashboard.DailyTestFailures = map[string]int{}
	}
	for _, row := range rows.Values {
		if len(row) < 2 || row[0] == nil {
			continue
		}
		count, parseErr := parsePostgresInt(row[1], "daily test failure count")
		if parseErr != nil {
			return model.DashboardSummary{}, parseErr
		}
		dashboard.DailyTestFailures[*row[0]] = count
	}
	return dashboard, nil
}

func (p *PostgresBackend) UpsertDiagnosisFeedback(ctx context.Context, feedback model.DiagnosisFeedback) (model.DiagnosisFeedback, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgTenant(feedback.TenantID, pgKindAnalysis), pgTenant(feedback.TenantID, pgKindFeedback)}, func(store *Store) (model.DiagnosisFeedback, error) {
		return store.UpsertDiagnosisFeedback(ctx, feedback)
	})
}

func (p *PostgresBackend) ListDiagnosisFeedback(ctx context.Context, tenantID string, limit int) ([]model.DiagnosisFeedback, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindFeedback)}, func(store *Store) ([]model.DiagnosisFeedback, error) {
		return store.ListDiagnosisFeedback(ctx, tenantID, limit)
	})
}

func (p *PostgresBackend) FeedbackMetrics(ctx context.Context, tenantID string) (model.FeedbackMetrics, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindAnalysis), pgTenant(tenantID, pgKindFeedback)}, func(store *Store) (model.FeedbackMetrics, error) { return store.FeedbackMetrics(ctx, tenantID) })
}

func (p *PostgresBackend) RecordTestObservations(ctx context.Context, tenantID string, observations []model.TestObservation) (out []model.TestCaseStats, err error) {
	tenantID = normalizeTenant(tenantID)
	observations = normalizePostgresObservations(tenantID, observations)
	if len(observations) == 0 {
		return nil, nil
	}
	specs := make([]pgSpec, 0, len(observations)*2)
	seen := map[string]bool{}
	for _, observation := range observations {
		key := TestKey(observation)
		if seen[key] {
			continue
		}
		seen[key] = true
		specs = append(specs, pgOne(tenantID, pgKindTestStats, key), pgOne(tenantID, pgKindQuarantine, key))
	}
	specs = normalizeSpecs(specs)
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	if err = lockSpecs(ctx, c, specs); err != nil {
		return nil, err
	}
	observations, err = filterExistingNativeTestObservations(ctx, c, tenantID, observations)
	if err != nil {
		return nil, err
	}
	if len(observations) == 0 {
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return nil, err
		}
		return nil, nil
	}
	objects, err := loadPGObjects(ctx, c, specs, true)
	if err != nil {
		return nil, err
	}
	store, err := hydrateStore(objects)
	if err != nil {
		return nil, err
	}
	out, err = store.RecordTestObservations(ctx, tenantID, observations)
	if err != nil {
		return nil, err
	}
	current, err := stateObjects(store.state)
	if err != nil {
		return nil, err
	}
	for _, object := range current {
		if matchesSpec(specs, object) {
			if err = upsertPGObject(ctx, c, object); err != nil {
				return nil, err
			}
		}
	}
	for _, observation := range observations {
		if err = insertNativeTestObservation(ctx, c, observation); err != nil {
			return nil, err
		}
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresBackend) ListTestCaseStats(ctx context.Context, tenantID, repository, classification string, limit int) ([]model.TestCaseStats, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindTestStats), pgTenant(tenantID, pgKindQuarantine)}, func(store *Store) ([]model.TestCaseStats, error) {
		return store.ListTestCaseStats(ctx, tenantID, repository, classification, limit)
	})
}

func (p *PostgresBackend) GetTestCaseStats(ctx context.Context, tenantID, testKey string) (*model.TestCaseStats, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgOne(tenantID, pgKindTestStats, testKey), pgOne(tenantID, pgKindQuarantine, testKey)}, func(store *Store) (*model.TestCaseStats, error) {
		return store.GetTestCaseStats(ctx, tenantID, testKey)
	})
}

func (p *PostgresBackend) ListTestObservations(ctx context.Context, tenantID, testKey string, limit int) ([]model.TestObservation, error) {
	tenantID = normalizeTenant(tenantID)
	testKey = strings.TrimSpace(testKey)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	query := `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_test_observations WHERE tenant_id=$1 AND test_key=$2 ORDER BY occurred_at DESC LIMIT $3`
	rows, err := c.QueryParams(ctx, query, tenantID, testKey, limit)
	if err != nil {
		return nil, err
	}
	out := make([]model.TestObservation, 0, len(rows.Values))
	for _, row := range rows.Values {
		if len(row) == 0 || row[0] == nil {
			continue
		}
		payload, decodeErr := decodePGBase64(*row[0])
		if decodeErr != nil {
			return nil, decodeErr
		}
		var observation model.TestObservation
		if unmarshalErr := json.Unmarshal(payload, &observation); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		out = append(out, observation)
	}
	return out, nil
}

func (p *PostgresBackend) SetTestCritical(ctx context.Context, tenantID, testKey string, critical bool) (*model.TestCaseStats, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgOne(tenantID, pgKindTestStats, testKey)}, func(store *Store) (*model.TestCaseStats, error) {
		return store.SetTestCritical(ctx, tenantID, testKey, critical)
	})
}

func (p *PostgresBackend) SetTestQuarantine(ctx context.Context, quarantine model.TestQuarantine) (model.TestQuarantine, error) {
	return pgStateWith(ctx, p, true, []pgSpec{pgOne(quarantine.TenantID, pgKindTestStats, quarantine.TestKey), pgOne(quarantine.TenantID, pgKindQuarantine, quarantine.TestKey)}, func(store *Store) (model.TestQuarantine, error) { return store.SetTestQuarantine(ctx, quarantine) })
}

func (p *PostgresBackend) RemoveTestQuarantine(ctx context.Context, tenantID, testKey string) error {
	return pgStateErr(ctx, p, true, []pgSpec{pgOne(tenantID, pgKindTestStats, testKey), pgOne(tenantID, pgKindQuarantine, testKey)}, func(store *Store) error { return store.RemoveTestQuarantine(ctx, tenantID, testKey) })
}

func (p *PostgresBackend) ListTestQuarantines(ctx context.Context, tenantID string) ([]model.TestQuarantine, error) {
	return pgStateWith(ctx, p, false, []pgSpec{pgTenant(tenantID, pgKindQuarantine)}, func(store *Store) ([]model.TestQuarantine, error) { return store.ListTestQuarantines(ctx, tenantID) })
}

func extensionKind(kind string) string {
	return "extension:" + strings.ToLower(strings.TrimSpace(kind))
}

func (p *PostgresBackend) PutObject(ctx context.Context, tenantID, kind, id string, value any) (err error) {
	tenantID = normalizeTenant(tenantID)
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if kind == "" || id == "" {
		return errors.New("kind and id are required")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	spec := pgSpec{Tenant: tenantID, Kind: extensionKind(kind), ObjectID: id}
	if err = lockSpecs(ctx, c, []pgSpec{spec}); err != nil {
		return err
	}
	now := time.Now().UTC()
	object := ExtensionObject{TenantID: tenantID, Kind: kind, ID: id, Value: data, CreatedAt: now, UpdatedAt: now}
	rows, err := c.QueryParams(ctx, `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3 FOR UPDATE`, tenantID, extensionKind(kind), id)
	if err != nil {
		return err
	}
	if len(rows.Values) == 1 && len(rows.Values[0]) > 0 && rows.Values[0][0] != nil {
		oldData, decodeErr := decodePGBase64(*rows.Values[0][0])
		if decodeErr == nil {
			var old ExtensionObject
			if json.Unmarshal(oldData, &old) == nil && !old.CreatedAt.IsZero() {
				object.CreatedAt = old.CreatedAt
			}
		}
	}
	payload, _ := json.Marshal(object)
	if err = upsertPGObject(ctx, c, pgObject{Tenant: tenantID, Kind: extensionKind(kind), ID: id, Payload: payload, EventTime: now, Status: "active"}); err != nil {
		return err
	}
	return c.Exec(ctx, "COMMIT")
}

func (p *PostgresBackend) PutObjectIfKindBelowLimit(ctx context.Context, tenantID, kind, id string, value any, limit int) (created bool, err error) {
	tenantID = normalizeTenant(tenantID)
	kind = strings.ToLower(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if kind == "" || id == "" || limit < 1 {
		return false, errors.New("kind, id, and a positive limit are required")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	kindName := extensionKind(kind)
	if err = lockSpecs(ctx, c, []pgSpec{{Tenant: tenantID, Kind: kindName}}); err != nil {
		return false, err
	}
	rows, err := c.QueryParams(ctx, `SELECT count(*)::text FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2`, tenantID, kindName)
	if err != nil {
		return false, err
	}
	row, err := requireRow(rows, 1)
	if err != nil {
		return false, err
	}
	if row[0] == nil {
		return false, errors.New("postgres object quota count returned no value")
	}
	count, err := strconv.Atoi(*row[0])
	if err != nil {
		return false, fmt.Errorf("parse postgres object count: %w", err)
	}
	existingRows, err := c.QueryParams(ctx, `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3 FOR UPDATE`, tenantID, kindName, id)
	if err != nil {
		return false, err
	}
	exists := len(existingRows.Values) == 1 && len(existingRows.Values[0]) > 0 && existingRows.Values[0][0] != nil
	if !exists && count >= limit {
		if err = c.Exec(ctx, "ROLLBACK"); err != nil {
			return false, err
		}
		return false, nil
	}
	now := time.Now().UTC()
	object := ExtensionObject{TenantID: tenantID, Kind: kind, ID: id, Value: data, CreatedAt: now, UpdatedAt: now}
	if exists {
		oldData, decodeErr := decodePGBase64(*existingRows.Values[0][0])
		if decodeErr == nil {
			var old ExtensionObject
			if json.Unmarshal(oldData, &old) == nil && !old.CreatedAt.IsZero() {
				object.CreatedAt = old.CreatedAt
			}
		}
	}
	payload, err := json.Marshal(object)
	if err != nil {
		return false, err
	}
	if err = upsertPGObject(ctx, c, pgObject{Tenant: tenantID, Kind: kindName, ID: id, Payload: payload, EventTime: now, Status: "active"}); err != nil {
		return false, err
	}
	if err = c.Exec(ctx, "COMMIT"); err != nil {
		return false, err
	}
	return true, nil
}

func (p *PostgresBackend) GetObject(ctx context.Context, tenantID, kind, id string, out any) (bool, error) {
	c, err := p.connect(ctx)
	if err != nil {
		return false, err
	}
	defer p.release(c)
	rows, err := c.QueryParams(ctx, `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3`, normalizeTenant(tenantID), extensionKind(kind), strings.TrimSpace(id))
	if err != nil || len(rows.Values) == 0 {
		return false, err
	}
	row, err := requireRow(rows, 1)
	if err != nil || row[0] == nil {
		return false, err
	}
	payload, err := decodePGBase64(*row[0])
	if err != nil {
		return false, err
	}
	var object ExtensionObject
	if err := json.Unmarshal(payload, &object); err != nil {
		return false, err
	}
	if out != nil {
		if err := json.Unmarshal(object.Value, out); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (p *PostgresBackend) ListObjects(ctx context.Context, tenantID, kind string, limit int) ([]ExtensionObject, error) {
	if limit < 1 || limit > 10000 {
		limit = 500
	}
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer p.release(c)
	query := `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 ORDER BY event_time DESC NULLS LAST,updated_at DESC LIMIT $3`
	rows, err := c.QueryParams(ctx, query, normalizeTenant(tenantID), extensionKind(kind), limit)
	if err != nil {
		return nil, err
	}
	out := make([]ExtensionObject, 0, len(rows.Values))
	for _, row := range rows.Values {
		if len(row) == 0 || row[0] == nil {
			continue
		}
		payload, err := decodePGBase64(*row[0])
		if err != nil {
			return nil, err
		}
		var object ExtensionObject
		if json.Unmarshal(payload, &object) == nil {
			out = append(out, object)
		}
	}
	return out, nil
}

func (p *PostgresBackend) DeleteObject(ctx context.Context, tenantID, kind, id string) error {
	return p.execParams(ctx, `DELETE FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3`, normalizeTenant(tenantID), extensionKind(kind), strings.TrimSpace(id))
}

func (p *PostgresBackend) Cleanup(ctx context.Context, retentionDays int) error {
	if retentionDays < 1 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer p.release(c)
	if err := ensureObservationPartitions(ctx, c, time.Now().UTC()); err != nil {
		return err
	}
	if err := dropExpiredObservationPartitions(ctx, c, cutoff); err != nil {
		return err
	}
	if err := c.Exec(ctx, "BEGIN"); err != nil {
		return err
	}
	queries := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM ciradar_test_observations WHERE occurred_at<$1`, []any{cutoff}},
		{`DELETE FROM ciradar_objects WHERE kind IN ($1,$2,$3,$4,$5) AND event_time<$6`, []any{pgKindAnalysis, pgKindEnvironment, pgKindAudit, pgKindNotification, pgKindObservation, cutoff}},
		{`DELETE FROM ciradar_objects WHERE kind=$1 AND state='resolved' AND event_time<$2`, []any{pgKindIncident, cutoff}},
		{`DELETE FROM ciradar_webhook_deliveries WHERE received_at<$1`, []any{cutoff}},
		{`DELETE FROM ciradar_jobs WHERE status NOT IN ('queued','running') AND updated_at<$1`, []any{cutoff}},
		{`DELETE FROM ciradar_rate_limits WHERE updated_at<$1`, []any{time.Now().UTC().Add(-48 * time.Hour)}},
		{`DELETE FROM ciradar_auth_failures WHERE updated_at<$1`, []any{time.Now().UTC().Add(-48 * time.Hour)}},
		{`DELETE FROM ciradar_sso_replays WHERE expires_at<$1`, []any{time.Now().UTC()}},
		{`DELETE FROM ciradar_objects WHERE kind=$1 AND event_time<$2`, []any{extensionKind("oauth_revocation"), time.Now().UTC().Add(-2 * time.Hour)}},
	}
	for _, query := range queries {
		if err := c.ExecParams(ctx, query.sql, query.args...); err != nil {
			rollbackPostgres(c)
			return err
		}
	}
	return c.Exec(ctx, "COMMIT")
}

var _ Backend = (*PostgresBackend)(nil)
