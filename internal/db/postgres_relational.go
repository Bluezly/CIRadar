package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/pgwire"
)

const (
	pgSystemTenant              = "__system__"
	postgresSchemaVersion int64 = 8
)

const (
	pgKindAnalysis     = "analysis"
	pgKindEnvironment  = "environment"
	pgKindIncident     = "incident"
	pgKindProvider     = "provider"
	pgKindNotification = "notification"
	pgKindTenant       = "tenant"
	pgKindAPIKey       = "api_key"
	pgKindAudit        = "audit"
	pgKindInstallation = "installation"
	pgKindProfile      = "repository_profile"
	pgKindFeedback     = "diagnosis_feedback"
	pgKindObservation  = "test_observation"
	pgKindTestStats    = "test_case_stats"
	pgKindQuarantine   = "test_quarantine"
)

type pgSpec struct {
	Tenant   string
	Kind     string
	ObjectID string
	All      bool
}

type pgObject struct {
	Tenant       string
	Kind         string
	ID           string
	Payload      []byte
	EventTime    time.Time
	Repository   string
	Organization string
	Fingerprint  string
	State        string
	Status       string
	DedupeKey    string
	ExpiresAt    time.Time
}

func pgTenant(tenant, kind string) pgSpec {
	return pgSpec{Tenant: normalizeTenant(tenant), Kind: kind}
}

func pgGlobal(kind string) pgSpec {
	return pgSpec{Tenant: pgSystemTenant, Kind: kind}
}

func pgOne(tenant, kind, objectID string) pgSpec {
	return pgSpec{Tenant: normalizeTenant(tenant), Kind: kind, ObjectID: strings.TrimSpace(objectID)}
}

func pgGlobalOne(kind, objectID string) pgSpec {
	return pgSpec{Tenant: pgSystemTenant, Kind: kind, ObjectID: strings.TrimSpace(objectID)}
}

func pgAll(kind string) pgSpec {
	return pgSpec{Kind: kind, All: true}
}

func nullableTextParam(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableInt64Param(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableTimeParam(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

var observationPartitionNamePattern = regexp.MustCompile(`^ciradar_test_observations_[0-9]{6}$`)

func observationPartitionDDL(name string, from, to time.Time) (string, error) {
	if !observationPartitionNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid observation partition name %q", name)
	}
	fromText := from.UTC().Format(time.RFC3339)
	toText := to.UTC().Format(time.RFC3339)
	return `DO $ciradar_partition$
BEGIN
  IF to_regclass('` + name + `') IS NULL THEN
    LOCK TABLE ciradar_test_observations IN ACCESS EXCLUSIVE MODE;
    CREATE TABLE ` + name + ` (LIKE ciradar_test_observations INCLUDING ALL);
    INSERT INTO ` + name + ` SELECT * FROM ciradar_test_observations_default
      WHERE occurred_at >= '` + fromText + `'::timestamptz AND occurred_at < '` + toText + `'::timestamptz
      ON CONFLICT DO NOTHING;
    DELETE FROM ciradar_test_observations_default
      WHERE occurred_at >= '` + fromText + `'::timestamptz AND occurred_at < '` + toText + `'::timestamptz;
    ALTER TABLE ciradar_test_observations ATTACH PARTITION ` + name + `
      FOR VALUES FROM ('` + fromText + `') TO ('` + toText + `');
  END IF;
END
$ciradar_partition$`, nil
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

func parsePGTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05.999999999-07"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func pgObjectKey(tenant, kind, id string) string {
	return tenant + "\x00" + kind + "\x00" + id
}

func normalizeSpecs(specs []pgSpec) []pgSpec {
	seen := map[string]struct{}{}
	out := make([]pgSpec, 0, len(specs))
	for _, spec := range specs {
		spec.Kind = strings.TrimSpace(spec.Kind)
		if spec.Kind == "" {
			continue
		}
		if !spec.All && spec.Tenant == "" {
			spec.Tenant = model.DefaultTenantID
		}
		key := strconv.FormatBool(spec.All) + "\x00" + spec.Tenant + "\x00" + spec.Kind + "\x00" + spec.ObjectID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			if out[i].Tenant == out[j].Tenant {
				return out[i].ObjectID < out[j].ObjectID
			}
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func specWhere(specs []pgSpec) (string, []any) {
	parts := make([]string, 0, len(specs))
	args := make([]any, 0, len(specs)*3)
	add := func(value any) string {
		args = append(args, value)
		return "$" + strconv.Itoa(len(args))
	}
	for _, spec := range specs {
		if spec.All {
			parts = append(parts, "kind="+add(spec.Kind))
			continue
		}
		part := "(tenant_id=" + add(spec.Tenant) + " AND kind=" + add(spec.Kind)
		if spec.ObjectID != "" {
			part += " AND object_id=" + add(spec.ObjectID)
		}
		parts = append(parts, part+")")
	}
	if len(parts) == 0 {
		return "FALSE", nil
	}
	return strings.Join(parts, " OR "), args
}

func matchesSpec(specs []pgSpec, object pgObject) bool {
	for _, spec := range specs {
		if spec.Kind != object.Kind {
			continue
		}
		if spec.All || (spec.Tenant == object.Tenant && (spec.ObjectID == "" || spec.ObjectID == object.ID)) {
			return true
		}
	}
	return false
}

func (p *PostgresBackend) migrateRelational(ctx context.Context, c *pgwire.Client) error {
	if err := c.Exec(ctx, `CREATE TABLE IF NOT EXISTS ciradar_schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	rows, err := c.Query(ctx, `SELECT coalesce(max(version),0)::text FROM ciradar_schema_migrations`)
	if err != nil {
		return err
	}
	row, err := requireRow(rows, 1)
	if err != nil {
		return err
	}
	version, err := strconv.ParseInt(valueOf(row[0]), 10, 64)
	if err != nil {
		return fmt.Errorf("parse postgres schema version: %w", err)
	}
	if version > postgresSchemaVersion {
		return fmt.Errorf("postgres schema version %d is newer than supported version %d; refusing an unsafe downgrade", version, postgresSchemaVersion)
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ciradar_objects (tenant_id text NOT NULL, kind text NOT NULL, object_id text NOT NULL, payload jsonb NOT NULL, event_time timestamptz, repository text, organization text, fingerprint text, state text, status text, dedupe_key text, expires_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,kind,object_id))`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_tenant_kind_time_idx ON ciradar_objects (tenant_id,kind,event_time DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_fingerprint_time_idx ON ciradar_objects (kind,fingerprint,event_time DESC) WHERE fingerprint IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_repository_time_idx ON ciradar_objects (tenant_id,repository,event_time DESC) WHERE repository IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_status_time_idx ON ciradar_objects (tenant_id,kind,status,event_time DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_dedupe_idx ON ciradar_objects (tenant_id,kind,dedupe_key,event_time DESC) WHERE dedupe_key IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_expires_idx ON ciradar_objects (expires_at) WHERE expires_at IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_event_brin_idx ON ciradar_objects USING brin (event_time) WHERE event_time IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS ciradar_jobs (id bigserial PRIMARY KEY, tenant_id text NOT NULL, type text NOT NULL, payload jsonb NOT NULL, status text NOT NULL, attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL, locked_at timestamptz, locked_by text, last_error text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS ciradar_jobs_claim_idx ON ciradar_jobs (status,available_at,id)`,
		`CREATE INDEX IF NOT EXISTS ciradar_jobs_tenant_idx ON ciradar_jobs (tenant_id,status,available_at)`,
		`CREATE TABLE IF NOT EXISTS ciradar_webhook_deliveries (id text PRIMARY KEY, event_type text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL, error text NOT NULL DEFAULT '')`,
		`CREATE UNLOGGED TABLE IF NOT EXISTS ciradar_rate_limits (scope text NOT NULL, key_hash text NOT NULL, window_start timestamptz NOT NULL, count bigint NOT NULL, updated_at timestamptz NOT NULL, PRIMARY KEY (scope,key_hash))`,
		`CREATE INDEX IF NOT EXISTS ciradar_rate_limits_updated_idx ON ciradar_rate_limits (updated_at)`,
		`CREATE TABLE IF NOT EXISTS ciradar_auth_failures (key_hash text PRIMARY KEY, window_start timestamptz NOT NULL, failures integer NOT NULL, blocked_until timestamptz, updated_at timestamptz NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS ciradar_auth_failures_updated_idx ON ciradar_auth_failures (updated_at)`,
		`CREATE TABLE IF NOT EXISTS ciradar_sso_replays (key_hash text PRIMARY KEY, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS ciradar_sso_replays_expires_idx ON ciradar_sso_replays (expires_at)`,
		`CREATE TABLE IF NOT EXISTS ciradar_test_observations (tenant_id text NOT NULL, id text NOT NULL, repository text NOT NULL, test_key text NOT NULL, framework text, workflow text, job text, run_id bigint, commit_sha text, branch text, status text NOT NULL, duration_ms bigint NOT NULL DEFAULT 0, occurred_at timestamptz NOT NULL, payload jsonb NOT NULL, ingested_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,id,occurred_at)) PARTITION BY RANGE (occurred_at)`,
	}
	for _, statement := range statements {
		if err := c.Exec(ctx, statement); err != nil {
			return err
		}
	}
	if err := c.Exec(ctx, `CREATE TABLE IF NOT EXISTS ciradar_test_observations_default PARTITION OF ciradar_test_observations DEFAULT`); err != nil {
		return err
	}
	if err := ensureObservationPartitions(ctx, c, time.Now().UTC()); err != nil {
		return err
	}
	postPartitionStatements := []string{
		`CREATE INDEX IF NOT EXISTS ciradar_test_observations_repo_time_idx ON ciradar_test_observations (tenant_id,repository,occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_test_observations_test_time_idx ON ciradar_test_observations (tenant_id,test_key,occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_test_observations_status_time_idx ON ciradar_test_observations (tenant_id,status,occurred_at DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_test_observations_time_brin_idx ON ciradar_test_observations USING brin (occurred_at)`,
	}
	for _, statement := range postPartitionStatements {
		if err := c.Exec(ctx, statement); err != nil {
			return err
		}
	}
	if err := p.migrateLegacyState(ctx, c); err != nil {
		return err
	}
	if err := backfillNativeTestObservations(ctx, c); err != nil {
		return err
	}
	defaultTenant := model.Tenant{ID: model.DefaultTenantID, Name: "Default", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	b, _ := json.Marshal(defaultTenant)
	object := pgObject{Tenant: pgSystemTenant, Kind: pgKindTenant, ID: defaultTenant.ID, Payload: b, EventTime: defaultTenant.UpdatedAt, Status: "enabled"}
	if err := insertPGObjectIfMissing(ctx, c, object); err != nil {
		return err
	}
	return c.ExecParams(ctx, `INSERT INTO ciradar_schema_migrations(version) VALUES ($1) ON CONFLICT (version) DO NOTHING`, postgresSchemaVersion)
}

func observationPartitionStatements(now time.Time) ([]string, error) {
	now = now.UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	out := make([]string, 0, 4)
	for offset := -1; offset <= 2; offset++ {
		from := month.AddDate(0, offset, 0)
		to := from.AddDate(0, 1, 0)
		name := fmt.Sprintf("ciradar_test_observations_%04d%02d", from.Year(), int(from.Month()))
		statement, err := observationPartitionDDL(name, from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, statement)
	}
	return out, nil
}

func ensureObservationPartitions(ctx context.Context, c *pgwire.Client, now time.Time) error {
	statements, err := observationPartitionStatements(now)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if err := c.Exec(ctx, statement); err != nil {
			return fmt.Errorf("ensure PostgreSQL observation partition: %w", err)
		}
	}
	return nil
}

func expiredObservationPartitions(rows pgwire.Rows, cutoff time.Time) []string {
	cutoff = cutoff.UTC()
	out := make([]string, 0)
	for _, row := range rows.Values {
		if len(row) == 0 || row[0] == nil {
			continue
		}
		name := strings.TrimSpace(*row[0])
		const prefix = "ciradar_test_observations_"
		if !strings.HasPrefix(name, prefix) || name == prefix+"default" {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if len(suffix) != 6 {
			continue
		}
		year, errYear := strconv.Atoi(suffix[:4])
		month, errMonth := strconv.Atoi(suffix[4:])
		if errYear != nil || errMonth != nil || month < 1 || month > 12 {
			continue
		}
		partitionEnd := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
		if !partitionEnd.After(cutoff) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func dropExpiredObservationPartitions(ctx context.Context, c *pgwire.Client, cutoff time.Time) error {
	rows, err := c.Query(ctx, `SELECT child.relname
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent=parent.oid
JOIN pg_class child ON pg_inherits.inhrelid=child.oid
WHERE parent.relname='ciradar_test_observations'`)
	if err != nil {
		return err
	}
	for _, name := range expiredObservationPartitions(rows, cutoff) {
		if err := c.Exec(ctx, `DROP TABLE IF EXISTS `+name); err != nil {
			return fmt.Errorf("drop expired PostgreSQL observation partition %s: %w", name, err)
		}
	}
	return nil
}

func backfillNativeTestObservations(ctx context.Context, c *pgwire.Client) error {
	query := `INSERT INTO ciradar_test_observations(tenant_id,id,repository,test_key,framework,workflow,job,run_id,commit_sha,branch,status,duration_ms,occurred_at,payload)
SELECT tenant_id,object_id,coalesce(repository,''),coalesce(payload->>'test_key',''),nullif(payload->>'framework',''),nullif(payload->>'workflow',''),nullif(payload->>'job',''),CASE WHEN coalesce(payload->>'run_id','') ~ '^[0-9]+$' THEN (payload->>'run_id')::bigint END,nullif(payload->>'commit_sha',''),nullif(payload->>'branch',''),coalesce(status,payload->>'status','unknown'),CASE WHEN coalesce(payload->>'duration_ms','') ~ '^[0-9]+$' THEN (payload->>'duration_ms')::bigint ELSE 0 END,coalesce(event_time,created_at),payload
FROM ciradar_objects WHERE kind='test_observation' ON CONFLICT DO NOTHING`
	return c.Exec(ctx, query)
}

func (p *PostgresBackend) migrateLegacyState(ctx context.Context, c *pgwire.Client) (err error) {
	rows, err := c.Query(ctx, `SELECT (EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='ciradar_state'))::text`)
	if err != nil {
		return err
	}
	row, err := requireRow(rows, 1)
	if err != nil || !pgBool(row[0]) {
		return err
	}
	countRows, err := c.Query(ctx, `SELECT count(*)::text FROM ciradar_objects`)
	if err != nil {
		return err
	}
	countRow, err := requireRow(countRows, 1)
	if err != nil {
		return err
	}
	count, err := parsePostgresInt(countRow[0], "legacy object count")
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	legacyRows, err := c.Query(ctx, `SELECT encode(convert_to(payload::text,'UTF8'),'base64') FROM ciradar_state WHERE id='global'`)
	if err != nil || len(legacyRows.Values) == 0 {
		return err
	}
	legacyRow, err := requireRow(legacyRows, 1)
	if err != nil {
		return err
	}
	payload, err := decodePGBase64(valueOf(legacyRow[0]))
	if err != nil {
		return err
	}
	store, err := newMemoryStore(payload)
	if err != nil {
		return fmt.Errorf("decode legacy postgres state: %w", err)
	}
	objects, err := stateObjects(store.state)
	if err != nil {
		return err
	}
	if err = c.Exec(ctx, "BEGIN"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			rollbackPostgres(c)
		}
	}()
	for _, object := range objects {
		if err = upsertPGObject(ctx, c, object); err != nil {
			return err
		}
	}
	for _, job := range store.state.Jobs {
		query := `INSERT INTO ciradar_jobs(id,tenant_id,type,payload,status,attempts,available_at,locked_at,locked_by,last_error,created_at,updated_at) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING`
		if err = c.ExecParams(ctx, query, job.ID, normalizeTenant(job.TenantID), job.Type, string(job.Payload), job.Status, job.Attempts, nullableTimeParam(job.AvailableAt), nullableTimeParam(job.LockedAt), nullableTextParam(job.LockedBy), nullableTextParam(job.LastError), nullableTimeParam(job.CreatedAt), nullableTimeParam(job.UpdatedAt)); err != nil {
			return err
		}
	}
	for id, delivery := range store.state.Deliveries {
		query := `INSERT INTO ciradar_webhook_deliveries(id,event_type,received_at,status,error) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`
		if err = c.ExecParams(ctx, query, id, delivery.EventType, nullableTimeParam(delivery.ReceivedAt), delivery.Status, delivery.Error); err != nil {
			return err
		}
	}
	if err = c.Exec(ctx, `SELECT setval(pg_get_serial_sequence('ciradar_jobs','id'),GREATEST((SELECT COALESCE(max(id),1) FROM ciradar_jobs),1),true)`); err != nil {
		return err
	}
	if err = c.Exec(ctx, `INSERT INTO ciradar_schema_migrations(version) VALUES (2) ON CONFLICT (version) DO NOTHING`); err != nil {
		return err
	}
	return c.Exec(ctx, "COMMIT")
}

func normalizePostgresObservations(tenantID string, observations []model.TestObservation) []model.TestObservation {
	return normalizeTestObservations(tenantID, observations)
}

func filterExistingNativeTestObservations(ctx context.Context, c *pgwire.Client, tenantID string, observations []model.TestObservation) ([]model.TestObservation, error) {
	if len(observations) == 0 {
		return nil, nil
	}
	existing := make(map[string]struct{})
	const chunkSize = 500
	for start := 0; start < len(observations); start += chunkSize {
		end := start + chunkSize
		if end > len(observations) {
			end = len(observations)
		}
		args := make([]any, 0, 1+end-start)
		args = append(args, normalizeTenant(tenantID))
		placeholders := make([]string, 0, end-start)
		for _, observation := range observations[start:end] {
			args = append(args, observation.ID)
			placeholders = append(placeholders, "$"+strconv.Itoa(len(args)))
		}
		query := `SELECT DISTINCT id FROM ciradar_test_observations WHERE tenant_id=$1 AND id IN (` + strings.Join(placeholders, ",") + `)`
		rows, err := c.QueryParams(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for _, row := range rows.Values {
			if len(row) > 0 && row[0] != nil {
				existing[*row[0]] = struct{}{}
			}
		}
	}
	filtered := make([]model.TestObservation, 0, len(observations)-len(existing))
	for _, observation := range observations {
		if _, duplicate := existing[observation.ID]; !duplicate {
			filtered = append(filtered, observation)
		}
	}
	return filtered, nil
}

func insertNativeTestObservation(ctx context.Context, c *pgwire.Client, observation model.TestObservation) error {
	payload, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	query := `INSERT INTO ciradar_test_observations(tenant_id,id,repository,test_key,framework,workflow,job,run_id,commit_sha,branch,status,duration_ms,occurred_at,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb) ON CONFLICT DO NOTHING`
	return c.ExecParams(ctx, query,
		normalizeTenant(observation.TenantID), observation.ID, strings.TrimSpace(observation.Repository), TestKey(observation),
		nullableTextParam(observation.Framework), nullableTextParam(observation.Workflow), nullableTextParam(observation.Job), nullableInt64Param(observation.RunID),
		nullableTextParam(observation.CommitSHA), nullableTextParam(observation.Branch), observation.Status, maxInt64(0, observation.DurationMS),
		nullableTimeParam(observation.OccurredAt), string(payload),
	)
}

func lockSpecs(ctx context.Context, c *pgwire.Client, specs []pgSpec) error {
	for _, spec := range specs {
		globalKey := "ciradar:" + spec.Kind + ":*"
		if spec.All {
			if err := c.ExecParams(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, advisoryLockKey(globalKey)); err != nil {
				return err
			}
			continue
		}
		if err := c.ExecParams(ctx, `SELECT pg_advisory_xact_lock_shared($1::bigint)`, advisoryLockKey(globalKey)); err != nil {
			return err
		}
		lockKey := "ciradar:" + spec.Kind + ":" + spec.Tenant
		if spec.ObjectID != "" {
			lockKey += ":" + spec.ObjectID
		}
		if err := c.ExecParams(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, advisoryLockKey(lockKey)); err != nil {
			return err
		}
	}
	return nil
}

func loadPGObjects(ctx context.Context, c *pgwire.Client, specs []pgSpec, forUpdate bool) ([]pgObject, error) {
	where, args := specWhere(specs)
	query := `SELECT tenant_id,kind,object_id,encode(convert_to(payload::text,'UTF8'),'base64'),coalesce(event_time::text,''),coalesce(repository,''),coalesce(organization,''),coalesce(fingerprint,''),coalesce(state,''),coalesce(status,''),coalesce(dedupe_key,''),coalesce(expires_at::text,'') FROM ciradar_objects WHERE ` + where
	if forUpdate {
		query += ` FOR UPDATE`
	}
	rows, err := c.QueryParams(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	out := make([]pgObject, 0, len(rows.Values))
	for _, row := range rows.Values {
		if len(row) < 12 || row[0] == nil || row[1] == nil || row[2] == nil || row[3] == nil {
			continue
		}
		payload, err := decodePGBase64(*row[3])
		if err != nil {
			return nil, err
		}
		value := func(i int) string {
			if row[i] == nil {
				return ""
			}
			return *row[i]
		}
		out = append(out, pgObject{Tenant: *row[0], Kind: *row[1], ID: *row[2], Payload: payload, EventTime: parsePGTime(value(4)), Repository: value(5), Organization: value(6), Fingerprint: value(7), State: value(8), Status: value(9), DedupeKey: value(10), ExpiresAt: parsePGTime(value(11))})
	}
	return out, nil
}

func pgObjectParams(object pgObject) []any {
	return []any{
		object.Tenant, object.Kind, object.ID, string(object.Payload), nullableTimeParam(object.EventTime),
		nullableTextParam(object.Repository), nullableTextParam(object.Organization), nullableTextParam(object.Fingerprint),
		nullableTextParam(object.State), nullableTextParam(object.Status), nullableTextParam(object.DedupeKey), nullableTimeParam(object.ExpiresAt),
	}
}

func insertPGObjectIfMissing(ctx context.Context, c *pgwire.Client, object pgObject) error {
	query := `INSERT INTO ciradar_objects(tenant_id,kind,object_id,payload,event_time,repository,organization,fingerprint,state,status,dedupe_key,expires_at,updated_at) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,now()) ON CONFLICT (tenant_id,kind,object_id) DO NOTHING`
	return c.ExecParams(ctx, query, pgObjectParams(object)...)
}

func upsertPGObject(ctx context.Context, c *pgwire.Client, object pgObject) error {
	query := `INSERT INTO ciradar_objects(tenant_id,kind,object_id,payload,event_time,repository,organization,fingerprint,state,status,dedupe_key,expires_at,updated_at) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,now()) ON CONFLICT (tenant_id,kind,object_id) DO UPDATE SET payload=excluded.payload,event_time=excluded.event_time,repository=excluded.repository,organization=excluded.organization,fingerprint=excluded.fingerprint,state=excluded.state,status=excluded.status,dedupe_key=excluded.dedupe_key,expires_at=excluded.expires_at,updated_at=now()`
	return c.ExecParams(ctx, query, pgObjectParams(object)...)
}

func hydrateStore(objects []pgObject) (*Store, error) {
	s, err := newMemoryStore(nil)
	if err != nil {
		return nil, err
	}
	for _, object := range objects {
		switch object.Kind {
		case pgKindAnalysis:
			var value analysisRecord
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.Analyses[object.ID] = value
			}
		case pgKindEnvironment:
			var value environmentRecord
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.Environments = append(s.state.Environments, value)
			}
		case pgKindIncident:
			var value model.Incident
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.Incidents[incidentKey(value.TenantID, value.Fingerprint)] = value
			}
		case pgKindProvider:
			var value model.ProviderStatus
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.ProviderStatuses[value.Provider] = value
			}
		case pgKindNotification:
			var value model.NotificationDelivery
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.NotificationDeliveries[value.ID] = value
			}
		case pgKindTenant:
			var value model.Tenant
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.Tenants[value.ID] = value
			}
		case pgKindAPIKey:
			var value apiKeyRecord
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.APIKeys[object.ID] = value
			}
		case pgKindAudit:
			var value model.AuditEvent
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.AuditEvents[object.ID] = value
			}
		case pgKindInstallation:
			var value string
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.InstallationTenants[object.ID] = value
			}
		case pgKindProfile:
			var value model.RepositoryProfile
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.RepositoryProfiles[profileKey(value.TenantID, value.Repository)] = value
			}
		case pgKindFeedback:
			var value model.DiagnosisFeedback
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.DiagnosisFeedback[object.ID] = value
			}
		case pgKindObservation:
			var value model.TestObservation
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.TestObservations[object.ID] = value
			}
		case pgKindTestStats:
			var value model.TestCaseStats
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.TestCaseStats[testStatsKey(value.TenantID, value.TestKey)] = value
			}
		case pgKindQuarantine:
			var value model.TestQuarantine
			if json.Unmarshal(object.Payload, &value) == nil {
				s.state.TestQuarantines[quarantineKey(value.TenantID, value.TestKey)] = value
			}
		}
	}
	rebuildStateOrders(&s.state)
	return s, nil
}

func rebuildStateOrders(st *state) {
	st.AnalysisOrder = st.AnalysisOrder[:0]
	for id := range st.Analyses {
		st.AnalysisOrder = append(st.AnalysisOrder, id)
	}
	sort.Slice(st.AnalysisOrder, func(i, j int) bool {
		return st.Analyses[st.AnalysisOrder[i]].Result.CreatedAt.Before(st.Analyses[st.AnalysisOrder[j]].Result.CreatedAt)
	})
	st.NotificationOrder = st.NotificationOrder[:0]
	for id := range st.NotificationDeliveries {
		st.NotificationOrder = append(st.NotificationOrder, id)
	}
	sort.Slice(st.NotificationOrder, func(i, j int) bool {
		return st.NotificationDeliveries[st.NotificationOrder[i]].UpdatedAt.Before(st.NotificationDeliveries[st.NotificationOrder[j]].UpdatedAt)
	})
	st.AuditOrder = st.AuditOrder[:0]
	for id := range st.AuditEvents {
		st.AuditOrder = append(st.AuditOrder, id)
	}
	sort.Slice(st.AuditOrder, func(i, j int) bool {
		return st.AuditEvents[st.AuditOrder[i]].CreatedAt.Before(st.AuditEvents[st.AuditOrder[j]].CreatedAt)
	})
	st.TestObservationOrder = st.TestObservationOrder[:0]
	for id := range st.TestObservations {
		st.TestObservationOrder = append(st.TestObservationOrder, id)
	}
	sort.Slice(st.TestObservationOrder, func(i, j int) bool {
		return st.TestObservations[st.TestObservationOrder[i]].OccurredAt.Before(st.TestObservations[st.TestObservationOrder[j]].OccurredAt)
	})
	sort.Slice(st.Environments, func(i, j int) bool { return st.Environments[i].CreatedAt.Before(st.Environments[j].CreatedAt) })
}

func stateObjects(st state) ([]pgObject, error) {
	out := make([]pgObject, 0, len(st.Analyses)+len(st.Incidents)+len(st.NotificationDeliveries))
	appendValue := func(tenant, kind, id string, value any, metadata pgObject) error {
		b, err := json.Marshal(value)
		if err != nil {
			return err
		}
		metadata.Tenant = tenant
		metadata.Kind = kind
		metadata.ID = id
		metadata.Payload = b
		out = append(out, metadata)
		return nil
	}
	for id, value := range st.Analyses {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindAnalysis, id, value, pgObject{EventTime: value.Result.CreatedAt, Repository: value.Result.Repository, Organization: value.Result.Organization, Fingerprint: value.Result.Fingerprint, State: string(value.Result.Attribution), Status: string(value.Result.Category)}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.Environments {
		id := environmentObjectID(value)
		if err := appendValue(normalizeTenant(value.TenantID), pgKindEnvironment, id, value, pgObject{EventTime: value.CreatedAt, Repository: value.Repository, Status: "successful"}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.Incidents {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindIncident, value.Fingerprint, value, pgObject{EventTime: value.LastSeenAt, Fingerprint: value.Fingerprint, State: value.State, Status: value.Severity}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.ProviderStatuses {
		if err := appendValue(pgSystemTenant, pgKindProvider, id, value, pgObject{EventTime: value.CheckedAt, Status: providerStatus(value)}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.NotificationDeliveries {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindNotification, id, value, pgObject{EventTime: value.UpdatedAt, Status: value.Status, DedupeKey: value.DedupeKey}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.Tenants {
		status := "disabled"
		if value.Enabled {
			status = "enabled"
		}
		if err := appendValue(pgSystemTenant, pgKindTenant, id, value, pgObject{EventTime: value.UpdatedAt, Status: status}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.APIKeys {
		status := "active"
		if !value.Key.RevokedAt.IsZero() {
			status = "revoked"
		}
		if err := appendValue(normalizeTenant(value.Key.TenantID), pgKindAPIKey, id, value, pgObject{EventTime: value.Key.CreatedAt, Fingerprint: value.Hash, Status: status}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.AuditEvents {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindAudit, id, value, pgObject{EventTime: value.CreatedAt, Status: value.Action}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.InstallationTenants {
		if err := appendValue(pgSystemTenant, pgKindInstallation, id, value, pgObject{}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.RepositoryProfiles {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindProfile, strings.ToLower(value.Repository), value, pgObject{EventTime: value.UpdatedAt, Repository: value.Repository, Status: value.Criticality}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.DiagnosisFeedback {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindFeedback, id, value, pgObject{EventTime: value.UpdatedAt, Status: value.Verdict}); err != nil {
			return nil, err
		}
	}
	for id, value := range st.TestObservations {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindObservation, id, value, pgObject{EventTime: value.OccurredAt, Repository: value.Repository, Status: value.Status}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.TestCaseStats {
		if err := appendValue(normalizeTenant(value.TenantID), pgKindTestStats, value.TestKey, value, pgObject{EventTime: value.LastSeenAt, Repository: value.Repository, Status: value.Classification}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.TestQuarantines {
		status := "inactive"
		if value.Active {
			status = "active"
		}
		if err := appendValue(normalizeTenant(value.TenantID), pgKindQuarantine, value.TestKey, value, pgObject{EventTime: value.CreatedAt, Status: status, ExpiresAt: value.ExpiresAt}); err != nil {
			return nil, err
		}
	}
	for _, value := range st.Extensions {
		if err := appendValue(normalizeTenant(value.TenantID), extensionKind(value.Kind), value.ID, value, pgObject{EventTime: value.UpdatedAt, Status: "active"}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func environmentObjectID(value environmentRecord) string {
	material := strings.Join([]string{value.TenantID, value.Repository, value.Workflow, value.Job, value.CommitSHA, value.CreatedAt.UTC().Format(time.RFC3339Nano)}, "\x00")
	h := sha256.Sum256([]byte(material))
	return hex.EncodeToString(h[:16])
}

func providerStatus(value model.ProviderStatus) string {
	if value.Incident {
		return "incident"
	}
	return "healthy"
}

type pgCall[T any] func(*Store) (T, error)

func pgStateWith[T any](ctx context.Context, p *PostgresBackend, write bool, specs []pgSpec, fn pgCall[T]) (out T, err error) {
	specs = normalizeSpecs(specs)
	c, err := p.connect(ctx)
	if err != nil {
		return out, err
	}
	defer p.release(c)
	if write {
		if err = c.Exec(ctx, "BEGIN"); err != nil {
			return out, err
		}
		defer func() {
			if err != nil {
				rollbackPostgres(c)
			}
		}()
		if err = lockSpecs(ctx, c, specs); err != nil {
			return out, err
		}
	}
	objects, err := loadPGObjects(ctx, c, specs, write)
	if err != nil {
		return out, err
	}
	store, err := hydrateStore(objects)
	if err != nil {
		return out, err
	}
	out, err = fn(store)
	if err != nil {
		return out, err
	}
	if write {
		current, err := stateObjects(store.state)
		if err != nil {
			return out, err
		}
		currentMap := map[string]pgObject{}
		for _, object := range current {
			if matchesSpec(specs, object) {
				currentMap[pgObjectKey(object.Tenant, object.Kind, object.ID)] = object
			}
		}
		existing := map[string]pgObject{}
		for _, object := range objects {
			existing[pgObjectKey(object.Tenant, object.Kind, object.ID)] = object
		}
		for key, object := range currentMap {
			old, ok := existing[key]
			if ok && string(old.Payload) == string(object.Payload) && old.EventTime.Equal(object.EventTime) && old.Repository == object.Repository && old.Organization == object.Organization && old.Fingerprint == object.Fingerprint && old.State == object.State && old.Status == object.Status && old.DedupeKey == object.DedupeKey && old.ExpiresAt.Equal(object.ExpiresAt) {
				delete(existing, key)
				continue
			}
			if err = upsertPGObject(ctx, c, object); err != nil {
				return out, err
			}
			delete(existing, key)
		}
		for _, object := range existing {
			if err = c.ExecParams(ctx, `DELETE FROM ciradar_objects WHERE tenant_id=$1 AND kind=$2 AND object_id=$3`, object.Tenant, object.Kind, object.ID); err != nil {
				return out, err
			}
		}
		if err = c.Exec(ctx, "COMMIT"); err != nil {
			return out, err
		}
	}
	return out, nil
}

func pgStateErr(ctx context.Context, p *PostgresBackend, write bool, specs []pgSpec, fn func(*Store) error) error {
	_, err := pgStateWith(ctx, p, write, specs, func(store *Store) (struct{}, error) {
		return struct{}{}, fn(store)
	})
	return err
}

func pgBool(raw *string) bool {
	if raw == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(*raw))
	return value == "t" || value == "true" || value == "1"
}

func requireRow(rows pgwire.Rows, columns int) ([]*string, error) {
	if len(rows.Values) != 1 || len(rows.Values[0]) < columns {
		return nil, errors.New("unexpected postgres result")
	}
	return rows.Values[0], nil
}
