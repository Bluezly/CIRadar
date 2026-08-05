package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/pgwire"
)

const pgSystemTenant = "__system__"

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

func sqlLiteral(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func sqlTime(value time.Time) string {
	if value.IsZero() {
		return "NULL"
	}
	return sqlLiteral(value.UTC().Format(time.RFC3339Nano)) + "::timestamptz"
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

func specWhere(specs []pgSpec) string {
	parts := make([]string, 0, len(specs))
	for _, spec := range specs {
		if spec.All {
			parts = append(parts, "kind="+sqlLiteral(spec.Kind))
		} else {
			part := "(tenant_id=" + sqlLiteral(spec.Tenant) + " AND kind=" + sqlLiteral(spec.Kind)
			if spec.ObjectID != "" {
				part += " AND object_id=" + sqlLiteral(spec.ObjectID)
			}
			parts = append(parts, part+")")
		}
	}
	if len(parts) == 0 {
		return "FALSE"
	}
	return strings.Join(parts, " OR ")
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
	statements := []string{
		`CREATE TABLE IF NOT EXISTS ciradar_schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS ciradar_objects (tenant_id text NOT NULL, kind text NOT NULL, object_id text NOT NULL, payload jsonb NOT NULL, event_time timestamptz, repository text, organization text, fingerprint text, state text, status text, dedupe_key text, expires_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,kind,object_id))`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_tenant_kind_time_idx ON ciradar_objects (tenant_id,kind,event_time DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_fingerprint_time_idx ON ciradar_objects (kind,fingerprint,event_time DESC) WHERE fingerprint IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_repository_time_idx ON ciradar_objects (tenant_id,repository,event_time DESC) WHERE repository IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_status_time_idx ON ciradar_objects (tenant_id,kind,status,event_time DESC)`,
		`CREATE INDEX IF NOT EXISTS ciradar_objects_dedupe_idx ON ciradar_objects (tenant_id,kind,dedupe_key,event_time DESC) WHERE dedupe_key IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS ciradar_jobs (id bigserial PRIMARY KEY, tenant_id text NOT NULL, type text NOT NULL, payload jsonb NOT NULL, status text NOT NULL, attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL, locked_at timestamptz, locked_by text, last_error text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE INDEX IF NOT EXISTS ciradar_jobs_claim_idx ON ciradar_jobs (status,available_at,id)`,
		`CREATE INDEX IF NOT EXISTS ciradar_jobs_tenant_idx ON ciradar_jobs (tenant_id,status,available_at)`,
		`CREATE TABLE IF NOT EXISTS ciradar_webhook_deliveries (id text PRIMARY KEY, event_type text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL, error text NOT NULL DEFAULT '')`,
	}
	for _, statement := range statements {
		if err := c.Exec(ctx, statement); err != nil {
			return err
		}
	}
	if err := p.migrateLegacyState(ctx, c); err != nil {
		return err
	}
	defaultTenant := model.Tenant{ID: model.DefaultTenantID, Name: "Default", Enabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	b, _ := json.Marshal(defaultTenant)
	object := pgObject{Tenant: pgSystemTenant, Kind: pgKindTenant, ID: defaultTenant.ID, Payload: b, EventTime: defaultTenant.UpdatedAt, Status: "enabled"}
	if err := insertPGObjectIfMissing(ctx, c, object); err != nil {
		return err
	}
	return c.Exec(ctx, `INSERT INTO ciradar_schema_migrations(version) VALUES (3) ON CONFLICT (version) DO NOTHING`)
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
			_ = c.Exec(context.Background(), "ROLLBACK")
		}
	}()
	for _, object := range objects {
		if err = upsertPGObject(ctx, c, object); err != nil {
			return err
		}
	}
	for _, job := range store.state.Jobs {
		query := `INSERT INTO ciradar_jobs(id,tenant_id,type,payload,status,attempts,available_at,locked_at,locked_by,last_error,created_at,updated_at) VALUES (` + strconv.FormatInt(job.ID, 10) + `,` + sqlLiteral(normalizeTenant(job.TenantID)) + `,` + sqlLiteral(job.Type) + `,` + jsonExpr(job.Payload) + `,` + sqlLiteral(job.Status) + `,` + strconv.Itoa(job.Attempts) + `,` + sqlTime(job.AvailableAt) + `,` + sqlTime(job.LockedAt) + `,` + nullableText(job.LockedBy) + `,` + nullableText(job.LastError) + `,` + sqlTime(job.CreatedAt) + `,` + sqlTime(job.UpdatedAt) + `) ON CONFLICT (id) DO NOTHING`
		if err = c.Exec(ctx, query); err != nil {
			return err
		}
	}
	for id, delivery := range store.state.Deliveries {
		query := `INSERT INTO ciradar_webhook_deliveries(id,event_type,received_at,status,error) VALUES (` + sqlLiteral(id) + `,` + sqlLiteral(delivery.EventType) + `,` + sqlTime(delivery.ReceivedAt) + `,` + sqlLiteral(delivery.Status) + `,` + sqlLiteral(delivery.Error) + `) ON CONFLICT (id) DO NOTHING`
		if err = c.Exec(ctx, query); err != nil {
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

func lockSpecs(ctx context.Context, c *pgwire.Client, specs []pgSpec) error {
	for _, spec := range specs {
		globalKey := "ciradar:" + spec.Kind + ":*"
		if spec.All {
			if err := c.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(`+sqlLiteral(globalKey)+`))`); err != nil {
				return err
			}
			continue
		}
		if err := c.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtext(`+sqlLiteral(globalKey)+`))`); err != nil {
			return err
		}
		lockKey := "ciradar:" + spec.Kind + ":" + spec.Tenant
		if spec.ObjectID != "" {
			lockKey += ":" + spec.ObjectID
		}
		if err := c.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(`+sqlLiteral(lockKey)+`))`); err != nil {
			return err
		}
	}
	return nil
}

func loadPGObjects(ctx context.Context, c *pgwire.Client, specs []pgSpec, forUpdate bool) ([]pgObject, error) {
	query := `SELECT tenant_id,kind,object_id,encode(convert_to(payload::text,'UTF8'),'base64'),coalesce(event_time::text,''),coalesce(repository,''),coalesce(organization,''),coalesce(fingerprint,''),coalesce(state,''),coalesce(status,''),coalesce(dedupe_key,''),coalesce(expires_at::text,'') FROM ciradar_objects WHERE ` + specWhere(specs)
	if forUpdate {
		query += ` FOR UPDATE`
	}
	rows, err := c.Query(ctx, query)
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

func insertPGObjectIfMissing(ctx context.Context, c *pgwire.Client, object pgObject) error {
	query := `INSERT INTO ciradar_objects(tenant_id,kind,object_id,payload,event_time,repository,organization,fingerprint,state,status,dedupe_key,expires_at,updated_at) VALUES (` +
		sqlLiteral(object.Tenant) + `,` + sqlLiteral(object.Kind) + `,` + sqlLiteral(object.ID) + `,` + jsonExpr(object.Payload) + `,` + sqlTime(object.EventTime) + `,` + nullableText(object.Repository) + `,` + nullableText(object.Organization) + `,` + nullableText(object.Fingerprint) + `,` + nullableText(object.State) + `,` + nullableText(object.Status) + `,` + nullableText(object.DedupeKey) + `,` + sqlTime(object.ExpiresAt) + `,now()) ON CONFLICT (tenant_id,kind,object_id) DO NOTHING`
	return c.Exec(ctx, query)
}

func upsertPGObject(ctx context.Context, c *pgwire.Client, object pgObject) error {
	query := `INSERT INTO ciradar_objects(tenant_id,kind,object_id,payload,event_time,repository,organization,fingerprint,state,status,dedupe_key,expires_at,updated_at) VALUES (` +
		sqlLiteral(object.Tenant) + `,` + sqlLiteral(object.Kind) + `,` + sqlLiteral(object.ID) + `,` + jsonExpr(object.Payload) + `,` + sqlTime(object.EventTime) + `,` + nullableText(object.Repository) + `,` + nullableText(object.Organization) + `,` + nullableText(object.Fingerprint) + `,` + nullableText(object.State) + `,` + nullableText(object.Status) + `,` + nullableText(object.DedupeKey) + `,` + sqlTime(object.ExpiresAt) + `,now()) ON CONFLICT (tenant_id,kind,object_id) DO UPDATE SET payload=excluded.payload,event_time=excluded.event_time,repository=excluded.repository,organization=excluded.organization,fingerprint=excluded.fingerprint,state=excluded.state,status=excluded.status,dedupe_key=excluded.dedupe_key,expires_at=excluded.expires_at,updated_at=now()`
	return c.Exec(ctx, query)
}

func nullableText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NULL"
	}
	return sqlLiteral(value)
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
	c, err := pgwire.Connect(ctx, p.dsn)
	if err != nil {
		return out, err
	}
	defer c.Close()
	if write {
		if err = c.Exec(ctx, "BEGIN"); err != nil {
			return out, err
		}
		defer func() {
			if err != nil {
				_ = c.Exec(context.Background(), "ROLLBACK")
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
			if err = c.Exec(ctx, `DELETE FROM ciradar_objects WHERE tenant_id=`+sqlLiteral(object.Tenant)+` AND kind=`+sqlLiteral(object.Kind)+` AND object_id=`+sqlLiteral(object.ID)); err != nil {
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
