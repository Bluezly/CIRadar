package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestPostgresIntegrationObservationLifecycle(t *testing.T) {
	dsn := os.Getenv("CIRADAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CIRADAR_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	backend, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres backend: %v", err)
	}
	defer backend.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	tenantID := fmt.Sprintf("integration-%d", now.UnixNano())
	base := model.TestObservation{
		TenantID:   tenantID,
		Repository: "acme/integration",
		Workflow:   "ci",
		Job:        "unit",
		RunID:      now.UnixNano(),
		CommitSHA:  "0123456789abcdef",
		Branch:     "main",
		Framework:  "junit",
		Suite:      "postgres",
		Name:       "observation lifecycle",
		DurationMS: 1400,
		OccurredAt: now,
	}
	failed := base
	failed.ID = "failed-" + tenantID
	failed.Status = "failed"
	passed := base
	passed.ID = "passed-" + tenantID
	passed.Status = "passed"
	passed.OccurredAt = now.Add(time.Second)

	stats, err := backend.RecordTestObservations(ctx, tenantID, []model.TestObservation{failed, passed})
	if err != nil {
		t.Fatalf("record observations: %v", err)
	}
	if len(stats) != 1 || stats[0].TotalRuns != 2 || stats[0].Failures != 1 || stats[0].Passes != 1 {
		t.Fatalf("unexpected stats after ingest: %+v", stats)
	}
	if stats[0].RerunRecoveries != 1 {
		t.Fatalf("expected same-commit rerun recovery, got %+v", stats[0])
	}

	replayed, err := backend.RecordTestObservations(ctx, tenantID, []model.TestObservation{failed, passed})
	if err != nil {
		t.Fatalf("replay observations: %v", err)
	}
	if len(replayed) != 0 {
		t.Fatalf("duplicate observations unexpectedly changed stats: %+v", replayed)
	}
	listed, err := backend.ListTestCaseStats(ctx, tenantID, "acme/integration", "", 10)
	if err != nil {
		t.Fatalf("list stats: %v", err)
	}
	if len(listed) != 1 || listed[0].TotalRuns != 2 {
		t.Fatalf("idempotency failed, listed stats=%+v", listed)
	}

	dashboard, err := backend.Dashboard(ctx, tenantID, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	day := now.Format("2006-01-02")
	if dashboard.DailyTestFailures[day] != 1 {
		t.Fatalf("native telemetry query missing failure: day=%s dashboard=%+v", day, dashboard.DailyTestFailures)
	}
}

func TestPostgresIntegrationParameterizedValues(t *testing.T) {
	dsn := os.Getenv("CIRADAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CIRADAR_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	backend, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres backend: %v", err)
	}
	defer backend.Close()

	tenant := "probe-' OR '1'='1"
	kind := "sql-probe'; drop table ciradar_objects;--"
	id := "id-'); DELETE FROM ciradar_objects;--"
	want := map[string]string{"value": "quote ' newline\n backslash \\ dollar $1 semicolon ;"}
	if err := backend.PutObject(ctx, tenant, kind, id, want); err != nil {
		t.Fatalf("put hostile parameter values: %v", err)
	}
	var got map[string]string
	found, err := backend.GetObject(ctx, tenant, kind, id, &got)
	if err != nil {
		t.Fatalf("get hostile parameter values: %v", err)
	}
	if !found || got["value"] != want["value"] {
		t.Fatalf("parameter round trip failed: found=%v got=%#v", found, got)
	}
	report, err := backend.Health(ctx)
	if err != nil {
		t.Fatalf("postgres health after hostile values: %v", err)
	}
	if report.SchemaVersion != postgresSchemaVersion {
		t.Fatalf("schema version=%d want=%d", report.SchemaVersion, postgresSchemaVersion)
	}
}

func TestPostgresIntegrationDistributedSecurityState(t *testing.T) {
	dsn := os.Getenv("CIRADAR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CIRADAR_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	first, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open first postgres backend: %v", err)
	}
	defer first.Close()
	second, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open second postgres backend: %v", err)
	}
	defer second.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	allowed, _, err := first.TakeRateLimit(ctx, "integration", "rate-"+suffix, 1, time.Minute, time.Now())
	if err != nil || !allowed {
		t.Fatalf("first distributed rate-limit take: allowed=%v err=%v", allowed, err)
	}
	allowed, retry, err := second.TakeRateLimit(ctx, "integration", "rate-"+suffix, 1, time.Minute, time.Now())
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("second distributed rate-limit take: allowed=%v retry=%s err=%v", allowed, retry, err)
	}

	key := "auth-" + suffix
	if delay, err := first.RecordAuthFailure(ctx, key, 2, time.Minute, 5*time.Second, time.Minute, time.Now()); err != nil || delay != 0 {
		t.Fatalf("first auth failure: delay=%s err=%v", delay, err)
	}
	if delay, err := second.RecordAuthFailure(ctx, key, 2, time.Minute, 5*time.Second, time.Minute, time.Now()); err != nil || delay < 5*time.Second {
		t.Fatalf("second auth failure: delay=%s err=%v", delay, err)
	}
	if retry, err := first.AuthFailureRetryAfter(ctx, key, time.Now()); err != nil || retry <= 0 {
		t.Fatalf("shared auth block missing: retry=%s err=%v", retry, err)
	}

	replayKey := "replay-" + suffix
	expires := time.Now().UTC().Add(5 * time.Minute)
	if claimed, err := first.ClaimSSOReplay(ctx, replayKey, expires); err != nil || !claimed {
		t.Fatalf("first replay claim: claimed=%v err=%v", claimed, err)
	}
	if claimed, err := second.ClaimSSOReplay(ctx, replayKey, expires); err != nil || claimed {
		t.Fatalf("duplicate replay claim: claimed=%v err=%v", claimed, err)
	}
}
