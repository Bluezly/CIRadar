package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"ciradar/internal/model"
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
