package worker

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func thresholdTestWorker(t *testing.T) (*Worker, *db.Store) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.Default()
	cfg.IncidentRepoThreshold = 3
	cfg.IncidentOrgThreshold = 2
	cfg.Notifications.Enabled = false
	cfg.ProviderPolling = false
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, store, analyzer.New("test-key"), nil, nil, logger), store
}

func TestWorkerIncidentThresholdDoesNotDoubleCountFirstFailure(t *testing.T) {
	w, store := thresholdTestWorker(t)
	result := model.AnalysisResult{
		Fingerprint: "worker-first-failure",
		Provider:    "npm",
		ErrorFamily: "network",
		Summary:     "first isolated failure",
	}
	incident, created, err := w.maybeCreateIncident(
		context.Background(),
		"default",
		"acme/api",
		result,
		db.CorrelationStats{Repositories: 1, Organizations: 1, Occurrences: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if incident != nil || created {
		t.Fatalf("worker opened an incident for the first isolated failure: incident=%+v created=%v", incident, created)
	}
	stored, err := store.GetIncidentForTenant(context.Background(), "default", result.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Fatalf("unexpected stored incident: %+v", stored)
	}
}

func TestWorkerIncidentUsesExactCorrelationCountsAtThreshold(t *testing.T) {
	w, _ := thresholdTestWorker(t)
	w.cfg.IncidentRepoThreshold = 2
	w.cfg.IncidentOrgThreshold = 99
	result := model.AnalysisResult{
		Fingerprint: "worker-exact-threshold",
		Provider:    "npm",
		ErrorFamily: "network",
		Summary:     "failure reached repository threshold",
	}
	incident, created, err := w.maybeCreateIncident(
		context.Background(),
		"default",
		"acme/api",
		result,
		db.CorrelationStats{Repositories: 2, Organizations: 1, Occurrences: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	if incident == nil || !created {
		t.Fatalf("expected a newly opened incident, got incident=%+v created=%v", incident, created)
	}
	if incident.RepositoryCount != 2 || incident.OrganizationCount != 1 || incident.OccurrenceCount != 2 {
		t.Fatalf("worker changed correlation counts: %+v", incident)
	}
}
