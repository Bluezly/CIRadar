package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestPersistenceAndCorrelation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	in := model.AnalysisInput{Repository: "acme/api", Organization: "acme", Workflow: "ci", Job: "test", Log: "SECRET RAW LOG"}
	r := model.AnalysisResult{ID: "a1", Fingerprint: "fp", Category: model.CategoryNetworkFailure, Confidence: model.ConfidenceModerate, CreatedAt: time.Now().UTC(), Environment: model.Environment{ToolVersions: map[string]string{}}}
	if err := s.RecordAnalysis(context.Background(), in, r, true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.state.Analyses["a1"].Input.Log; got != "" {
		t.Fatalf("raw log persisted unexpectedly: %q", got)
	}
	st, err := s2.Correlation(context.Background(), "fp", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.Repositories != 1 || st.Organizations != 1 || st.Occurrences != 1 {
		t.Fatalf("stats=%+v", st)
	}
}

func TestTenantCorrelationIsolationAndOptionalSharing(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateTenant(context.Background(), "a", "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTenant(context.Background(), "b", "B"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, tc := range []struct{ tenant, repo, org, id string }{{"a", "a/api", "a", "a1"}, {"b", "b/api", "b", "b1"}} {
		in := model.AnalysisInput{TenantID: tc.tenant, Repository: tc.repo, Organization: tc.org, OccurredAt: now}
		r := model.AnalysisResult{ID: tc.id, TenantID: tc.tenant, Fingerprint: "shared", CreatedAt: now}
		if err := s.RecordAnalysisForTenant(context.Background(), tc.tenant, in, r, false, false); err != nil {
			t.Fatal(err)
		}
	}
	isolated, err := s.CorrelationForTenant(context.Background(), "a", "shared", "a/api", "a", now.Add(-time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if isolated.Occurrences != 2 || isolated.Repositories != 1 || isolated.Organizations != 1 {
		t.Fatalf("isolated=%+v", isolated)
	}
	shared, err := s.CorrelationForTenant(context.Background(), "a", "shared", "a/api", "a", now.Add(-time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if shared.Occurrences != 3 || shared.Repositories != 2 || shared.Organizations != 2 {
		t.Fatalf("shared=%+v", shared)
	}
}

func TestAPIKeyStoredHashedAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key, token, err := s.CreateAPIKey(context.Background(), model.DefaultTenantID, "viewer", model.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), token) {
		t.Fatal("plaintext API token persisted")
	}
	p, err := s.AuthenticateAPIKey(context.Background(), token)
	if err != nil || p == nil || p.Role != model.RoleViewer {
		t.Fatalf("principal=%+v err=%v", p, err)
	}
	if err := s.RevokeAPIKey(context.Background(), model.DefaultTenantID, key.ID); err != nil {
		t.Fatal(err)
	}
	p, _ = s.AuthenticateAPIKey(context.Background(), token)
	if p != nil {
		t.Fatal("revoked key authenticated")
	}
	_ = s.Close()
}

func TestNotificationRetryDoesNotSuppressItself(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	decision, d, err := s.BeginNotificationDeliveryForTenant(ctx, "default", "evt", "slack", "slack", "fp", 15*time.Minute, 3)
	if err != nil || decision != "send" {
		t.Fatalf("first=%s %+v %v", decision, d, err)
	}
	d.Status = "retrying"
	d.LastError = "temporary"
	if err := s.RecordNotificationDelivery(ctx, d); err != nil {
		t.Fatal(err)
	}
	decision, d, err = s.BeginNotificationDeliveryForTenant(ctx, "default", "evt", "slack", "slack", "fp", 15*time.Minute, 3)
	if err != nil || decision != "send" || d.Attempts != 2 {
		t.Fatalf("retry=%s %+v %v", decision, d, err)
	}
}

func TestQueuedJobsAreTenantIsolated(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTenant(context.Background(), "beta", "Beta"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueForTenant(context.Background(), "alpha", "test", map[string]string{"x": "a"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueForTenant(context.Background(), "beta", "test", map[string]string{"x": "b"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	a, _ := s.StatsForTenant(context.Background(), "alpha")
	b, _ := s.StatsForTenant(context.Background(), "beta")
	if a.QueuedJobs != 1 || b.QueuedJobs != 1 {
		t.Fatalf("alpha=%+v beta=%+v", a, b)
	}
	job, err := s.ClaimJob(context.Background(), "worker")
	if err != nil || job == nil || job.TenantID == "" {
		t.Fatalf("job=%+v err=%v", job, err)
	}
}

func TestCleanupPrunesAuditAndNotificationHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := time.Now().UTC().Add(-48 * time.Hour)
	s.mu.Lock()
	s.state.AuditEvents["old"] = model.AuditEvent{ID: "old", TenantID: "default", CreatedAt: old}
	s.state.AuditOrder = append(s.state.AuditOrder, "old")
	s.state.NotificationDeliveries["default|e|c"] = model.NotificationDelivery{ID: "default|e|c", TenantID: "default", EventID: "e", Channel: "c", CreatedAt: old, UpdatedAt: old}
	s.state.NotificationOrder = append(s.state.NotificationOrder, "default|e|c")
	_ = s.persistLocked()
	s.mu.Unlock()
	if err := s.Cleanup(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if len(s.state.AuditEvents) != 0 || len(s.state.NotificationDeliveries) != 0 {
		t.Fatalf("audit=%d notifications=%d", len(s.state.AuditEvents), len(s.state.NotificationDeliveries))
	}
}

func TestTenantAndRepositoryProfileValidation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateTenant(context.Background(), "Bad Tenant!", "Bad"); err == nil {
		t.Fatal("invalid tenant id accepted")
	}
	if _, err := s.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: "alpha", Repository: "missing-slash"}); err == nil {
		t.Fatal("invalid repository accepted")
	}
	if _, err := s.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: "alpha", Repository: "acme/api", Criticality: "nuclear"}); err == nil {
		t.Fatal("invalid criticality accepted")
	}
	p, err := s.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: "alpha", Repository: "acme/api", Criticality: "HIGH", NotificationChannels: []string{"slack", " slack ", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Criticality != "high" || len(p.NotificationChannels) != 1 || p.NotificationChannels[0] != "slack" {
		t.Fatalf("profile not normalized: %+v", p)
	}
}

func TestDisabledTenantJobsAreNotClaimed(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueForTenant(context.Background(), "alpha", "test", map[string]string{"x": "a"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenantEnabled(context.Background(), "alpha", false); err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimJob(context.Background(), "worker")
	if err != nil {
		t.Fatal(err)
	}
	if job != nil {
		t.Fatalf("disabled tenant job was claimed: %+v", job)
	}
	if err := s.EnqueueForTenant(context.Background(), "alpha", "test", nil, time.Now()); err == nil {
		t.Fatal("enqueue for disabled tenant succeeded")
	}
}

func TestCannotDisableLastEnabledTenant(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetTenantEnabled(context.Background(), model.DefaultTenantID, false); err == nil {
		t.Fatal("last enabled tenant was disabled")
	}
	if _, err := s.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenantEnabled(context.Background(), "alpha", false); err != nil {
		t.Fatal(err)
	}
}

func TestInstallationBindRequiresEnabledTenantAndCanUnbind(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTenantEnabled(context.Background(), "alpha", false); err != nil {
		t.Fatal(err)
	}
	if err := s.BindInstallation(context.Background(), "alpha", 77); err == nil {
		t.Fatal("bound installation to disabled tenant")
	}
	if err := s.SetTenantEnabled(context.Background(), "alpha", true); err != nil {
		t.Fatal(err)
	}
	if err := s.BindInstallation(context.Background(), "alpha", 77); err != nil {
		t.Fatal(err)
	}
	if err := s.UnbindInstallation(context.Background(), 77); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveInstallationTenant(context.Background(), 77); ok {
		t.Fatal("installation remains bound")
	}
}

func TestDashboardDailyTrends(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	input := model.AnalysisInput{TenantID: "default", Repository: "acme/api", Organization: "acme", OccurredAt: now}
	result := model.AnalysisResult{ID: "trend-analysis", TenantID: "default", Repository: "acme/api", Fingerprint: "trend-fp", Category: model.CategoryNetworkFailure, Attribution: model.AttributionExternal, CreatedAt: now}
	if err := store.RecordAnalysisForTenant(ctx, "default", input, result, false, false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIncidentForTenant(ctx, "default", model.Incident{ID: "trend-incident", TenantID: "default", Fingerprint: "trend-fp", State: "open", Severity: "major", FirstSeenAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{{ID: "trend-test", TenantID: "default", Repository: "acme/api", Framework: "junit", Name: "fails", Status: "failed", OccurredAt: now}}); err != nil {
		t.Fatal(err)
	}
	dashboard, err := store.Dashboard(ctx, "default", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	day := now.Format("2006-01-02")
	if dashboard.DailyAnalyses[day] != 1 || dashboard.DailyIncidents[day] != 1 || dashboard.DailyTestFailures[day] != 1 {
		t.Fatalf("analyses=%v incidents=%v tests=%v", dashboard.DailyAnalyses, dashboard.DailyIncidents, dashboard.DailyTestFailures)
	}
}

func TestCorrelationCandidateDoesNotInventNewRepositoryOrOrganization(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	in := model.AnalysisInput{TenantID: "default", Repository: "local/test", Organization: "local", OccurredAt: now}
	result := model.AnalysisResult{ID: "one", TenantID: "default", Fingerprint: "same", CreatedAt: now}
	if err := s.RecordAnalysisForTenant(context.Background(), "default", in, result, false, false); err != nil {
		t.Fatal(err)
	}
	stats, err := s.CorrelationForTenant(context.Background(), "default", "same", "local/test", "local", now.Add(-time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Repositories != 1 || stats.Organizations != 1 || stats.Occurrences != 2 {
		t.Fatalf("stats=%+v", stats)
	}
	other, err := s.CorrelationForTenant(context.Background(), "default", "same", "other/repo", "other", now.Add(-time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if other.Repositories != 2 || other.Organizations != 2 || other.Occurrences != 2 {
		t.Fatalf("other=%+v", other)
	}
}

func TestCloseCanBeRetriedAfterPersistenceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	originalPath := store.path
	blockingFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blockingFile, "state.json")
	if err := store.Close(); err == nil {
		t.Fatal("Close unexpectedly succeeded with an invalid persistence path")
	}
	if store.closed {
		t.Fatal("store was marked closed after persistence failed")
	}
	store.path = originalPath
	if err := store.Close(); err != nil {
		t.Fatalf("retry Close failed: %v", err)
	}
	if !store.closed {
		t.Fatal("store was not marked closed after successful retry")
	}
}

func TestReplaceFileWithRollbackPreservesOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingTemp := filepath.Join(dir, "missing.tmp")
	if err := replaceFileWithRollback(missingTemp, target); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "old" {
		t.Fatalf("target=%q err=%v", string(body), err)
	}
	if _, err := os.Stat(target + ".replace-old"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback file remains: %v", err)
	}
}

func TestReplaceFileWithRollbackInstallsNewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	temp := filepath.Join(dir, "state.tmp")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileWithRollback(temp, target); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "new" {
		t.Fatalf("target=%q err=%v", string(body), err)
	}
}

func TestFlakeClassificationUsesColdStartConfidence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	statuses := []string{"passed", "failed", "passed", "failed", "passed"}
	var latest []model.TestCaseStats
	for i, status := range statuses {
		latest, err = store.RecordTestObservations(ctx, "default", []model.TestObservation{{
			Repository: "acme/api", Framework: "go", Name: "TestSometimes", Status: status,
			CommitSHA: "abc123", RunID: int64(i + 1), DurationMS: 1000, OccurredAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(latest) != 1 {
		t.Fatalf("stats=%#v", latest)
	}
	st := latest[0]
	if st.Classification != "suspected_flaky" || !st.ColdStart || st.HistoryConfidence >= .55 {
		t.Fatalf("stats=%#v", st)
	}
	if st.Classification == "flaky" {
		t.Fatal("cold-start test must not be promoted to confirmed flaky")
	}
}

func TestFlakeStatsTrackSameCommitRecoveryAndLostTime(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	base := model.TestObservation{Repository: "acme/api", Framework: "go", Name: "TestRetry", CommitSHA: "same", DurationMS: 60000, OccurredAt: time.Now().UTC()}
	failed := base
	failed.Status = "failed"
	passed := base
	passed.Status = "passed"
	passed.OccurredAt = passed.OccurredAt.Add(time.Minute)
	latest, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{failed, passed})
	if err != nil {
		t.Fatal(err)
	}
	st := latest[0]
	if st.RerunRecoveries != 1 || st.EstimatedComputeMinutesLost != 2 || st.EstimatedEngineeringMinutesLost != 7 {
		t.Fatalf("stats=%#v", st)
	}
	if st.FailureRateLow <= 0 || st.FailureRateHigh >= 1 || st.AverageDurationMS != 60000 {
		t.Fatalf("stats=%#v", st)
	}
}

func TestTestObservationReplayIsIdempotent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	observation := model.TestObservation{
		ID: "delivery-result-1", Repository: "acme/api", Framework: "go", Name: "TestIdempotent",
		Status: "failed", RunID: 42, CommitSHA: "abc", DurationMS: 2000, OccurredAt: time.Now().UTC(),
	}
	first, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{observation})
	if err != nil || len(first) != 1 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("replayed observation unexpectedly updated stats: %#v", second)
	}
	stats, err := store.ListTestCaseStats(ctx, "default", "acme/api", "", 10)
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if stats[0].TotalRuns != 1 || stats[0].ExecutedRuns != 1 || stats[0].Failures != 1 {
		t.Fatalf("replay inflated stats: %#v", stats[0])
	}
}

func TestSkippedObservationsDoNotIncreaseFlakeConfidence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	observations := []model.TestObservation{
		{ID: "skip-1", Repository: "acme/api", Framework: "go", Name: "TestOptional", Status: "skipped", OccurredAt: now},
		{ID: "skip-2", Repository: "acme/api", Framework: "go", Name: "TestOptional", Status: "skipped", OccurredAt: now.Add(time.Second)},
		{ID: "skip-3", Repository: "acme/api", Framework: "go", Name: "TestOptional", Status: "skipped", OccurredAt: now.Add(2 * time.Second)},
	}
	latest, err := store.RecordTestObservations(ctx, "default", observations)
	if err != nil || len(latest) != 1 {
		t.Fatalf("latest=%#v err=%v", latest, err)
	}
	st := latest[0]
	if st.TotalRuns != 3 || st.ExecutedRuns != 0 || st.Skipped != 3 {
		t.Fatalf("unexpected counts: %#v", st)
	}
	if st.HistoryConfidence != 0 || st.FailureRate != 0 || st.Classification != "not_executed" || !st.ColdStart {
		t.Fatalf("skips became flake evidence: %#v", st)
	}
}

func TestOutOfOrderObservationDoesNotReplaceLatestExecution(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	newer := model.TestObservation{ID: "newer", Repository: "acme/api", Framework: "go", Name: "TestOrdering", Status: "passed", RunID: 2, CommitSHA: "new", OccurredAt: now}
	older := model.TestObservation{ID: "older", Repository: "acme/api", Framework: "go", Name: "TestOrdering", Status: "failed", RunID: 1, CommitSHA: "old", OccurredAt: now.Add(-time.Hour)}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{newer}); err != nil {
		t.Fatal(err)
	}
	latest, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{older})
	if err != nil || len(latest) != 1 {
		t.Fatalf("latest=%#v err=%v", latest, err)
	}
	st := latest[0]
	if st.LastStatus != "passed" || st.LastRunID != 2 || st.LastCommitSHA != "new" || !st.LastSeenAt.Equal(now) {
		t.Fatalf("older event replaced latest state: %#v", st)
	}
	if st.Transitions != 0 || st.RerunRecoveries != 0 {
		t.Fatalf("out-of-order event created a false transition: %#v", st)
	}
}

func TestTestStatsTrackPullRequestImpactAndVariants(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	observations := []model.TestObservation{
		{ID: "pr-1", Repository: "acme/api", Framework: "go", Name: "TestCheckout", Variant: "linux-go1.24", Status: "failed", PullRequestNumber: 41, OccurredAt: now},
		{ID: "pr-2", Repository: "acme/api", Framework: "go", Name: "TestCheckout", Variant: "linux-go1.24", Status: "failed", PullRequestNumber: 41, OccurredAt: now.Add(time.Second)},
		{ID: "pr-3", Repository: "acme/api", Framework: "go", Name: "TestCheckout", Variant: "linux-go1.24", Status: "failed", PullRequestNumber: 52, OccurredAt: now.Add(2 * time.Second)},
	}
	stats, err := store.RecordTestObservations(ctx, "default", observations)
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if stats[0].PullRequestsImpacted != 2 || len(stats[0].ImpactedPullRequests) != 2 {
		t.Fatalf("PR impact=%#v", stats[0])
	}
	if stats[0].Variant != "linux-go1.24" {
		t.Fatalf("variant=%q", stats[0].Variant)
	}
	other := observations[0]
	other.Variant = "windows-go1.24"
	if TestKey(other) == TestKey(observations[0]) {
		t.Fatal("execution variants must have separate test identities")
	}
	withoutVariant := observations[0]
	withoutVariant.Variant = ""
	legacyMaterial := strings.Join([]string{"acme/api", "go", "", "", "TestCheckout", ""}, "\x00")
	digest := sha256.Sum256([]byte(legacyMaterial))
	if TestKey(withoutVariant) != hex.EncodeToString(digest[:16]) {
		t.Fatal("blank variant changed existing test keys")
	}
}

func TestTestHistoryCriticalFlagAndTenantIsolation(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	base := model.TestObservation{Repository: "acme/api", Framework: "go", Name: "TestPolicy"}
	first := base
	first.ID, first.Status, first.OccurredAt = "history-1", "failed", now
	second := base
	second.ID, second.Status, second.OccurredAt = "history-2", "passed", now.Add(time.Minute)
	if _, err := store.RecordTestObservations(ctx, "tenant-a", []model.TestObservation{first, second}); err != nil {
		t.Fatal(err)
	}
	foreign := base
	foreign.ID, foreign.Status, foreign.OccurredAt = "history-foreign", "failed", now.Add(2*time.Minute)
	if _, err := store.RecordTestObservations(ctx, "tenant-b", []model.TestObservation{foreign}); err != nil {
		t.Fatal(err)
	}
	key := TestKey(first)
	stats, err := store.SetTestCritical(ctx, "tenant-a", key, true)
	if err != nil || stats == nil || !stats.Critical {
		t.Fatalf("critical stats=%#v err=%v", stats, err)
	}
	loaded, err := store.GetTestCaseStats(ctx, "tenant-a", key)
	if err != nil || loaded == nil || !loaded.Critical {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	history, err := store.ListTestObservations(ctx, "tenant-a", key, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].ID != "history-2" || history[1].ID != "history-1" {
		t.Fatalf("history=%#v", history)
	}
}

func TestQuarantinedFailuresAreCountedOnlyDuringActiveWindow(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	seed := model.TestObservation{ID: "seed", Repository: "acme/api", Framework: "go", Name: "TestQuarantineCount", Status: "passed", OccurredAt: now}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{seed}); err != nil {
		t.Fatal(err)
	}
	key := TestKey(seed)
	q, err := store.SetTestQuarantine(ctx, model.TestQuarantine{TenantID: "default", TestKey: key, Owner: "platform", Reason: "investigation", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	failed := seed
	failed.ID, failed.Status, failed.OccurredAt = "during-quarantine", "failed", q.CreatedAt.Add(time.Second)
	stats, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{failed})
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if stats[0].QuarantinedFailures != 1 {
		t.Fatalf("quarantined failures=%d", stats[0].QuarantinedFailures)
	}
}

func TestStaleWorkerCannotCompleteReclaimedJob(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Enqueue(ctx, "test", map[string]string{"value": "x"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimJob(ctx, "worker-a")
	if err != nil || first == nil {
		t.Fatalf("first claim=%#v err=%v", first, err)
	}
	store.mu.Lock()
	for i := range store.state.Jobs {
		if store.state.Jobs[i].ID == first.ID {
			store.state.Jobs[i].LockedAt = time.Now().UTC().Add(-time.Hour)
		}
	}
	if err := store.persistLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	if err := store.RequeueStaleJobs(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimJob(ctx, "worker-b")
	if err != nil || second == nil {
		t.Fatalf("second claim=%#v err=%v", second, err)
	}
	if first.LeaseToken == second.LeaseToken {
		t.Fatal("reclaimed job reused its old lease")
	}
	if err := store.CompleteJob(ctx, first.ID, first.LeaseToken); !errors.Is(err, ErrJobLeaseLost) {
		t.Fatalf("stale worker completion error=%v", err)
	}
	if err := store.CompleteJob(ctx, second.ID, second.LeaseToken); err != nil {
		t.Fatalf("current worker completion failed: %v", err)
	}
}

func TestDeliveryAndJobAreEnqueuedAtomicallyAndIdempotently(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	fresh, err := store.EnqueueDeliveryForTenant(ctx, "delivery-1", "github", model.DefaultTenantID, "github.workflow_run", map[string]string{"run": "1"}, time.Now())
	if err != nil || !fresh {
		t.Fatalf("first enqueue fresh=%v err=%v", fresh, err)
	}
	fresh, err = store.EnqueueDeliveryForTenant(ctx, "delivery-1", "github", model.DefaultTenantID, "github.workflow_run", map[string]string{"run": "1"}, time.Now())
	if err != nil || fresh {
		t.Fatalf("duplicate enqueue fresh=%v err=%v", fresh, err)
	}
	stats, err := store.StatsForTenant(ctx, model.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.QueuedJobs != 1 {
		t.Fatalf("queued jobs=%d, want 1", stats.QueuedJobs)
	}
}

func TestErroredDeliveryCanBeRetried(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	claimed, err := store.ClaimDelivery(ctx, "marketplace-retry", "github.marketplace", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim=%v err=%v", claimed, err)
	}
	claimed, err = store.ClaimDelivery(ctx, "marketplace-retry", "github.marketplace", time.Minute)
	if err != nil || claimed {
		t.Fatalf("concurrent claim=%v err=%v", claimed, err)
	}
	if err := store.UpdateDelivery(ctx, "marketplace-retry", "error", "temporary"); err != nil {
		t.Fatal(err)
	}
	claimed, err = store.ClaimDelivery(ctx, "marketplace-retry", "github.marketplace", time.Minute)
	if err != nil || !claimed {
		t.Fatalf("retry claim=%v err=%v", claimed, err)
	}
}

func TestJobLeaseRenewalPreventsStaleRequeue(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Enqueue(ctx, "test", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	job, err := store.ClaimJob(ctx, "worker")
	if err != nil || job == nil {
		t.Fatalf("claim=%#v err=%v", job, err)
	}
	store.mu.Lock()
	for i := range store.state.Jobs {
		if store.state.Jobs[i].ID == job.ID {
			store.state.Jobs[i].LockedAt = time.Now().UTC().Add(-time.Hour)
		}
	}
	store.mu.Unlock()
	if err := store.RenewJobLease(ctx, job.ID, job.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if err := store.RequeueStaleJobs(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteJob(ctx, job.ID, job.LeaseToken); err != nil {
		t.Fatalf("renewed job was requeued: %v", err)
	}
}

func TestEmbeddedStoreRollsBackCriticalMutationsWhenPersistenceFails(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalPath := store.path
	badPath := filepath.Join(t.TempDir(), "state-directory")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	store.path = badPath
	ctx := context.Background()
	analysis := model.AnalysisResult{ID: "must-rollback", CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{Repository: "acme/api"}, analysis, false, false); err == nil {
		t.Fatal("analysis persistence failure was not reported")
	}
	if got, err := store.GetAnalysisForTenant(ctx, model.DefaultTenantID, analysis.ID); err != nil || got != nil {
		t.Fatalf("failed analysis remained in memory: got=%#v err=%v", got, err)
	}
	decision, _, err := store.BeginNotificationDeliveryForTenant(ctx, model.DefaultTenantID, "event", "slack", "slack", "dedupe", time.Minute, 3)
	if err == nil || decision != "" {
		t.Fatalf("notification persistence decision=%q err=%v", decision, err)
	}
	if delivery, err := store.GetNotificationDeliveryForTenant(ctx, model.DefaultTenantID, "event", "slack"); err != nil || delivery != nil {
		t.Fatalf("failed notification remained in memory: delivery=%#v err=%v", delivery, err)
	}
	store.path = originalPath
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRecoveryPreservesGoodBackupAndQuarantinesCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "recoverable", CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysis(context.Background(), model.AnalysisInput{Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	goodBackup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := recovered.GetAnalysis(context.Background(), "recoverable")
	if err != nil || loaded == nil {
		t.Fatalf("analysis was not recovered: loaded=%#v err=%v", loaded, err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt state was not quarantined: %v", err)
	}
	backupAfterRecovery, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if string(backupAfterRecovery) != string(goodBackup) {
		t.Fatal("successful recovery overwrote the known-good backup")
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken-again"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoveredAgain, err := Open(path)
	if err != nil {
		t.Fatalf("second recovery failed: %v", err)
	}
	defer recoveredAgain.Close()
	loaded, err = recoveredAgain.GetAnalysis(context.Background(), "recoverable")
	if err != nil || loaded == nil {
		t.Fatalf("backup was not reusable: loaded=%#v err=%v", loaded, err)
	}
}

func TestMissingMainStateRecoversFromBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "backup-only", CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysis(context.Background(), model.AnalysisInput{Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	loaded, err := recovered.GetAnalysis(context.Background(), "backup-only")
	if err != nil || loaded == nil {
		t.Fatalf("backup-only recovery failed: loaded=%#v err=%v", loaded, err)
	}
}

func TestEmptyMainStateRecoversFromBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "empty-main-recovery", CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysis(context.Background(), model.AnalysisInput{Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	loaded, err := recovered.GetAnalysis(context.Background(), analysis.ID)
	if err != nil || loaded == nil {
		t.Fatalf("empty main did not recover from backup: loaded=%#v err=%v", loaded, err)
	}
}

func TestMissingMainWithCorruptBackupFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path+".bak", []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt backup was ignored and a new empty state was created")
	}
}

func TestTerminalDeliveryIsPersistedAtomically(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fresh, err := store.RecordTerminalDelivery(context.Background(), "terminal-1", "github", "invalid", "bad payload")
	if err != nil || !fresh {
		t.Fatalf("fresh=%v err=%v", fresh, err)
	}
	store.mu.Lock()
	record := store.state.Deliveries["terminal-1"]
	store.mu.Unlock()
	if record.Status != "invalid" || record.Error != "bad payload" {
		t.Fatalf("record=%#v", record)
	}
	fresh, err = store.RecordTerminalDelivery(context.Background(), "terminal-1", "github", "ignored", "changed")
	if err != nil || fresh {
		t.Fatalf("duplicate fresh=%v err=%v", fresh, err)
	}
}

func TestStatsExposeRunningAndFailedJobs(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Enqueue(ctx, "running", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	running, err := store.ClaimJob(ctx, "worker-running")
	if err != nil || running == nil {
		t.Fatalf("running claim=%#v err=%v", running, err)
	}
	if err := store.Enqueue(ctx, "failed", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	failed, err := store.ClaimJob(ctx, "worker-failed")
	if err != nil || failed == nil {
		t.Fatalf("failed claim=%#v err=%v", failed, err)
	}
	if err := store.FailJob(ctx, failed.ID, failed.LeaseToken, 8, "permanent"); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RunningJobs != 1 || stats.FailedJobs != 1 || stats.QueuedJobs != 0 {
		t.Fatalf("stats=%#v", stats)
	}
}
