package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestEmbeddedStoreRollsBackSecondaryMutationsWhenPersistenceFails(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalPath := store.path
	defer func() {
		store.path = originalPath
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()

	if _, err := store.CreateTenant(ctx, "team2", "Team Two"); err != nil {
		t.Fatal(err)
	}
	key, _, err := store.CreateAPIKey(ctx, model.DefaultTenantID, "rollback-key", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindInstallation(ctx, model.DefaultTenantID, 7); err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "feedback-seed", Category: model.CategoryCodeFailure, Attribution: model.AttributionCode, CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{TenantID: model.DefaultTenantID, Fingerprint: "incident-seed", State: "open", FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
	if err := store.UpsertIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	seed := model.TestObservation{ID: "observation-seed", Repository: "acme/api", Framework: "go", Name: "TestRollback", Status: "passed", OccurredAt: time.Now().UTC()}
	if _, err := store.RecordTestObservations(ctx, model.DefaultTenantID, []model.TestObservation{seed}); err != nil {
		t.Fatal(err)
	}
	testKey := TestKey(seed)
	oldQuarantine, err := store.SetTestQuarantine(ctx, model.TestQuarantine{TenantID: model.DefaultTenantID, TestKey: testKey, Reason: "existing", Owner: "old-owner", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutObject(ctx, model.DefaultTenantID, "rollback", "object", map[string]string{"value": "old"}); err != nil {
		t.Fatal(err)
	}

	badPath := filepath.Join(t.TempDir(), "state-directory")
	if err := os.Mkdir(badPath, 0o700); err != nil {
		t.Fatal(err)
	}
	store.path = badPath

	if _, err := store.CreateTenant(ctx, "must-not-exist", "No Persist"); err == nil {
		t.Fatal("tenant persistence failure was not reported")
	}
	if tenant, _ := store.GetTenant(ctx, "must-not-exist"); tenant != nil {
		t.Fatal("failed tenant creation remained in memory")
	}

	if err := store.SetTenantEnabled(ctx, "team2", false); err == nil {
		t.Fatal("tenant update persistence failure was not reported")
	}
	if tenant, _ := store.GetTenant(ctx, "team2"); tenant == nil || !tenant.Enabled {
		t.Fatalf("failed tenant update changed memory: %#v", tenant)
	}

	beforeKeys, err := store.ListAPIKeys(ctx, model.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateAPIKey(ctx, model.DefaultTenantID, "must-not-exist", model.RoleViewer); err == nil {
		t.Fatal("API key persistence failure was not reported")
	}
	afterKeys, _ := store.ListAPIKeys(ctx, model.DefaultTenantID)
	if len(afterKeys) != len(beforeKeys) {
		t.Fatalf("failed API key creation changed key count: before=%d after=%d", len(beforeKeys), len(afterKeys))
	}
	if err := store.RevokeAPIKey(ctx, model.DefaultTenantID, key.ID); err == nil {
		t.Fatal("API key revocation persistence failure was not reported")
	}
	if got, _ := store.GetAPIKey(ctx, model.DefaultTenantID, key.ID); got == nil || !got.RevokedAt.IsZero() {
		t.Fatalf("failed API key revocation changed memory: %#v", got)
	}

	if err := store.BindInstallation(ctx, model.DefaultTenantID, 8); err == nil {
		t.Fatal("installation bind persistence failure was not reported")
	}
	if _, ok := store.ResolveInstallationTenant(ctx, 8); ok {
		t.Fatal("failed installation bind remained in memory")
	}
	if err := store.UnbindInstallation(ctx, 7); err == nil {
		t.Fatal("installation unbind persistence failure was not reported")
	}
	if tenant, ok := store.ResolveInstallationTenant(ctx, 7); !ok || tenant != model.DefaultTenantID {
		t.Fatalf("failed installation unbind changed memory: tenant=%q ok=%v", tenant, ok)
	}

	beforeAudit, _ := store.ListAudit(ctx, model.DefaultTenantID, 100)
	if err := store.RecordAudit(ctx, model.AuditEvent{TenantID: model.DefaultTenantID, Actor: "tester", Action: "rollback"}); err == nil {
		t.Fatal("audit persistence failure was not reported")
	}
	afterAudit, _ := store.ListAudit(ctx, model.DefaultTenantID, 100)
	if len(afterAudit) != len(beforeAudit) {
		t.Fatalf("failed audit changed memory: before=%d after=%d", len(beforeAudit), len(afterAudit))
	}

	if _, err := store.UpsertRepositoryProfile(ctx, model.RepositoryProfile{TenantID: model.DefaultTenantID, Repository: "acme/api", Owner: "owner"}); err == nil {
		t.Fatal("repository profile persistence failure was not reported")
	}
	if profile, _ := store.GetRepositoryProfile(ctx, model.DefaultTenantID, "acme/api"); profile != nil {
		t.Fatalf("failed repository profile remained in memory: %#v", profile)
	}

	if _, err := store.UpdateIncidentState(ctx, model.DefaultTenantID, incident.Fingerprint, "resolved", "tester", "done"); err == nil {
		t.Fatal("incident update persistence failure was not reported")
	}
	if got, _ := store.GetIncidentForTenant(ctx, model.DefaultTenantID, incident.Fingerprint); got == nil || got.State != "open" {
		t.Fatalf("failed incident update changed memory: %#v", got)
	}

	if _, err := store.UpsertDiagnosisFeedback(ctx, model.DiagnosisFeedback{TenantID: model.DefaultTenantID, AnalysisID: analysis.ID, Actor: "reviewer", Verdict: "correct"}); err == nil {
		t.Fatal("feedback persistence failure was not reported")
	}
	if feedback, _ := store.ListDiagnosisFeedback(ctx, model.DefaultTenantID, 100); len(feedback) != 0 {
		t.Fatalf("failed feedback remained in memory: %#v", feedback)
	}

	failed := seed
	failed.ID = "observation-failed"
	failed.Status = "failed"
	failed.Message = "timeout while connecting"
	failed.OccurredAt = seed.OccurredAt.Add(time.Second)
	if _, err := store.RecordTestObservations(ctx, model.DefaultTenantID, []model.TestObservation{failed}); err == nil {
		t.Fatal("test observation persistence failure was not reported")
	}
	stats, _ := store.GetTestCaseStats(ctx, model.DefaultTenantID, testKey)
	if stats == nil || stats.TotalRuns != 1 || stats.Failures != 0 || len(stats.CauseCounts) != 0 {
		t.Fatalf("failed observation changed stats: %#v", stats)
	}
	history, _ := store.ListTestObservations(ctx, model.DefaultTenantID, testKey, 100)
	if len(history) != 1 || history[0].ID != seed.ID {
		t.Fatalf("failed observation changed history: %#v", history)
	}

	if _, err := store.SetTestCritical(ctx, model.DefaultTenantID, testKey, true); err == nil {
		t.Fatal("critical flag persistence failure was not reported")
	}
	stats, _ = store.GetTestCaseStats(ctx, model.DefaultTenantID, testKey)
	if stats == nil || stats.Critical {
		t.Fatalf("failed critical update changed memory: %#v", stats)
	}

	if _, err := store.SetTestQuarantine(ctx, model.TestQuarantine{TenantID: model.DefaultTenantID, TestKey: testKey, Reason: "replacement", Owner: "new-owner", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}); err == nil {
		t.Fatal("quarantine update persistence failure was not reported")
	}
	quarantines, _ := store.ListTestQuarantines(ctx, model.DefaultTenantID)
	if len(quarantines) != 1 || quarantines[0].Owner != oldQuarantine.Owner || !quarantines[0].ExpiresAt.Equal(oldQuarantine.ExpiresAt) {
		t.Fatalf("failed quarantine update replaced existing record: %#v", quarantines)
	}
	if err := store.RemoveTestQuarantine(ctx, model.DefaultTenantID, testKey); err == nil {
		t.Fatal("quarantine removal persistence failure was not reported")
	}
	quarantines, _ = store.ListTestQuarantines(ctx, model.DefaultTenantID)
	if len(quarantines) != 1 || quarantines[0].Owner != oldQuarantine.Owner {
		t.Fatalf("failed quarantine removal changed memory: %#v", quarantines)
	}

	if err := store.PutObject(ctx, model.DefaultTenantID, "rollback", "object", map[string]string{"value": "new"}); err == nil {
		t.Fatal("extension update persistence failure was not reported")
	}
	var object map[string]string
	if ok, err := store.GetObject(ctx, model.DefaultTenantID, "rollback", "object", &object); err != nil || !ok || object["value"] != "old" {
		t.Fatalf("failed extension update changed memory: object=%#v ok=%v err=%v", object, ok, err)
	}
	if err := store.DeleteObject(ctx, model.DefaultTenantID, "rollback", "object"); err == nil {
		t.Fatal("extension delete persistence failure was not reported")
	}
	object = nil
	if ok, err := store.GetObject(ctx, model.DefaultTenantID, "rollback", "object", &object); err != nil || !ok || object["value"] != "old" {
		t.Fatalf("failed extension deletion changed memory: object=%#v ok=%v err=%v", object, ok, err)
	}
}

func TestListingQuarantinesDoesNotMutateExpiredRecords(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := quarantineKey(model.DefaultTenantID, "expired")
	store.mu.Lock()
	store.state.TestQuarantines[key] = model.TestQuarantine{TenantID: model.DefaultTenantID, TestKey: "expired", Active: true, ExpiresAt: time.Now().UTC().Add(-time.Minute)}
	store.mu.Unlock()
	listed, err := store.ListTestQuarantines(context.Background(), model.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("expired quarantine was listed: %#v", listed)
	}
	store.mu.Lock()
	stored := store.state.TestQuarantines[key]
	store.mu.Unlock()
	if !stored.Active {
		t.Fatal("read-only quarantine listing mutated persisted state")
	}
}
