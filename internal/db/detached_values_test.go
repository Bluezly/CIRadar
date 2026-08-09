package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestEmbeddedStoreDetachesMutableAnalysisValues(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	result := model.AnalysisResult{
		ID:                 "detached-analysis",
		Category:           model.CategoryCodeFailure,
		Attribution:        model.AttributionCode,
		Evidence:           []model.Evidence{{Kind: "log", Description: "original"}},
		MatchedRules:       []string{"rule-a"},
		EnvironmentChanges: []string{"go:1.24"},
		Environment: model.Environment{
			ToolVersions:   map[string]string{"go": "1.24"},
			ContainerRefs:  []string{"ubuntu@sha256:one"},
			ActionVersions: []string{"actions/checkout@v4"},
		},
		SuggestedActions: []model.SuggestedAction{{ID: "fix", Commands: []string{"go test ./..."}, References: []string{"ref-a"}}},
		CreatedAt:        time.Now().UTC(),
	}
	if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{Repository: "acme/api"}, result, false, false); err != nil {
		t.Fatal(err)
	}
	result.Environment.ToolVersions["go"] = "mutated-input"
	result.Environment.ContainerRefs[0] = "mutated-input"
	result.MatchedRules[0] = "mutated-input"
	result.SuggestedActions[0].Commands[0] = "mutated-input"

	first, err := store.GetAnalysisForTenant(ctx, model.DefaultTenantID, result.ID)
	if err != nil || first == nil {
		t.Fatalf("analysis=%#v err=%v", first, err)
	}
	if first.Environment.ToolVersions["go"] != "1.24" || first.Environment.ContainerRefs[0] != "ubuntu@sha256:one" || first.MatchedRules[0] != "rule-a" || first.SuggestedActions[0].Commands[0] != "go test ./..." {
		t.Fatalf("caller input mutated stored analysis: %#v", first)
	}
	first.Environment.ToolVersions["go"] = "mutated-output"
	first.Environment.ContainerRefs[0] = "mutated-output"
	first.MatchedRules[0] = "mutated-output"
	first.SuggestedActions[0].Commands[0] = "mutated-output"
	second, err := store.GetAnalysisForTenant(ctx, model.DefaultTenantID, result.ID)
	if err != nil || second == nil {
		t.Fatalf("analysis=%#v err=%v", second, err)
	}
	if second.Environment.ToolVersions["go"] != "1.24" || second.Environment.ContainerRefs[0] != "ubuntu@sha256:one" || second.MatchedRules[0] != "rule-a" || second.SuggestedActions[0].Commands[0] != "go test ./..." {
		t.Fatalf("caller output mutated stored analysis: %#v", second)
	}
}

func TestEmbeddedStoreDetachesMutableTenantAndIncidentValues(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	profile := model.RepositoryProfile{TenantID: model.DefaultTenantID, Repository: "acme/api", NotificationChannels: []string{"slack"}}
	if _, err := store.UpsertRepositoryProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	profile.NotificationChannels[0] = "mutated-input"
	gotProfile, err := store.GetRepositoryProfile(ctx, model.DefaultTenantID, "acme/api")
	if err != nil || gotProfile == nil || gotProfile.NotificationChannels[0] != "slack" {
		t.Fatalf("profile input alias leaked: %#v err=%v", gotProfile, err)
	}
	gotProfile.NotificationChannels[0] = "mutated-output"
	againProfile, _ := store.GetRepositoryProfile(ctx, model.DefaultTenantID, "acme/api")
	if againProfile == nil || againProfile.NotificationChannels[0] != "slack" {
		t.Fatalf("profile output alias leaked: %#v", againProfile)
	}

	audit := model.AuditEvent{TenantID: model.DefaultTenantID, Actor: "tester", Action: "detached", Metadata: map[string]string{"source": "original"}}
	if err := store.RecordAudit(ctx, audit); err != nil {
		t.Fatal(err)
	}
	audit.Metadata["source"] = "mutated-input"
	audits, err := store.ListAudit(ctx, model.DefaultTenantID, 10)
	if err != nil || len(audits) != 1 || audits[0].Metadata["source"] != "original" {
		t.Fatalf("audit input alias leaked: %#v err=%v", audits, err)
	}
	audits[0].Metadata["source"] = "mutated-output"
	audits, _ = store.ListAudit(ctx, model.DefaultTenantID, 10)
	if len(audits) != 1 || audits[0].Metadata["source"] != "original" {
		t.Fatalf("audit output alias leaked: %#v", audits)
	}

	incident := model.Incident{
		TenantID:    model.DefaultTenantID,
		Fingerprint: "detached-incident",
		State:       "open",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		SuggestedActions: []model.SuggestedAction{{
			ID:       "investigate",
			Commands: []string{"inspect"},
		}},
	}
	if err := store.UpsertIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	incident.SuggestedActions[0].Commands[0] = "mutated-input"
	gotIncident, err := store.GetIncidentForTenant(ctx, model.DefaultTenantID, incident.Fingerprint)
	if err != nil || gotIncident == nil || gotIncident.SuggestedActions[0].Commands[0] != "inspect" {
		t.Fatalf("incident input alias leaked: %#v err=%v", gotIncident, err)
	}
	gotIncident.SuggestedActions[0].Commands[0] = "mutated-output"
	againIncident, _ := store.GetIncidentForTenant(ctx, model.DefaultTenantID, incident.Fingerprint)
	if againIncident == nil || againIncident.SuggestedActions[0].Commands[0] != "inspect" {
		t.Fatalf("incident output alias leaked: %#v", againIncident)
	}
}

func TestEmbeddedStoreDetachesMutableTestValues(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	observation := model.TestObservation{
		ID:         "detached-test",
		Repository: "acme/api",
		Framework:  "go",
		Name:       "TestDetached",
		Status:     "failed",
		Message:    "timeout while connecting",
		Environment: model.Environment{
			ToolVersions: map[string]string{"go": "1.24"},
		},
		OccurredAt: time.Now().UTC(),
	}
	stats, err := store.RecordTestObservations(ctx, model.DefaultTenantID, []model.TestObservation{observation})
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	observation.Environment.ToolVersions["go"] = "mutated-input"
	stats[0].CauseCounts[stats[0].PrimaryFlakeCause] = 999
	stats[0].ImpactedPullRequests = append(stats[0].ImpactedPullRequests, 999)
	key := TestKey(observation)
	storedStats, err := store.GetTestCaseStats(ctx, model.DefaultTenantID, key)
	if err != nil || storedStats == nil {
		t.Fatalf("stats=%#v err=%v", storedStats, err)
	}
	if storedStats.CauseCounts[storedStats.PrimaryFlakeCause] == 999 {
		t.Fatalf("returned stats map aliases internal state: %#v", storedStats.CauseCounts)
	}
	history, err := store.ListTestObservations(ctx, model.DefaultTenantID, key, 10)
	if err != nil || len(history) != 1 || history[0].Environment.ToolVersions["go"] != "1.24" {
		t.Fatalf("observation input alias leaked: %#v err=%v", history, err)
	}
	history[0].Environment.ToolVersions["go"] = "mutated-output"
	history, _ = store.ListTestObservations(ctx, model.DefaultTenantID, key, 10)
	if len(history) != 1 || history[0].Environment.ToolVersions["go"] != "1.24" {
		t.Fatalf("observation output alias leaked: %#v", history)
	}
}
