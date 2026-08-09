package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestMaybeIncidentDoesNotDoubleCountFirstFailure(t *testing.T) {
	s, store, _ := testServer(t)
	s.cfg.IncidentRepoThreshold = 3
	s.cfg.IncidentOrgThreshold = 2

	result := model.AnalysisResult{
		Fingerprint: "unique-first-failure",
		Provider:    "npm",
		ErrorFamily: "network",
		Summary:     "first isolated failure",
	}
	incident, created, err := s.maybeIncident(
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
		t.Fatalf("first isolated failure opened an incident: incident=%+v created=%v", incident, created)
	}
	stored, err := store.GetIncidentForTenant(context.Background(), "default", result.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Fatalf("unexpected stored incident: %+v", stored)
	}
}

func TestMaybeIncidentUsesExactCorrelationCountsAtThreshold(t *testing.T) {
	s, _, _ := testServer(t)
	s.cfg.IncidentRepoThreshold = 2
	s.cfg.IncidentOrgThreshold = 99

	result := model.AnalysisResult{
		Fingerprint: "exact-threshold",
		Provider:    "npm",
		ErrorFamily: "network",
		Summary:     "failure reached repository threshold",
	}
	incident, created, err := s.maybeIncident(
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
		t.Fatalf("incident counts were changed after correlation: %+v", incident)
	}
}

func TestAnalyzeFirstFailureDoesNotOpenIncidentBeforeThreshold(t *testing.T) {
	s, store, _ := testServer(t)
	s.cfg.IncidentRepoThreshold = 3
	s.cfg.IncidentOrgThreshold = 2

	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	_, token, err := store.CreateAPIKey(context.Background(), "alpha", "threshold-test", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	payload := model.AnalysisInput{
		Repository:   "acme/api",
		Organization: "acme",
		Workflow:     "ci",
		Job:          "test",
		Log:          "npm ERR! code ECONNRESET\nnpm ERR! request to https://registry.npmjs.org/pkg failed",
	}
	rr := doReq(t, s, "POST", "/api/v1/analyze", token, "", payload)
	if rr.Code != 200 {
		t.Fatalf("analyze status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result model.AnalysisResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.CrossRepoCount != 1 || result.CrossOrgCount != 1 {
		t.Fatalf("first analysis correlation counts=%d/%d, want 1/1", result.CrossRepoCount, result.CrossOrgCount)
	}
	incident, err := store.GetIncidentForTenant(context.Background(), "alpha", result.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if incident != nil {
		t.Fatalf("first isolated analysis unexpectedly opened incident: %+v", incident)
	}
}
