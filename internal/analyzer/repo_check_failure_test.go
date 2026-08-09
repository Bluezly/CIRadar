package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestRepoCheckGofmtFailureFromGitHubActions(t *testing.T) {
	log := `Run ./scripts/repo-check.sh
internal/analyzer/ecosystem_corpus_test.go
internal/analyzer/matching_robustness_test.go
internal/analyzer/modern_ecosystem_corpus_test.go
internal/analyzer/rules_catalog_ecosystem_1.go
internal/analyzer/rules_catalog_ecosystem_2.go
internal/analyzer/rules_catalog_ecosystem_3.go
internal/analyzer/rules_catalog_modern_2.go
Error: Process completed with exit code 1.`
	result := New("test").Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "Bluezly/CIRadar", Log: log}, Context{})
	if result.Category != model.CategoryCodeFailure {
		t.Fatalf("category=%s matched=%v", result.Category, result.MatchedRules)
	}
	if result.Provider != "gofmt" {
		t.Fatalf("provider=%s matched=%v", result.Provider, result.MatchedRules)
	}
	if result.Operation != "format-check" || result.ErrorFamily != "formatting-required" {
		t.Fatalf("operation=%s family=%s", result.Operation, result.ErrorFamily)
	}
	found := false
	for _, id := range result.MatchedRules {
		if id == "oss-gofmt-check" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing oss-gofmt-check in %v", result.MatchedRules)
	}
}

func TestExplicitRepoCheckGofmtFailure(t *testing.T) {
	log := `gofmt check failed; unformatted files:
internal/analyzer/rules.go
internal/server/server.go`
	result := New("test").Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if result.Provider != "gofmt" || result.ErrorFamily != "formatting-required" {
		t.Fatalf("provider=%s family=%s matched=%v", result.Provider, result.ErrorFamily, result.MatchedRules)
	}
}
