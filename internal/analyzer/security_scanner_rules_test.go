package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestSecurityScannerCatalogIsRegisteredAndUnique(t *testing.T) {
	specs := catalogSecurityScannerRules()
	if len(specs) != 52 {
		t.Fatalf("security scanner rules=%d want=52", len(specs))
	}
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if _, exists := seen[spec.id]; exists {
			t.Fatalf("duplicate security scanner rule %q", spec.id)
		}
		seen[spec.id] = struct{}{}
	}
	builtin := BuiltinRules()
	for id := range seen {
		found := false
		for _, rule := range builtin {
			if rule.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("security scanner rule %q is not registered", id)
		}
	}
}

func TestCodeQLCurrentCIRadarAlertsAreDiagnosedPrecisely(t *testing.T) {
	tests := []struct {
		name   string
		log    string
		family string
		rule   string
	}{
		{
			name: "weak sensitive hash",
			log: `Use of a broken or weak cryptographic hashing algorithm on sensitive data
High
#38 opened 2 hours ago • Detected by CodeQL in internal/db/postgres_rate_limit.go:117
main`,
			family: "weak-sensitive-data-hashing",
			rule:   "codeql-weak-sensitive-hash",
		},
		{
			name: "incorrect integer conversion",
			log: `Incorrect conversion between integer types
High
#37 opened 2 hours ago • Detected by CodeQL in internal/db/postgres_rate_limit.go:137
main`,
			family: "incorrect-integer-conversion",
			rule:   "codeql-incorrect-int-conversion",
		},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "Bluezly/CIRadar", Log: tt.log}, Context{})
			if r.Category != model.CategoryCodeFailure || r.Provider != "CodeQL" || r.Operation != "security-scan" || r.ErrorFamily != tt.family {
				t.Fatalf("category=%s provider=%q operation=%q family=%q rules=%v", r.Category, r.Provider, r.Operation, r.ErrorFamily, r.MatchedRules)
			}
			if !containsRuleID(r.MatchedRules, tt.rule) {
				t.Fatalf("missing %q in %v", tt.rule, r.MatchedRules)
			}
		})
	}
}

func TestSecurityScannerRepresentativeOutputs(t *testing.T) {
	tests := []struct {
		name     string
		log      string
		provider string
		family   string
		rule     string
	}{
		{name: "bandit", log: ">> Issue: [B506:yaml_load] Use of unsafe yaml load.\n   Severity: High   Confidence: High", provider: "Bandit", family: "python-security-finding", rule: "bandit-security-finding"},
		{name: "gitleaks", log: "Finding:     API_KEY=deadbeef\nSecret:      deadbeef\nRuleID:      generic-api-key\nFile:        .env\nLine:        1", provider: "Gitleaks", family: "secret-detected", rule: "gitleaks-secret"},
		{name: "trivy", log: "app:latest (debian 12)\nTotal: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 1)", provider: "Trivy", family: "vulnerabilities-found", rule: "trivy-critical-high"},
		{name: "grype", log: "✔ Scanned for vulnerabilities     [5 vulnerability matches]\n├── by severity: 2 critical, 3 high, 0 medium, 0 low", provider: "Grype", family: "vulnerabilities-found", rule: "grype-vulnerabilities"},
		{name: "osv", log: "Total 2 packages affected by 2 known vulnerabilities (1 Critical, 1 High, 0 Medium, 0 Low, 0 Unknown) from 2 ecosystems.", provider: "OSV-Scanner", family: "known-vulnerabilities-found", rule: "osv-known-vulnerabilities"},
		{name: "snyk", log: "Tested 412 dependencies for known issues, found 3 issues", provider: "Snyk", family: "vulnerabilities-found", rule: "snyk-vulnerabilities"},
		{name: "checkov", log: `Check: CKV_AWS_18: "Ensure the S3 bucket has access logging enabled" FAILED for resource: aws_s3_bucket.logs`, provider: "Checkov", family: "iac-policy-failure", rule: "checkov-failed-check"},
		{name: "hadolint", log: "Dockerfile:7 DL3008 warning: Pin versions in apt get install", provider: "Hadolint", family: "dockerfile-lint-failure", rule: "hadolint-finding"},
		{name: "shellcheck", log: "script.sh:12:8: warning: Double quote to prevent globbing and word splitting [SC2086]", provider: "ShellCheck", family: "shell-lint-failure", rule: "shellcheck-finding"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "example/security", Log: tt.log}, Context{})
			if r.Provider != tt.provider || r.ErrorFamily != tt.family {
				t.Fatalf("provider=%q family=%q rules=%v", r.Provider, r.ErrorFamily, r.MatchedRules)
			}
			if !containsRuleID(r.MatchedRules, tt.rule) {
				t.Fatalf("missing %q in %v", tt.rule, r.MatchedRules)
			}
		})
	}
}
