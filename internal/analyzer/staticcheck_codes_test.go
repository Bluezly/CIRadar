package analyzer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestStaticcheckCodeCatalogRecognizesEverySupportedCode(t *testing.T) {
	specs := catalogStaticcheckRules()
	if len(specs) != 161 {
		t.Fatalf("staticcheck rules=%d want=161", len(specs))
	}

	builtin := BuiltinRules()
	byID := make(map[string]Rule, len(builtin))
	for _, rule := range builtin {
		byID[rule.ID] = rule
	}

	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if _, ok := seen[spec.id]; ok {
			t.Fatalf("duplicate staticcheck rule %q", spec.id)
		}
		seen[spec.id] = struct{}{}
		code := strings.ToUpper(strings.TrimPrefix(spec.id, "staticcheck-"))
		rule, ok := byID[spec.id]
		if !ok {
			t.Fatalf("missing builtin rule %q", spec.id)
		}
		if rule.Category != model.CategoryCodeFailure || rule.Provider != "Staticcheck" || rule.Operation != "static-analysis" || rule.ErrorFamily != spec.errorFamily {
			t.Fatalf("%s category=%s provider=%q operation=%q family=%q", code, rule.Category, rule.Provider, rule.Operation, rule.ErrorFamily)
		}
		log := fmt.Sprintf("internal/checks/sample.go:42:7: representative Staticcheck diagnostic (%s)", code)
		matched := false
		for _, pattern := range rule.Patterns {
			if pattern.MatchString(log) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("%s pattern did not match representative text output", code)
		}
	}
}

func TestStaticcheckU1000RealGitHubActionsLog(t *testing.T) {
	log := `go: downloading honnef.co/go/tools v0.7.0
go: downloading golang.org/x/tools v0.40.1-0.20260108161641-ca281cf95054
Error: internal/server/oauth.go:555:6: func containsString is unused (U1000)
Error: Process completed with exit code 1.`

	r := New("test").Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "Bluezly/CIRadar", Log: log}, Context{})
	if r.Category != model.CategoryCodeFailure || r.Provider != "Staticcheck" || r.ErrorFamily != "unused-code" {
		t.Fatalf("category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
	}
	if !containsRuleID(r.MatchedRules, "staticcheck-u1000") {
		t.Fatalf("rules=%v", r.MatchedRules)
	}
	if !strings.Contains(r.Summary, "U1000") {
		t.Fatalf("summary=%q", r.Summary)
	}
}

func TestStaticcheckCodeCatalogSupportsStylishAndMatrixOutput(t *testing.T) {
	tests := []struct {
		name   string
		log    string
		family string
		rule   string
	}{
		{
			name:   "stylish",
			log:    "internal/server/oauth.go\n  (555, 6)     U1000   func containsString is unused",
			family: "unused-code",
			rule:   "staticcheck-u1000",
		},
		{
			name:   "matrix",
			log:    "shared.go:4:6: func bar is unused [linux,windows] (U1000)",
			family: "unused-code",
			rule:   "staticcheck-u1000",
		},
		{
			name:   "sa4006",
			log:    "go/src/fmt/print.go:1069:15: this value of afterIndex is never used (SA4006)",
			family: "unused-assignment",
			rule:   "staticcheck-sa4006",
		},
		{
			name:   "st1005",
			log:    "internal/api/errors.go:91:10: error strings should not be capitalized (ST1005)",
			family: "error-string-style",
			rule:   "staticcheck-st1005",
		},
		{
			name:   "s1039",
			log:    "internal/text/text.go:17:9: unnecessary use of fmt.Sprint (S1039)",
			family: "unnecessary-fmt-sprint",
			rule:   "staticcheck-s1039",
		},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "example/staticcheck", Log: tt.log}, Context{})
			if r.Provider != "Staticcheck" || r.ErrorFamily != tt.family {
				t.Fatalf("provider=%q family=%q rules=%v", r.Provider, r.ErrorFamily, r.MatchedRules)
			}
			if !containsRuleID(r.MatchedRules, tt.rule) {
				t.Fatalf("missing %q in %v", tt.rule, r.MatchedRules)
			}
		})
	}
}

func TestStaticcheckUnknownFutureCodeFallsBackToGenericDiagnosis(t *testing.T) {
	tests := []string{
		"internal/future/future.go:12:3: future Staticcheck diagnostic (SA9999)",
		"internal/future/future.go\n  (12, 3)     QF1999   future Staticcheck quickfix",
	}
	a := New("test")
	for _, log := range tests {
		r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "example/staticcheck", Log: log}, Context{})
		if r.Provider != "Staticcheck" || r.ErrorFamily != "static-analysis-failure" {
			t.Fatalf("provider=%q family=%q rules=%v", r.Provider, r.ErrorFamily, r.MatchedRules)
		}
		if !containsRuleID(r.MatchedRules, "real-go-staticcheck-diagnostic") {
			t.Fatalf("rules=%v", r.MatchedRules)
		}
	}
}
