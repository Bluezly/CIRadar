package analyzer

import (
	"strings"
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

const reactCompilerDifferentialFailure = `Run bash scripts/test-rust-port.sh
Building Rust native module...
Finished dev profile [unoptimized + debuginfo] target(s) in 0.03s
Testing 1806 fixtures for pass: PruneHoistedContexts
Results: 1805 passed, 1 failed (1806 total), frontier: HIR
Code: 1806 passed, 0 failed (1806 total)
FAIL compiler/packages/babel-plugin-react-compiler/src/__tests__/fixtures/compiler/jsx-underscore-prefix-component.js
--- TypeScript
+++ Rust
@@ line 61 @@
-                loc: 10:10-10:14
+                loc: 10:22-10:27
Error: Process completed with exit code 1.`

func TestReactCompilerDifferentialFailure(t *testing.T) {
	result := New("test").Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "facebook/react", Log: reactCompilerDifferentialFailure}, Context{})
	if result.Category != model.CategoryCodeFailure {
		t.Fatalf("category=%s matched=%v", result.Category, result.MatchedRules)
	}
	if result.Provider != "compiler differential test" || result.Operation != "fixture-comparison" || result.ErrorFamily != "compiler-output-mismatch" {
		t.Fatalf("provider=%q operation=%q family=%q matched=%v", result.Provider, result.Operation, result.ErrorFamily, result.MatchedRules)
	}
	if result.Attribution != model.AttributionCode {
		t.Fatalf("attribution=%s score=%d matched=%v", result.Attribution, result.Score, result.MatchedRules)
	}
	if !containsRuleID(result.MatchedRules, "compiler-differential-output-mismatch") {
		t.Fatalf("matched=%v", result.MatchedRules)
	}
}

func TestReactCompilerDifferentialFailureInsideLargeLog(t *testing.T) {
	var log strings.Builder
	for i := 0; i < 1800; i++ {
		log.WriteString("compiler fixture completed successfully\n")
	}
	log.WriteString(reactCompilerDifferentialFailure)
	log.WriteByte('\n')
	for i := 0; i < 1800; i++ {
		log.WriteString("compiler fixture completed successfully\n")
	}
	if log.Len() <= maxDirectMatchLogBytes {
		t.Fatalf("large log fixture too small: %d", log.Len())
	}
	result := New("test").Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "facebook/react", Log: log.String()}, Context{})
	if result.Provider != "compiler differential test" || result.ErrorFamily != "compiler-output-mismatch" {
		t.Fatalf("provider=%q family=%q category=%s matched=%v", result.Provider, result.ErrorFamily, result.Category, result.MatchedRules)
	}
}

func containsRuleID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
