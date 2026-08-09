package analyzer

import (
	"strings"
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestBuiltinRuleCountAndUniqueness(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) != 630 {
		t.Fatalf("builtin rule count=%d want=630", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule.ID]; ok {
			t.Fatalf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
}

func TestRepresentativeDiagnoses(t *testing.T) {
	tests := []struct {
		name        string
		log         string
		category    model.Category
		provider    string
		errorFamily string
	}{
		{name: "openclaw stale release dependency", log: `Error: plugin-npm-release-check rejected stale required release dependencies:\n- @openclaw/codex@2026.7.2: @openai/codex must match npm latest for release; found "0.146.1", latest is "0.147.0".`, category: model.CategoryCodeFailure, provider: "OpenClaw release check", errorFamily: "stale-release-dependency"},
		{name: "hosted runner acquisition", log: "The job was not acquired by Runner because hosted capacity is temporarily unavailable", category: model.CategoryRunnerFailure, provider: "hosted CI runner", errorFamily: "hosted-runner-acquisition-failed"},
		{name: "python syntax", log: "File \"agent/agent_init.py\", line 2047\n    compression_micro_compact_defrag_tokens = max(\n                                               ^\nSyntaxError: '(' was never closed", category: model.CategoryCodeFailure, provider: "Python", errorFamily: "syntax-unclosed-delimiter"},
		{name: "go assertion", log: "--- FAIL: TestSetBs_SingleDb (0.01s)\nError Trace: localstorage_test.go:193\nError: Not equal:\nexpected: 3\nactual  : 2\nTest: TestSetBs_SingleDb", category: model.CategoryCodeFailure, provider: "Go test/testify", errorFamily: "assertion-expected-actual"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.errorFamily {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
		})
	}
}

func TestCrossProjectRegressionCases(t *testing.T) {
	tests := []struct {
		name        string
		repository  string
		log         string
		category    model.Category
		provider    string
		errorFamily string
	}{
		{name: "actions setup-node missing node headers", repository: "actions/setup-node", log: "gyp ERR! build error\n../src/addon.cc:1:10: fatal error: node.h: No such file or directory\ncompilation terminated.", category: model.CategoryToolchainFailure, provider: "node-gyp", errorFamily: "node-headers-missing"},
		{name: "node-gyp missing Visual Studio", repository: "nodejs/node-gyp", log: "gyp ERR! find VS could not use PowerShell to find Visual Studio 2017 or newer\ngyp ERR! find VS Could not find any Visual Studio installation to use", category: model.CategoryToolchainFailure, provider: "node-gyp", errorFamily: "native-toolchain-unavailable"},
		{name: "supabase postgres scram", repository: "supabase/cli", log: "database connection failed: SASL authentication failed: invalid SCRAM server-final-message", category: model.CategoryCodeFailure, provider: "PostgreSQL", errorFamily: "scram-authentication-failure"},
		{name: "postgres password authentication", repository: "postgres/postgres", log: `FATAL: password authentication failed for user "ci_runner"`, category: model.CategoryCodeFailure, provider: "PostgreSQL", errorFamily: "scram-authentication-failure"},
		{name: "gradle invalid heap", repository: "gradle/gradle-build-action", log: "Invalid maximum heap size: -Xmx999999g\nError: Could not create the Java Virtual Machine.\nError: A fatal exception has occurred. Program will exit.", category: model.CategoryToolchainFailure, provider: "JVM", errorFamily: "invalid-jvm-option"},
		{name: "gradle unsupported vm option", repository: "gradle/gradle", log: "Unrecognized VM option 'UseConcMarkSweepGC'\nError: Could not create the Java Virtual Machine.", category: model.CategoryToolchainFailure, provider: "JVM", errorFamily: "invalid-jvm-option"},
		{name: "audio whisper cache bad request", repository: "bnosac/audio.whisper", log: "Failed to restore cache: Cache service responded with 400 Bad Request", category: model.CategoryCacheFailure, provider: "GitHub Actions Cache", errorFamily: "cache-service-request-rejected"},
		{name: "github cache service unavailable", repository: "actions/cache", log: "Failed to save cache: Cache service responded with 503 Service Unavailable", category: model.CategoryProviderIncident, provider: "GitHub Actions Cache", errorFamily: "cache-service-unavailable"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: tt.repository, Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.errorFamily {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
		})
	}
}

func TestDiagnosticMemoryIsTenantIsolatedAndAnalyzeRemainsStateless(t *testing.T) {
	a := New("test")
	log := "opaque proprietary failure token ZXQ-7781 with no public signature"
	seed := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if seed.Category != model.CategoryUnknown {
		t.Fatalf("seed category=%s", seed.Category)
	}
	a.RememberFeedback(seed, model.DiagnosisFeedback{TenantID: "alpha", AnalysisID: seed.ID, Verdict: "incorrect", ActualCategory: model.CategoryCodeFailure, ActualCause: model.AttributionCode, ActualProvider: "private-build", ActualErrorFamily: "tenant-confirmed"})
	stateless := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if stateless.Category != model.CategoryUnknown {
		t.Fatalf("Analyze must remain memory-free for benchmark determinism: %s", stateless.Category)
	}
	recalled := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if recalled.Category != model.CategoryCodeFailure || recalled.Provider != "private-build" || recalled.ErrorFamily != "tenant-confirmed" {
		t.Fatalf("recalled=%+v", recalled)
	}
	if !strings.Contains(recalled.DecisionReason, "tenant-isolated") {
		t.Fatalf("decision reason=%q", recalled.DecisionReason)
	}
	other := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "beta", Log: log}, Context{})
	if other.Category != model.CategoryUnknown {
		t.Fatalf("memory leaked across tenants: %+v", other)
	}
}

func TestDiagnosticMemoryExpires(t *testing.T) {
	a := New("test")
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	a.memory.now = func() time.Time { return now }
	a.memory.ttl = time.Minute
	log := "opaque tenant failure F00-BAR"
	seed := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	a.RememberFeedback(seed, model.DiagnosisFeedback{Verdict: "incorrect", ActualCategory: model.CategoryCodeFailure, ActualCause: model.AttributionCode, ActualProvider: "internal", ActualErrorFamily: "known"})
	now = now.Add(2 * time.Minute)
	r := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if r.Category != model.CategoryUnknown {
		t.Fatalf("expired memory still applied: %+v", r)
	}
}
