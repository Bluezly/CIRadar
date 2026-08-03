package analyzer

import (
	"strings"
	"testing"

	"ciradar/internal/model"
)

func TestNPMExternal(t *testing.T) {
	a := New("test")
	r := a.Analyze(model.AnalysisInput{Repository: "acme/app", Log: "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed"}, Context{})
	if r.Category != model.CategoryDependencyRegistry {
		t.Fatalf("category=%s", r.Category)
	}
	if r.Provider != "npm" {
		t.Fatalf("provider=%s", r.Provider)
	}
}

func TestRedaction(t *testing.T) {
	r := NewRedactor().Redact("Authorization: Bearer abcdefghijklmnop token=hello")
	if r == "Authorization: Bearer abcdefghijklmnop token=hello" {
		t.Fatal("not redacted")
	}
}

func TestCodeFailure(t *testing.T) {
	a := New("test")
	r := a.Analyze(model.AnalysisInput{Log: "main.go:12:3: undefined: thing"}, Context{})
	if r.Category != model.CategoryCodeFailure {
		t.Fatalf("category=%s", r.Category)
	}
	if r.Confidence != model.ConfidenceLikelyCode {
		t.Fatalf("confidence=%s score=%d", r.Confidence, r.Score)
	}
}

func TestEnvironmentExtractionWithGitHubTimestamps(t *testing.T) {
	log := "2026-08-03T01:11:02Z Image: ubuntu-24.04\n2026-08-03T01:11:02Z Version: 20260727.1\n2026-08-03T01:11:03Z Node.js version: 22.17.0\n"
	env := ExtractEnvironment(log)
	if env.RunnerOS != "ubuntu-24.04" || env.RunnerImage != "20260727.1" || env.ToolVersions["node"] != "22.17.0" {
		t.Fatalf("env=%+v", env)
	}
}

func TestRedactionEnvironmentSecrets(t *testing.T) {
	input := "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD\nMY_API_TOKEN=top-secret-value\n"
	redacted := NewRedactor().Redact(input)
	if strings.Contains(redacted, "abcdefghijklmnopqrstuvwxyz1234567890ABCD") || strings.Contains(redacted, "top-secret-value") {
		t.Fatalf("environment secret was not redacted: %s", redacted)
	}
}
