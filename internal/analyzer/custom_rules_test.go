package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"ciradar/internal/model"
)

func TestLoadCustomRules(t *testing.T) {
	dir := t.TempDir()
	body := `{
	  "id":"corp-registry",
	  "category":"DEPENDENCY_REGISTRY",
	  "provider":"corp",
	  "operation":"download",
	  "error_family":"timeout",
	  "summary":"Corp registry timeout",
	  "recommendation":"Check registry status",
	  "weight":60,
	  "patterns":["registry\\.corp.*timeout"]
	}`
	if err := os.WriteFile(filepath.Join(dir, "corp.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadCustomRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d", len(rules))
	}
	a := New("test", rules...)
	result := a.Analyze(model.AnalysisInput{Log: "registry.corp download timeout"}, Context{})
	if result.Provider != "corp" || result.Category != model.CategoryDependencyRegistry {
		t.Fatalf("result=%+v", result)
	}
}
