package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestRulesWorksBeforeInit(t *testing.T) {
	dir := t.TempDir()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := cmdRules(nil); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateTestGate(t *testing.T) {
	passed := model.TestObservation{TenantID: "default", Repository: "acme/api", Suite: "unit", ClassName: "Calc", Name: "ok", Status: "passed"}
	failed := model.TestObservation{TenantID: "default", Repository: "acme/api", Suite: "unit", ClassName: "Calc", Name: "flaky", Status: "failed"}
	key := db.TestKey(failed)
	r := evaluateTestGate([]model.TestObservation{passed, failed}, []model.TestQuarantine{{TestKey: key, Active: true, ExpiresAt: time.Now().Add(time.Hour)}})
	if len(r.QuarantinedFailures) != 1 || len(r.UnquarantinedFailures) != 0 {
		t.Fatalf("%+v", r)
	}
	r = evaluateTestGate([]model.TestObservation{failed}, nil)
	if len(r.UnquarantinedFailures) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestAnalyzeWithoutCorrelationIsScoreStable(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	logPath := filepath.Join(dir, "npm.txt")
	if err := os.WriteFile(logPath, []byte("npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := runAnalyzeJSON(t, []string{"--config", configPath, "--json", logPath})
	second := runAnalyzeJSON(t, []string{"--config", configPath, "--json", logPath})
	if first.Score != second.Score || first.Score != 52 {
		t.Fatalf("first=%d second=%d", first.Score, second.Score)
	}
	if first.CrossRepoCount != 0 || second.CrossRepoCount != 0 || first.CrossOrgCount != 0 || second.CrossOrgCount != 0 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestAnalyzeCorrelationDoesNotInventRepositories(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	logPath := filepath.Join(dir, "npm.txt")
	if err := os.WriteFile(logPath, []byte("npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = runAnalyzeJSON(t, []string{"--config", configPath, "--json", logPath})
	result := runAnalyzeJSON(t, []string{"--config", configPath, "--json", "--correlate", logPath})
	if result.CrossRepoCount != 1 || result.CrossOrgCount != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func writeTestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(dir, "state.json")
	cfg.DataDirectory = filepath.Join(dir, "data")
	cfg.RulesDirectory = filepath.Join(dir, "rules")
	cfg.ProviderPolling = false
	cfg.FingerprintHMACKey = "test-fingerprint-key"
	cfg.AdminToken = "cir_root_test"
	cfg.DashboardSessionSecret = "test-dashboard-session-secret-32-bytes"
	path := filepath.Join(dir, "ciradar.json")
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runAnalyzeJSON(t *testing.T, args []string) model.AnalysisResult {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := cmdAnalyze(args)
	_ = w.Close()
	os.Stdout = old
	body, readErr := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	var result model.AnalysisResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode %q: %v", string(body), err)
	}
	return result
}

func TestResolveTestKeyByReadableIdentity(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	obs := model.TestObservation{TenantID: "default", Repository: "acme/api", Framework: "junit", Suite: "payments", ClassName: "PaymentServiceTest", Name: "retries_transient_gateway_error", Status: "failed", OccurredAt: time.Now().UTC()}
	stats, err := store.RecordTestObservations(context.Background(), "default", []model.TestObservation{obs})
	if err != nil {
		t.Fatal(err)
	}
	key, err := resolveTestKey(context.Background(), store, "default", "acme/api", "", "payments/PaymentServiceTest/retries_transient_gateway_error")
	if err != nil {
		t.Fatal(err)
	}
	if key != stats[0].TestKey {
		t.Fatalf("key=%s want=%s", key, stats[0].TestKey)
	}
}

func TestParseOptionalRFC3339RejectsInvalidInput(t *testing.T) {
	if value, err := parseOptionalRFC3339("started-at", ""); err != nil || !value.IsZero() {
		t.Fatalf("empty value=%v err=%v", value, err)
	}
	if _, err := parseOptionalRFC3339("started-at", "not-a-time"); err == nil || !strings.Contains(err.Error(), "--started-at") {
		t.Fatalf("invalid RFC3339 error=%v", err)
	}
	value, err := parseOptionalRFC3339("started-at", "2026-08-05T03:00:00Z")
	if err != nil || value.UTC().Format(time.RFC3339) != "2026-08-05T03:00:00Z" {
		t.Fatalf("value=%v err=%v", value, err)
	}
}

func TestTestsCriticalCLI(t *testing.T) {
	dir := t.TempDir()
	configPath := writeTestConfig(t, dir)
	store, err := db.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := model.TestObservation{TenantID: "default", Repository: "acme/api", Suite: "unit", ClassName: "Payments", Name: "refund", Status: "failed", OccurredAt: time.Now().UTC()}
	stats, err := store.RecordTestObservations(context.Background(), "default", []model.TestObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := cmdTests([]string{"critical", "--config", configPath, "--key", stats[0].TestKey})
	_ = w.Close()
	os.Stdout = old
	body, readErr := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	var updated model.TestCaseStats
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("decode %q: %v", string(body), err)
	}
	if !updated.Critical {
		t.Fatalf("critical=%v", updated.Critical)
	}
}

func TestDemoDoesNotRequireConfig(t *testing.T) {
	if err := cmdDemo([]string{"--json", "npm-econnreset"}); err != nil {
		t.Fatal(err)
	}
}
