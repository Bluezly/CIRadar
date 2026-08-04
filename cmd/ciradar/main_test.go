package main

import (
	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func TestBuiltInAnalysisSamples(t *testing.T) {
	for _, name := range []string{"npm-econnreset", "go-test-failure"} {
		value, err := builtInAnalysisSample(name)
		if err != nil || value == "" {
			t.Fatalf("name=%s value=%q err=%v", name, value, err)
		}
	}
	if _, err := builtInAnalysisSample("missing"); err == nil {
		t.Fatal("unknown sample was accepted")
	}
}

func TestLocalAnalyzeDoesNotSelfCorrelateByDefault(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)
	if err := config.SaveDefault("ciradar.json"); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(tmp, "npm.log")
	if err := os.WriteFile(logPath, []byte("npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/lodash failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := runAnalyzeJSON(t, []string{"--config", "ciradar.json", "--json", logPath})
	second := runAnalyzeJSON(t, []string{"--config", "ciradar.json", "--json", logPath})
	if first.Score != second.Score {
		t.Fatalf("first=%d second=%d", first.Score, second.Score)
	}
	if second.CrossRepoCount != 0 || second.CrossOrgCount != 0 {
		t.Fatalf("cross repo=%d org=%d", second.CrossRepoCount, second.CrossOrgCount)
	}
}

func runAnalyzeJSON(t *testing.T, args []string) model.AnalysisResult {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = cmdAnalyze(args)
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var result model.AnalysisResult
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("output=%q err=%v", b, err)
	}
	return result
}
