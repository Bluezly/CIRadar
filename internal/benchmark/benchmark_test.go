package benchmark

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ciradar/internal/analyzer"
	"ciradar/internal/model"
)

func TestEvaluateReportsAccuracyCoverageAndConfusion(t *testing.T) {
	ds := Dataset{
		SchemaVersion: SchemaVersion,
		Name:          "fixture",
		Version:       "1",
		Cases: []Case{
			{ID: "npm", Input: model.AnalysisInput{Log: "npm ERR! code ECONNRESET\nrequest to https://registry.npmjs.org/pkg failed"}, Expected: Expected{Category: model.CategoryDependencyRegistry, Attribution: model.AttributionExternal, Provider: "npm", ErrorFamily: "connection-reset"}},
			{ID: "assert", Input: model.AnalysisInput{Log: "--- FAIL: TestTotal\nexpected 4, got 5"}, Expected: Expected{Category: model.CategoryCodeFailure}},
			{ID: "unknown", Input: model.AnalysisInput{Log: "an internal company-specific tool returned frobnitz 17"}, Expected: Expected{Category: model.CategoryUnknown}},
		},
	}
	r := Evaluate(analyzer.New("benchmark-key"), ds)
	if r.Cases != 3 || r.CategoryCorrect != 3 || r.CategoryAccuracy != 1 {
		t.Fatalf("report=%#v", r)
	}
	if r.UnknownRate != 1.0/3.0 || r.Coverage != 2.0/3.0 || r.CoveredAccuracy != 1 {
		t.Fatalf("coverage=%v unknown=%v covered_accuracy=%v", r.Coverage, r.UnknownRate, r.CoveredAccuracy)
	}
	if r.AttributionCases != 1 || r.AttributionAccuracy != 1 || r.ProviderAccuracy != 1 || r.ErrorFamilyAccuracy != 1 {
		t.Fatalf("secondary metrics=%#v", r)
	}
	if len(r.Misclassified) != 0 {
		t.Fatalf("unexpected errors=%#v", r.Misclassified)
	}
}

func TestEvaluateMisclassificationCountsFalsePositiveAndFalseNegative(t *testing.T) {
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{
		{ID: "wrong", Input: model.AnalysisInput{Log: "npm ERR! code ECONNRESET"}, Expected: Expected{Category: model.CategoryNetworkFailure}},
	}}
	r := Evaluate(analyzer.New("benchmark-key"), ds)
	if r.CategoryAccuracy != 0 || len(r.Misclassified) != 1 {
		t.Fatalf("report=%#v", r)
	}
	var network ClassMetrics
	for _, m := range r.ByCategory {
		if m.Label == model.CategoryNetworkFailure {
			network = m
		}
	}
	if network.Support != 1 || network.FalseNeg != 1 || network.Recall != 0 {
		t.Fatalf("network metrics=%#v", network)
	}
}

func TestLoadExternalLogAndRejectTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "failure.log"), []byte("npm ERR! code ECONNRESET"), 0o600); err != nil {
		t.Fatal(err)
	}
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{{ID: "one", LogFile: "failure.log", Expected: Expected{Category: model.CategoryDependencyRegistry}}}}
	body, _ := json.Marshal(ds)
	path := filepath.Join(dir, "dataset.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(loaded.Cases[0].Input.Log, "ECONNRESET") {
		t.Fatalf("log=%q", loaded.Cases[0].Input.Log)
	}

	ds.Cases[0].LogFile = "../secret.log"
	body, _ = json.Marshal(ds)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal error=%v", err)
	}
}

func TestLoadRejectsUnknownFieldsAndDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dataset.json")
	bad := `{"schema_version":1,"name":"x","unknown":true,"cases":[{"id":"a","input":{"log":"x"},"expected":{"category":"UNKNOWN"}}]}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error=%v", err)
	}

	ds := Dataset{SchemaVersion: SchemaVersion, Name: "x", Cases: []Case{
		{ID: "same", Input: model.AnalysisInput{Log: "x"}, Expected: Expected{Category: model.CategoryUnknown}},
		{ID: "same", Input: model.AnalysisInput{Log: "y"}, Expected: Expected{Category: model.CategoryUnknown}},
	}}
	body, _ := json.Marshal(ds)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error=%v", err)
	}
}

func TestCheckThresholds(t *testing.T) {
	report := Report{CategoryAccuracy: 0.80, MacroF1: 0.70, Coverage: 0.75, UnknownRate: 0.25}
	if err := CheckThresholds(report, Thresholds{MinimumCategoryAccuracy: 0.8, MinimumMacroF1: 0.7, MinimumCoverage: 0.75, MaximumUnknownRate: 0.25}); err != nil {
		t.Fatal(err)
	}
	if err := CheckThresholds(report, Thresholds{MinimumCategoryAccuracy: 0.81}); err == nil {
		t.Fatal("expected threshold failure")
	}
}

func TestDigestChangesWithLogOrLabel(t *testing.T) {
	base := Dataset{SchemaVersion: SchemaVersion, Name: "x", Cases: []Case{{ID: "one", Input: model.AnalysisInput{Log: "first"}, Expected: Expected{Category: model.CategoryUnknown}}}}
	a := Digest(base)
	base.Cases[0].Input.Log = "second"
	b := Digest(base)
	if a == b {
		t.Fatal("digest did not change with log content")
	}
	base.Cases[0].Input.Log = "first"
	base.Cases[0].Expected.Category = model.CategoryCodeFailure
	if a == Digest(base) {
		t.Fatal("digest did not change with label")
	}
}

func TestEvaluateMacroIncludesPredictedOnlyCategories(t *testing.T) {
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{
		{ID: "wrong", Input: model.AnalysisInput{Log: "npm ERR! code ECONNRESET"}, Expected: Expected{Category: model.CategoryNetworkFailure}},
	}}
	r := Evaluate(analyzer.New("benchmark-key"), ds)
	if len(r.ByCategory) != 2 {
		t.Fatalf("expected truth and predicted classes in macro metrics, got %#v", r.ByCategory)
	}
	if r.MacroF1 != 0 {
		t.Fatalf("macro F1=%v, want 0", r.MacroF1)
	}
}

func TestEvaluateReportsConfidenceIntervalsAndRuleCoverage(t *testing.T) {
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{
		{ID: "known", Input: model.AnalysisInput{Log: "npm ERR! code ECONNRESET"}, Expected: Expected{Category: model.CategoryDependencyRegistry}},
		{ID: "unknown", Input: model.AnalysisInput{Log: "frobnitz private-tool failure 17"}, Expected: Expected{Category: model.CategoryUnknown}},
	}}
	r := Evaluate(analyzer.New("benchmark-key"), ds)
	if r.CategoryAccuracyCI95Low <= 0 || r.CategoryAccuracyCI95High > 1 || r.CategoryAccuracyCI95Low >= r.CategoryAccuracyCI95High {
		t.Fatalf("accuracy interval=%v..%v", r.CategoryAccuracyCI95Low, r.CategoryAccuracyCI95High)
	}
	if r.CoverageCI95Low < 0 || r.CoverageCI95High > 1 || r.CoverageCI95Low >= r.CoverageCI95High {
		t.Fatalf("coverage interval=%v..%v", r.CoverageCI95Low, r.CoverageCI95High)
	}
	if r.CasesWithMatchedRules < 1 || r.DistinctRulesMatched < 1 || r.RuleMatchCoverage <= 0 {
		t.Fatalf("rule coverage=%#v", r)
	}
}

func TestCheckThresholdsMinimumCases(t *testing.T) {
	report := Report{Cases: 99}
	if err := CheckThresholds(report, Thresholds{MinimumCases: 100}); err == nil || !strings.Contains(err.Error(), "case count") {
		t.Fatalf("threshold error=%v", err)
	}
}

func TestDigestChangesWithContextAndInputMetadata(t *testing.T) {
	base := Dataset{SchemaVersion: SchemaVersion, Name: "x", Cases: []Case{{ID: "one", Input: model.AnalysisInput{Repository: "acme/a", Log: "same"}, Expected: Expected{Category: model.CategoryUnknown}}}}
	a := Digest(base)
	base.Cases[0].Context.ProviderIncident = true
	if a == Digest(base) {
		t.Fatal("digest did not change with benchmark context")
	}
	base.Cases[0].Context.ProviderIncident = false
	base.Cases[0].Input.Repository = "acme/b"
	if a == Digest(base) {
		t.Fatal("digest did not change with analysis input metadata")
	}
}

func TestSelectUsesHeldOutSplit(t *testing.T) {
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{
		{ID: "train", Split: "train", Input: model.AnalysisInput{Log: "one"}, Expected: Expected{Category: model.CategoryUnknown}},
		{ID: "test", Split: "test", Input: model.AnalysisInput{Log: "two"}, Expected: Expected{Category: model.CategoryUnknown}},
	}}
	selected, err := Select(ds, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Cases) != 1 || selected.Cases[0].ID != "test" {
		t.Fatalf("selected=%#v", selected.Cases)
	}
	if _, err := Select(ds, "dev"); err == nil {
		t.Fatal("expected missing split to fail")
	}
}

func TestLoadRejectsUnknownSplit(t *testing.T) {
	dir := t.TempDir()
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{{ID: "one", Split: "secret", Input: model.AnalysisInput{Log: "x"}, Expected: Expected{Category: model.CategoryUnknown}}}}
	body, _ := json.Marshal(ds)
	path := filepath.Join(dir, "dataset.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid split") {
		t.Fatalf("split error=%v", err)
	}
}

func TestWilson95ReferenceValues(t *testing.T) {
	low, high := wilson95(3, 3)
	if low < 0.4384 || low > 0.4386 || high < 0.9999 || high > 1 {
		t.Fatalf("3/3 interval=%0.6f..%0.6f", low, high)
	}
	low, high = wilson95(2, 3)
	if low < 0.2076 || low > 0.2078 || high < 0.9384 || high > 0.9386 {
		t.Fatalf("2/3 interval=%0.6f..%0.6f", low, high)
	}
	low, high = wilson95(0, 3)
	if low != 0 || high < 0.5614 || high > 0.5616 {
		t.Fatalf("0/3 interval=%0.6f..%0.6f", low, high)
	}
}

func TestReportIncludesAnalyzerConfigurationDigest(t *testing.T) {
	a := analyzer.New("benchmark-key")
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "digest", Cases: []Case{{ID: "one", Input: model.AnalysisInput{Log: "npm ERR! code ECONNRESET"}, Expected: Expected{Category: model.CategoryDependencyRegistry}}}}
	report := Evaluate(a, ds)
	if report.AnalyzerDigestSHA256 == "" || report.AnalyzerDigestSHA256 != a.ConfigurationDigest() {
		t.Fatalf("analyzer digest=%q expected=%q", report.AnalyzerDigestSHA256, a.ConfigurationDigest())
	}
}

func TestLoadRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	datasetDir := filepath.Join(root, "dataset")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(datasetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(outsideDir, "secret.log")
	if err := os.WriteFile(outside, []byte("secret outside dataset"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(datasetDir, "linked.log")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{{ID: "one", LogFile: "linked.log", Expected: Expected{Category: model.CategoryUnknown}}}}
	body, _ := json.Marshal(ds)
	path := filepath.Join(datasetDir, "dataset.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("symlink escape error=%v", err)
	}
}

func TestBenchmarkLogBudgetRejectsAggregateMemoryAmplification(t *testing.T) {
	remaining := int64(maxBenchmarkResolvedLogLen - 1)
	used, err := consumeBenchmarkLogBudget(remaining, 1)
	if err != nil || used != maxBenchmarkResolvedLogLen {
		t.Fatalf("boundary used=%d err=%v", used, err)
	}
	if _, err := consumeBenchmarkLogBudget(used, 1); err == nil {
		t.Fatal("aggregate log budget overflow was accepted")
	}
}

func TestCheckThresholdsRejectsNonFiniteValuesAndSupportsZeroUnknownRate(t *testing.T) {
	report := Report{Cases: 1, CategoryAccuracy: 1, MacroF1: 1, Coverage: 1, UnknownRate: 0.01}
	if err := CheckThresholds(report, Thresholds{MinimumCategoryAccuracy: math.NaN()}); err == nil {
		t.Fatal("NaN threshold was accepted")
	}
	if err := CheckThresholds(report, Thresholds{MinimumMacroF1: math.Inf(1)}); err == nil {
		t.Fatal("infinite threshold was accepted")
	}
	if err := CheckThresholds(report, Thresholds{MaximumUnknownRate: 0, MaximumUnknownRateEnabled: true}); err == nil {
		t.Fatal("explicit zero UNKNOWN-rate gate did not fail")
	}
	if err := CheckThresholds(report, Thresholds{}); err != nil {
		t.Fatalf("zero-value thresholds should remain disabled: %v", err)
	}
}

func TestLoadRequiresDeclaredCaseSourcesAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dataset.json")
	ds := Dataset{
		SchemaVersion: SchemaVersion,
		Name:          "fixture",
		Sources:       []Source{{Name: "public-v1"}},
		Cases:         []Case{{ID: "one", Source: "missing", Input: model.AnalysisInput{Log: "x"}, Expected: Expected{Category: model.CategoryUnknown}}},
	}
	body, _ := json.Marshal(ds)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "undeclared source") {
		t.Fatalf("undeclared source error=%v", err)
	}

	ds.Sources = []Source{{Name: "public-v1"}, {Name: "public-v1"}}
	ds.Cases[0].Source = "public-v1"
	body, _ = json.Marshal(ds)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "duplicate benchmark source") {
		t.Fatalf("duplicate source error=%v", err)
	}
}

func TestEvaluateReportsCasesBySource(t *testing.T) {
	ds := Dataset{SchemaVersion: SchemaVersion, Name: "fixture", Cases: []Case{
		{ID: "a", Source: "corpus-a", Input: model.AnalysisInput{Log: "x"}, Expected: Expected{Category: model.CategoryUnknown}},
		{ID: "b", Source: "corpus-a", Input: model.AnalysisInput{Log: "y"}, Expected: Expected{Category: model.CategoryUnknown}},
		{ID: "c", Source: "corpus-b", Input: model.AnalysisInput{Log: "z"}, Expected: Expected{Category: model.CategoryUnknown}},
	}}
	report := Evaluate(analyzer.New("benchmark-key"), ds)
	if report.SourceCases["corpus-a"] != 2 || report.SourceCases["corpus-b"] != 1 {
		t.Fatalf("source cases=%#v", report.SourceCases)
	}
}
