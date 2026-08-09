package testselection

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestBuildGraphAndSelectByDependencyPath(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, root, "internal/ledger/ledger.go", "package ledger\nfunc Sum() int { return 1 }\n")
	writeTestFile(t, root, "internal/payments/payments.go", "package payments\nimport \"example.com/app/internal/ledger\"\nfunc Charge() int { return ledger.Sum() }\n")
	writeTestFile(t, root, "internal/payments/payments_test.go", "package payments\nimport \"testing\"\nfunc TestCharge(t *testing.T) {}\n")
	graph, err := BuildGraph(root, "acme/app")
	if err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := SaveGraph(ctx, store, "default", graph); err != nil {
		t.Fatal(err)
	}
	obs := model.TestObservation{TenantID: "default", Repository: "acme/app", Framework: "go", Suite: "payments", Name: "TestCharge", File: "internal/payments/payments_test.go", Status: "passed", OccurredAt: time.Now().UTC()}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{obs}); err != nil {
		t.Fatal(err)
	}
	out, err := Select(ctx, store, "default", model.TestSelectionRequest{Repository: "acme/app", ChangedFiles: []string{"internal/ledger/ledger.go"}, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Selected) != 1 {
		t.Fatalf("%#v", out)
	}
	selected := out.Selected[0]
	if selected.Strategy != "dependency_graph" || len(selected.ImpactPath) < 3 || selected.Confidence < .8 {
		t.Fatalf("%#v", selected)
	}
}

func TestCoverageOverridesGraph(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	obs := model.TestObservation{TenantID: "default", Repository: "acme/app", Framework: "jest", Name: "charges card", File: "tests/payment.test.ts", Status: "passed", OccurredAt: time.Now().UTC()}
	stats, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{obs})
	if err != nil {
		t.Fatal(err)
	}
	graph := model.ImpactGraph{Repository: "acme/app", Dependencies: map[string][]string{}, TestCoverage: map[string][]string{stats[0].TestKey: {"src/card.ts"}}}
	if err := SaveGraph(ctx, store, "default", graph); err != nil {
		t.Fatal(err)
	}
	out, err := Select(ctx, store, "default", model.TestSelectionRequest{Repository: "acme/app", ChangedFiles: []string{"src/card.ts"}, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Selected) != 1 || out.Selected[0].Strategy != "coverage" || out.Selected[0].PriorityScore < 99 {
		t.Fatalf("%#v", out)
	}
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageReadableIdentitySelectsIngestedTest(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	obs := model.TestObservation{TenantID: "default", Repository: "fake/repo", Framework: "junit", Suite: "payments", ClassName: "PaymentServiceTest", Name: "retries_transient_gateway_error", File: "tests/payment_service_test.go", Status: "failed", OccurredAt: time.Now().UTC()}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{obs}); err != nil {
		t.Fatal(err)
	}
	_, err = MergeCoverage(ctx, store, "default", model.TestCoverageInput{Repository: "fake/repo", Coverage: map[string][]string{"payments/PaymentServiceTest::retries_transient_gateway_error": {"fakerepo/src/payments.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Select(ctx, store, "default", model.TestSelectionRequest{Repository: "fake/repo", ChangedFiles: []string{"fakerepo/src/payments.go"}, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Selected) != 1 || out.Selected[0].Strategy != "coverage" {
		t.Fatalf("%#v", out)
	}
	if out.Selected[0].DisplayName != "payments/PaymentServiceTest/retries_transient_gateway_error" {
		t.Fatalf("display_name=%q", out.Selected[0].DisplayName)
	}
	if len(out.Selected[0].ImpactPath) != 2 {
		t.Fatalf("impact_path=%v", out.Selected[0].ImpactPath)
	}
	if len(out.Diagnostics) != 0 {
		t.Fatalf("diagnostics=%v", out.Diagnostics)
	}
}

func TestEmptySelectionExplainsCoverageIdentityMismatch(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	obs := model.TestObservation{TenantID: "default", Repository: "fake/repo", Framework: "junit", Suite: "accounts", ClassName: "AccountServiceTest", Name: "unrelated_behavior", Status: "passed", OccurredAt: time.Now().UTC()}
	if _, err := store.RecordTestObservations(ctx, "default", []model.TestObservation{obs}); err != nil {
		t.Fatal(err)
	}
	_, err = MergeCoverage(ctx, store, "default", model.TestCoverageInput{Repository: "fake/repo", Coverage: map[string][]string{"unrelated/test": {"src/payments.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Select(ctx, store, "default", model.TestSelectionRequest{Repository: "fake/repo", ChangedFiles: []string{"src/payments.go"}, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Selected) != 1 || !out.FullSuiteRequired || out.SelectionSafe || len(out.Diagnostics) == 0 {
		t.Fatalf("%#v", out)
	}
	if out.Selected[0].Strategy != "safety_full_suite" {
		t.Fatalf("expected safety fallback, got %#v", out.Selected[0])
	}
}

func TestResolveTestAcceptsReadableIdentity(t *testing.T) {
	stats := []model.TestCaseStats{{TestKey: "520c59865eaf60792dcadc23048c3660", Suite: "payments", ClassName: "PaymentServiceTest", Name: "retries_transient_gateway_error"}}
	got, err := ResolveTest(stats, "payments/PaymentServiceTest/retries_transient_gateway_error")
	if err != nil {
		t.Fatal(err)
	}
	if got.TestKey != stats[0].TestKey {
		t.Fatalf("got=%s", got.TestKey)
	}
}
