package testselection

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestSelectionUsesFile(t *testing.T) {
	s, e := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, e = s.RecordTestObservations(context.Background(), "default", []model.TestObservation{{TenantID: "default", Repository: "acme/api", Framework: "jest", File: "src/payments.test.ts", Suite: "payments", Name: "charges", Status: "failed", OccurredAt: time.Now()}})
	if e != nil {
		t.Fatal(e)
	}
	out, e := Select(context.Background(), s, "default", model.TestSelectionRequest{Repository: "acme/api", ChangedFiles: []string{"src/payments.ts"}, Limit: 10})
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Selected) != 1 || out.Selected[0].PriorityScore <= 0 {
		t.Fatalf("%#v", out)
	}
}

func TestSelectionRequiresFullSuiteForMigration(t *testing.T) {
	s, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.RecordTestObservations(context.Background(), "default", []model.TestObservation{{TenantID: "default", Repository: "acme/api", Framework: "go", File: "db/db_test.go", Name: "TestMigration", Status: "passed", OccurredAt: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Select(context.Background(), s, "default", model.TestSelectionRequest{Repository: "acme/api", ChangedFiles: []string{"db/migrations/20260806_add_index.sql"}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.FullSuiteRequired || out.SelectionSafe || out.RiskLevel != "critical" || out.Recommendation != "run_full_suite" {
		t.Fatalf("%#v", out)
	}
	if len(out.Selected) != 1 {
		t.Fatalf("%#v", out.Selected)
	}
}

func TestUnsafePartialOverrideIsExplicit(t *testing.T) {
	s, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.RecordTestObservations(context.Background(), "default", []model.TestObservation{{TenantID: "default", Repository: "acme/api", Framework: "jest", File: "src/payments.test.ts", Suite: "payments", Name: "charges", Status: "failed", OccurredAt: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Select(context.Background(), s, "default", model.TestSelectionRequest{Repository: "acme/api", ChangedFiles: []string{"src/payments.ts"}, AllowUnsafePartial: true})
	if err != nil {
		t.Fatal(err)
	}
	if !out.FullSuiteRequired || !out.UnsafeOverrideApplied || out.SelectionSafe {
		t.Fatalf("%#v", out)
	}
}
