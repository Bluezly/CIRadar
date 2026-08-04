package testselection

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ciradar/internal/db"
	"ciradar/internal/model"
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
