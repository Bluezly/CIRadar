package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestPersistenceAndCorrelation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	in := model.AnalysisInput{Repository: "acme/api", Organization: "acme", Workflow: "ci", Job: "test", Log: "SECRET RAW LOG"}
	r := model.AnalysisResult{ID: "a1", Fingerprint: "fp", Category: model.CategoryNetworkFailure, Confidence: model.ConfidenceModerate, CreatedAt: time.Now().UTC(), Environment: model.Environment{ToolVersions: map[string]string{}}}
	if err := s.RecordAnalysis(context.Background(), in, r, true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.state.Analyses["a1"].Input.Log; got != "" {
		t.Fatalf("raw log persisted unexpectedly: %q", got)
	}
	st, err := s2.Correlation(context.Background(), "fp", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.Repositories != 1 || st.Organizations != 1 || st.Occurrences != 1 {
		t.Fatalf("stats=%+v", st)
	}
}
