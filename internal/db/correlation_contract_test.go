package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCorrelationForTenantIncludesCurrentCandidateOnce(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	stats, err := store.CorrelationForTenant(
		context.Background(),
		"default",
		"unique-fingerprint",
		"acme/api",
		"acme",
		time.Now().UTC().Add(-time.Hour),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Repositories != 1 || stats.Organizations != 1 || stats.Occurrences != 1 {
		t.Fatalf("first candidate must be counted exactly once, got %+v", stats)
	}
}
