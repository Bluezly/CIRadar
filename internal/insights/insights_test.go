package insights

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestDORAAndUsage(t *testing.T) {
	store, e := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	_, e = RecordDeployment(ctx, store, model.DeploymentEvent{TenantID: "default", Repository: "a/b", Environment: "production", CommitSHA: "x", Status: "success", FirstCommitAt: now.Add(-2 * time.Hour), StartedAt: now.Add(-10 * time.Minute), CompletedAt: now})
	if e != nil {
		t.Fatal(e)
	}
	_, e = RecordUsage(ctx, store, model.CIEvent{TenantID: "default", Provider: "github", Repository: "a/b", JobID: "1", DurationSeconds: 120, CompletedAt: now}, .01, "USD")
	if e != nil {
		t.Fatal(e)
	}
	d, e := DORA(ctx, store, "default", "production", now.Add(-24*time.Hour), now.Add(time.Minute))
	if e != nil || d.Deployments != 1 || d.LeadTimeForChangesMinutes < 119 {
		t.Fatalf("%#v %v", d, e)
	}
	u, e := Usage(ctx, store, "default", now.Add(-24*time.Hour), now.Add(time.Minute))
	if e != nil || u.Runs != 1 || u.EstimatedCost <= 0 {
		t.Fatalf("%#v %v", u, e)
	}
}

type failingIncidentStore struct {
	db.Backend
	err error
}

func (s failingIncidentStore) ListIncidentsForTenant(context.Context, string, int, string) ([]model.Incident, error) {
	return nil, s.err
}

func TestDORAFailsWhenIncidentHistoryCannotBeRead(t *testing.T) {
	base, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	sentinel := errors.New("incident storage unavailable")
	_, err = DORA(context.Background(), failingIncidentStore{Backend: base, err: sentinel}, "default", "production", time.Now().Add(-time.Hour), time.Now())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}
