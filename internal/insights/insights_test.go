package insights

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ciradar/internal/db"
	"ciradar/internal/model"
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
