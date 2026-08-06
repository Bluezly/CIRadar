package testintelligence

import (
	"testing"
	"time"

	"ciradar/internal/model"
)

func TestGroupFailureTypesNormalizesVolatileValues(t *testing.T) {
	now := time.Now().UTC()
	items := GroupFailureTypes([]model.TestObservation{
		{Status: "failed", Message: "timeout request 12345 at api/client.go:41", OccurredAt: now},
		{Status: "failed", Message: "timeout request 67890 at api/client.go:99", OccurredAt: now.Add(time.Minute)},
		{Status: "failed", Message: "permission denied", OccurredAt: now.Add(2 * time.Minute)},
	}, 10)
	if len(items) != 2 {
		t.Fatalf("failure groups=%d want=2: %+v", len(items), items)
	}
	if items[0].Count != 2 {
		t.Fatalf("top count=%d want=2", items[0].Count)
	}
}
