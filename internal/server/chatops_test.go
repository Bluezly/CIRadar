package server

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func TestTeamsCommand(t *testing.T) {
	v, e := teamsCommand("ack abc", "default")
	if e != nil || v != "default|ack|abc" {
		t.Fatalf("%q %v", v, e)
	}
}
func TestPerformChatAction(t *testing.T) {
	store, e := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	inc := model.Incident{TenantID: "default", Fingerprint: "fp", Title: "registry", State: "open", Severity: "major", FirstSeenAt: time.Now(), LastSeenAt: time.Now()}
	if e := store.UpsertIncidentForTenant(context.Background(), "default", inc); e != nil {
		t.Fatal(e)
	}
	srv := &Server{cfg: config.Config{ChatOps: config.ChatOpsConfig{DefaultTenant: "default", AllowAcknowledge: true, AllowResolve: true, AllowQuarantine: true, QuarantineDuration: "1d"}}, store: store}
	r := httptest.NewRequest("POST", "http://x", nil)
	msg, e := srv.performChatAction(r, "default|ack|fp", "alice")
	if e != nil || msg == "" {
		t.Fatalf("%s %v", msg, e)
	}
	got, e := store.GetIncidentForTenant(r.Context(), "default", "fp")
	if e != nil || got.State != "acknowledged" {
		t.Fatalf("%#v %v", got, e)
	}
}
