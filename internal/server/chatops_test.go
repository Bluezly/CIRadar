package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

func TestTeamsChatOpsRejectsReplay(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secret := "teams-secret"
	srv := &Server{cfg: config.Config{ChatOps: config.ChatOpsConfig{Enabled: true, TeamsSigningSecret: secret, TeamsAllowedUsers: []string{"user-1"}, DefaultTenant: "default", AllowAcknowledge: true}}, store: store}
	incident := model.Incident{TenantID: "default", Fingerprint: "fp", Title: "registry", State: "open", Severity: "major", FirstSeenAt: time.Now(), LastSeenAt: time.Now()}
	if err := store.UpsertIncidentForTenant(context.Background(), "default", incident); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"activity-1","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","text":"ack fp","from":{"id":"user-1","name":"Alice"},"conversation":{"id":"c1"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	auth := "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://x/chatops/teams", bytes.NewReader(body))
		req.Header.Set("Authorization", auth)
		rr := httptest.NewRecorder()
		srv.teamsChatOps(rr, req)
		return rr
	}
	if rr := do(); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "acknowledged") {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := do(); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "duplicate request ignored") {
		t.Fatalf("replay status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTeamsChatOpsRequiresFreshSignedTimestamp(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secret := "teams-secret"
	srv := &Server{cfg: config.Config{ChatOps: config.ChatOpsConfig{Enabled: true, TeamsSigningSecret: secret, TeamsAllowedUsers: []string{"user-1"}, DefaultTenant: "default"}}, store: store}
	body := []byte(`{"id":"activity-old","timestamp":"` + time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339) + `","text":"ack fp","from":{"id":"user-1"}}`)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	req := httptest.NewRequest(http.MethodPost, "http://x/chatops/teams", bytes.NewReader(body))
	req.Header.Set("Authorization", "HMAC "+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	rr := httptest.NewRecorder()
	srv.teamsChatOps(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
