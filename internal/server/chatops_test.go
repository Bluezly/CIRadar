package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
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

func signedSlackAction(t *testing.T, srv *Server, secret, teamID, value string) *httptest.ResponseRecorder {
	t.Helper()
	payload := fmt.Sprintf(`{"type":"block_actions","team":{"id":%q},"user":{"id":"U1","username":"alice"},"actions":[{"action_id":"ciradar_ack","value":%q}]}`, teamID, value)
	body := url.Values{"payload": []string{payload}}.Encode()
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("v0:" + ts + ":" + body))
	req := httptest.NewRequest(http.MethodPost, "http://x/chatops/slack", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	rr := httptest.NewRecorder()
	srv.slackChatOps(rr, req)
	return rr
}

func TestSlackChatOpsBindsWorkspaceToTenant(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, tenant := range []string{"alpha", "beta"} {
		if _, err := store.CreateTenant(context.Background(), tenant, strings.ToUpper(tenant)); err != nil {
			t.Fatal(err)
		}
		inc := model.Incident{TenantID: tenant, Fingerprint: "shared-fp", Title: tenant + " registry", State: "open", Severity: "major", FirstSeenAt: time.Now(), LastSeenAt: time.Now()}
		if err := store.UpsertIncidentForTenant(context.Background(), tenant, inc); err != nil {
			t.Fatal(err)
		}
	}
	secret := "slack-secret"
	srv := &Server{cfg: config.Config{ChatOps: config.ChatOpsConfig{
		Enabled: true, SlackSigningSecret: secret, SlackAllowedTeams: []string{"T-ALPHA", "T-BETA"},
		SlackTeamTenants: map[string]string{"t-alpha": "alpha", "t-beta": "beta"}, AllowAcknowledge: true,
	}}, store: store}

	if rr := signedSlackAction(t, srv, secret, "T-ALPHA", "beta|ack|shared-fp"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "does not match Slack workspace") {
		t.Fatalf("cross-tenant action status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, tenant := range []string{"alpha", "beta"} {
		inc, err := store.GetIncidentForTenant(context.Background(), tenant, "shared-fp")
		if err != nil || inc == nil || inc.State != "open" {
			t.Fatalf("tenant %s changed after rejected cross-tenant action: %#v err=%v", tenant, inc, err)
		}
	}

	if rr := signedSlackAction(t, srv, secret, "T-ALPHA", "alpha|ack|shared-fp"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "acknowledged") {
		t.Fatalf("bound action status=%d body=%s", rr.Code, rr.Body.String())
	}
	alpha, _ := store.GetIncidentForTenant(context.Background(), "alpha", "shared-fp")
	beta, _ := store.GetIncidentForTenant(context.Background(), "beta", "shared-fp")
	if alpha == nil || alpha.State != "acknowledged" || beta == nil || beta.State != "open" {
		t.Fatalf("workspace binding failed: alpha=%#v beta=%#v", alpha, beta)
	}

	if rr := signedSlackAction(t, srv, secret, "T-UNKNOWN", "alpha|ack|shared-fp"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "not allowed") {
		t.Fatalf("unknown workspace status=%d body=%s", rr.Code, rr.Body.String())
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
