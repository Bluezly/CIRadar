package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func testServer(t *testing.T) (*Server, *db.Store, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root-secret"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, store, analyzer.New("test-key"), log), store, cfg
}

func doReq(t *testing.T, s *Server, method, path, token, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rbody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rbody = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rbody)
	req.RemoteAddr = "203.0.113.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-CI-Radar-Tenant", tenant)
	}
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	return rr
}

func TestTenantIsolationAndRoles(t *testing.T) {
	s, store, _ := testServer(t)
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTenant(context.Background(), "beta", "Beta"); err != nil {
		t.Fatal(err)
	}
	_, alphaViewer, err := store.CreateAPIKey(context.Background(), "alpha", "alpha-view", model.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	_, alphaOperator, err := store.CreateAPIKey(context.Background(), "alpha", "alpha-op", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	_, betaOperator, err := store.CreateAPIKey(context.Background(), "beta", "beta-op", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}

	payload := model.AnalysisInput{Repository: "acme/api", Workflow: "ci", Job: "test", Log: "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/a failed"}
	rr := doReq(t, s, http.MethodPost, "/api/v1/analyze", alphaViewer, "", payload)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doReq(t, s, http.MethodPost, "/api/v1/analyze", alphaOperator, "", payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("alpha analyze=%d body=%s", rr.Code, rr.Body.String())
	}
	var alpha model.AnalysisResult
	if err := json.Unmarshal(rr.Body.Bytes(), &alpha); err != nil {
		t.Fatal(err)
	}
	if alpha.TenantID != "alpha" {
		t.Fatalf("tenant=%q", alpha.TenantID)
	}

	payload.Repository = "other/web"
	rr = doReq(t, s, http.MethodPost, "/api/v1/analyze", betaOperator, "", payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("beta analyze=%d body=%s", rr.Code, rr.Body.String())
	}
	var beta model.AnalysisResult
	_ = json.Unmarshal(rr.Body.Bytes(), &beta)

	rr = doReq(t, s, http.MethodGet, "/api/v1/analyses", alphaViewer, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	if strings.Contains(rr.Body.String(), beta.ID) || !strings.Contains(rr.Body.String(), alpha.ID) {
		t.Fatalf("tenant leak/list mismatch: %s", rr.Body.String())
	}
	rr = doReq(t, s, http.MethodGet, "/api/v1/analyses/"+beta.ID, alphaViewer, "", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant read status=%d", rr.Code)
	}
}

func TestRootTenantSwitchAndDashboard(t *testing.T) {
	s, store, _ := testServer(t)
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	in := model.AnalysisInput{TenantID: "alpha", Repository: "alpha/api", Organization: "alpha", Workflow: "ci", Job: "build", OccurredAt: time.Now().UTC()}
	r := model.AnalysisResult{ID: "a-alpha", TenantID: "alpha", Category: model.CategoryNetworkFailure, Attribution: model.AttributionExternal, Provider: "npm", Confidence: model.ConfidenceModerate, Score: 60, Fingerprint: "fp", Summary: "network", CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysisForTenant(context.Background(), "alpha", in, r, true, false); err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, s, http.MethodGet, "/api/v1/dashboard?range=24h", "root-secret", "alpha", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"tenant_id":"alpha"`) || !strings.Contains(rr.Body.String(), `"total_analyses":1`) {
		t.Fatalf("dashboard=%s", rr.Body.String())
	}
	rr = doReq(t, s, http.MethodGet, "/api/v1/status", "root-secret", "missing", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant status=%d", rr.Code)
	}
}

func TestIncidentWorkflowWritesAudit(t *testing.T) {
	s, store, _ := testServer(t)
	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "ops", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	inc := model.Incident{ID: "inc_default_fp", TenantID: model.DefaultTenantID, Fingerprint: "fp", State: "open", Severity: "major", FirstSeenAt: now, LastSeenAt: now, Title: "npm outage"}
	if err := store.UpsertIncidentForTenant(context.Background(), model.DefaultTenantID, inc); err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, s, http.MethodPost, "/api/v1/incidents/fp/acknowledge", token, "", map[string]string{"note": "investigating"})
	if rr.Code != http.StatusOK {
		t.Fatalf("ack=%d body=%s", rr.Code, rr.Body.String())
	}
	got, _ := store.GetIncidentForTenant(context.Background(), model.DefaultTenantID, "fp")
	if got == nil || got.State != "acknowledged" || got.AcknowledgedBy != "ops" {
		t.Fatalf("incident=%+v", got)
	}
	audits, _ := store.ListAudit(context.Background(), model.DefaultTenantID, 10)
	if len(audits) == 0 || audits[0].Action != "incident.acknowledged" {
		t.Fatalf("audit=%+v", audits)
	}
}

func TestRateLimiterRejectsExcess(t *testing.T) {
	l := newRateLimiter(2, time.Minute)
	h := rateLimit(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		r.RemoteAddr = "198.51.100.4:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i < 2 && w.Code != http.StatusNoContent {
			t.Fatalf("request %d status=%d", i, w.Code)
		}
		if i == 2 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("rate limit status=%d", w.Code)
		}
	}
}

func TestDashboardRequiresTokenByDefault(t *testing.T) {
	s, _, _ := testServer(t)
	rr := doReq(t, s, http.MethodGet, "/api/v1/dashboard", "", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRepositoryProfileValidatesConfiguredChannels(t *testing.T) {
	s, store, cfg := testServer(t)
	cfg.Notifications.Channels[0].Name = "slack-ops"

	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "admin", model.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, s, http.MethodPut, "/api/v1/repositories/acme/api", token, "", model.RepositoryProfile{Criticality: "high", NotificationChannels: []string{"missing"}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown channel status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doReq(t, s, http.MethodPut, "/api/v1/repositories/acme/api", token, "", model.RepositoryProfile{Criticality: "high", NotificationChannels: []string{"slack-ops"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("valid profile status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWebhookRequiresTenantBinding(t *testing.T) {
	s, store, _ := testServer(t)
	s.cfg.GitHubAppID = 1
	s.cfg.GitHubPrivateKeyPath = "configured.pem"
	s.cfg.GitHubWebhookSecret = "webhook-secret"
	s.cfg.RequireInstallationBinding = true
	body := []byte(`{"action":"completed","installation":{"id":987},"repository":{"full_name":"acme/api"},"workflow_run":{"id":12,"name":"ci","status":"completed","conclusion":"failure","head_sha":"abc"}}`)
	mac := hmac.New(sha256.New, []byte(s.cfg.GitHubWebhookSecret))
	_, _ = mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Delivery", "delivery-unbound")
	req.Header.Set("X-GitHub-Event", "workflow_run")
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("unbound status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := store.CreateTenant(context.Background(), "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindInstallation(context.Background(), "acme", 987); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("X-GitHub-Delivery", "delivery-bound")
	req.Header.Set("X-GitHub-Event", "workflow_run")
	rr = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"tenant_id":"acme"`) {
		t.Fatalf("bound status=%d body=%s", rr.Code, rr.Body.String())
	}
	st, _ := store.StatsForTenant(context.Background(), "acme")
	if st.QueuedJobs != 1 {
		t.Fatalf("queued jobs=%d", st.QueuedJobs)
	}
}

func TestWebhookUsesSeparateBurstBucket(t *testing.T) {
	l := newRateLimiter(1, time.Minute)
	h := rateLimit(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodPost, "/webhooks/github", nil)
		r.RemoteAddr = "192.0.2.44:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("webhook request %d status=%d", i, w.Code)
		}
	}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		r.RemoteAddr = "192.0.2.44:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i == 0 && w.Code != http.StatusNoContent {
			t.Fatalf("api request status=%d", w.Code)
		}
		if i == 1 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("api limit status=%d", w.Code)
		}
	}
}

func TestRootCanDisableTenantButNotLastEnabled(t *testing.T) {
	s, store, _ := testServer(t)
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, s, http.MethodPatch, "/api/v1/tenants/alpha", "root-secret", model.DefaultTenantID, map[string]any{"enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("disable alpha=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doReq(t, s, http.MethodPatch, "/api/v1/tenants/default", "root-secret", model.DefaultTenantID, map[string]any{"enabled": false})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("disable last=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestGitLabWebhookQueuesTenantScopedCIEvent(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.Notifications.Enabled = false
	cfg.Connectors = []config.CIConnector{{Name: "gitlab", Provider: "gitlab", Enabled: true, TenantID: "alpha", BaseURL: "https://gitlab.example", Token: "api", WebhookSecret: "hook"}}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := []byte(`{"object_kind":"build","build_id":42,"build_name":"test","build_status":"failed","pipeline_id":9,"project":{"id":7,"path_with_namespace":"acme/api"},"commit":{"sha":"abc"}}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/gitlab", bytes.NewReader(body))
	req.Header.Set("X-Gitlab-Token", "hook")
	req.Header.Set("X-Gitlab-Webhook-UUID", "gl-1")
	rr := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	job, err := store.ClaimJob(context.Background(), "test")
	if err != nil || job == nil || job.Type != "ci.event" || job.TenantID != "alpha" {
		t.Fatalf("job=%#v err=%v", job, err)
	}
}

func TestMCPHTTPIsAuthenticatedAndReadOnly(t *testing.T) {
	s, store, _ := testServer(t)
	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "view", model.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
	rr := doReq(t, s, http.MethodPost, "/mcp", "", "", body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth=%d", rr.Code)
	}
	rr = doReq(t, s, http.MethodPost, "/mcp", token, "", body)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "list_active_incidents") {
		t.Fatalf("mcp=%d %s", rr.Code, rr.Body.String())
	}
	write := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "retry_job", "arguments": map[string]any{}}}
	rr = doReq(t, s, http.MethodPost, "/mcp", token, "", write)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "unknown read-only tool") {
		t.Fatalf("write=%d %s", rr.Code, rr.Body.String())
	}
}

func TestJUnitAutoQuarantineAndManifest(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.Notifications.Enabled = false
	cfg.ProviderPolling = false
	cfg.TestIntelligence.Enabled = true
	cfg.TestIntelligence.AutoQuarantine = true
	cfg.TestIntelligence.AutoQuarantineMinRuns = 3
	cfg.TestIntelligence.AutoQuarantineMinScore = 35
	cfg.TestIntelligence.AutoQuarantineDuration = 48 * time.Hour
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "operator", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))

	reports := []string{
		`<testsuite name="unit"><testcase classname="Calc" name="adds"/></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"><failure message="boom">stack</failure></testcase></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"/></testsuite>`,
	}
	for i, xmlBody := range reports {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tests/junit?repository=acme/api&workflow=ci&job=test&run_id="+strconv.Itoa(i+1), strings.NewReader(xmlBody))
		req.RemoteAddr = "203.0.113.20:1234"
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ingest %d status=%d body=%s", i, rr.Code, rr.Body.String())
		}
	}

	rr := doReq(t, s, http.MethodGet, "/api/v1/tests/quarantine-manifest", token, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("manifest=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"test_keys":[`) || strings.Contains(rr.Body.String(), `"test_keys":[]`) {
		t.Fatalf("manifest missing active test: %s", rr.Body.String())
	}
	items, err := store.ListTestQuarantines(context.Background(), model.DefaultTenantID)
	if err != nil || len(items) != 1 || !items[0].Active {
		t.Fatalf("quarantines=%+v err=%v", items, err)
	}
}

func TestMCPStreamableHTTPGuards(t *testing.T) {
	s, store, _ := testServer(t)
	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "viewer", model.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	get.RemoteAddr = "203.0.113.9:1"
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, get)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET=%d", w.Code)
	}

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("origin=%d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", "1900-01-01")
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("protocol=%d %s", w.Code, w.Body.String())
	}

	note := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	req = httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(note))
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
		t.Fatalf("notification=%d body=%q", w.Code, w.Body.String())
	}
}
