package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
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
	bad := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/fp/acknowledge", strings.NewReader(`{"note":`))
	bad.RemoteAddr = "203.0.113.10:1234"
	bad.Header.Set("Authorization", "Bearer "+token)
	badResult := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(badResult, bad)
	if badResult.Code != http.StatusBadRequest {
		t.Fatalf("malformed acknowledgement status=%d body=%s", badResult.Code, badResult.Body.String())
	}
	unchanged, _ := store.GetIncidentForTenant(context.Background(), model.DefaultTenantID, "fp")
	if unchanged == nil || unchanged.State != "open" {
		t.Fatalf("malformed request changed incident: %+v", unchanged)
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

func TestCSRFGuardAllowsSignedSAMLCallbackWithExistingSession(t *testing.T) {
	cfg := config.Default()
	cfg.PublicBaseURL = "https://ciradar.example"
	cfg.SSO.Enabled = true
	cfg.SSO.Mode = "saml"
	cfg.SSO.CookieName = "ciradar_session"
	resolver := newClientIPResolver(nil)
	called := false
	handler := csrfGuard(cfg, resolver, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	callback := httptest.NewRequest(http.MethodPost, "https://ciradar.example/auth/callback", strings.NewReader("SAMLResponse=x"))
	callback.Header.Set("Origin", "https://idp.example")
	callback.AddCookie(&http.Cookie{Name: cfg.SSO.CookieName, Value: "existing-session"})
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, callback)
	if result.Code != http.StatusNoContent || !called {
		t.Fatalf("SAML callback status=%d called=%v body=%s", result.Code, called, result.Body.String())
	}

	called = false
	unsafe := httptest.NewRequest(http.MethodPost, "https://ciradar.example/api/v1/analyze", strings.NewReader(`{"log":"x"}`))
	unsafe.Header.Set("Origin", "https://idp.example")
	unsafe.AddCookie(&http.Cookie{Name: cfg.SSO.CookieName, Value: "existing-session"})
	result = httptest.NewRecorder()
	handler.ServeHTTP(result, unsafe)
	if result.Code != http.StatusForbidden || called {
		t.Fatalf("ordinary cross-site POST status=%d called=%v body=%s", result.Code, called, result.Body.String())
	}
}

func TestRateLimiterRejectsExcess(t *testing.T) {
	l := newRateLimiter(2, time.Minute)
	h := rateLimit(l, newClientIPResolver(nil), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
	h := rateLimit(l, newClientIPResolver(nil), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "unknown tool") {
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
		`<testsuite name="unit"><testcase classname="Calc" name="adds"><failure message="boom">stack</failure></testcase></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"/></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"><failure message="boom">stack</failure></testcase></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"/></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"><failure message="boom">stack</failure></testcase></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"/></testsuite>`,
		`<testsuite name="unit"><testcase classname="Calc" name="adds"><failure message="boom">stack</failure></testcase></testsuite>`,
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

	req = httptest.NewRequest(http.MethodPost, "http://ciradar.test/mcp", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://ciradar.test")
	w = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-scheme MCP origin=%d %s", w.Code, w.Body.String())
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

func TestDashboardUsesStrictCSPWithoutInlineCode(t *testing.T) {
	s, _, _ := testServer(t)
	rr := doReq(t, s, http.MethodGet, "/", "", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("csp=%q", csp)
	}
	body := rr.Body.String()
	for _, forbidden := range []string{"onclick=", "style=", "<script>", "<style>"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard contains %q", forbidden)
		}
	}
	if !strings.Contains(body, "/assets/dashboard.js") || !strings.Contains(body, "/assets/dashboard.css") {
		t.Fatalf("dashboard assets missing")
	}
	for _, forbidden := range []string{"linear-gradient(", "radial-gradient(", "backdrop-filter", "box-shadow:"} {
		if strings.Contains(dashboardCSS, forbidden) {
			t.Fatalf("dashboard CSS contains %q", forbidden)
		}
	}
	for _, forbidden := range []string{`class="logo"`, ">C<"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard HTML contains %q", forbidden)
		}
	}
	if strings.Contains(dashboardJS, "prompt(") {
		t.Fatal("dashboard uses browser prompts")
	}
	for _, required := range []string{`id="action-dialog"`, `id="session-panel"`, `class="sidebar"`} {
		if !strings.Contains(body, required) {
			t.Fatalf("dashboard missing %q", required)
		}
	}
}

func TestSecureDashboardLoginUsesEncryptedHttpOnlyCookie(t *testing.T) {
	s, _, cfg := testServer(t)
	rr := doReq(t, s, http.MethodPost, "/auth/token", "", "", map[string]string{"token": cfg.AdminToken, "tenant": model.DefaultTenantID})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("session cookie missing")
	}
	cookie := cookies[0]
	if cookie.Name != dashboardSessionCookie || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie=%+v", cookie)
	}
	if strings.Contains(cookie.Value, cfg.AdminToken) || strings.Contains(cookie.Value, model.DefaultTenantID) || !strings.HasPrefix(cookie.Value, "v1.") {
		t.Fatalf("cookie is not encrypted: %q", cookie.Value)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("cookie authentication=%d body=%s", response.Code, response.Body.String())
	}
}

func TestUnauthenticatedLocalhostUsesResolvedClientIP(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.AllowUnauthenticatedLocalhost = true
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("proxied remote client received localhost trust: %d", response.Code)
	}
}

func TestCookieAuthenticatedWritesRequireSameOrigin(t *testing.T) {
	s, _, cfg := testServer(t)
	login := doReq(t, s, http.MethodPost, "/auth/token", "", "", map[string]string{"token": cfg.AdminToken, "tenant": model.DefaultTenantID})
	cookie := login.Result().Cookies()[0]
	payload := []byte(`{"repository":"acme/api","log":"npm ERR! code ECONNRESET"}`)
	request := httptest.NewRequest(http.MethodPost, "http://ciradar.example/api/v1/analyze", bytes.NewReader(payload))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing origin status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "http://ciradar.example/api/v1/analyze", bytes.NewReader(payload))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://ciradar.example")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-scheme origin status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "http://ciradar.example/api/v1/analyze", bytes.NewReader(payload))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://ciradar.example")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("same origin status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHSTSUsesTrustedForwardedProto(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.RemoteAddr = "10.0.0.5:443"
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing behind trusted HTTPS proxy")
	}
}

func TestMarketplacePurchaseUsesPrimaryGitHubWebhook(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.GitHubMarketplace.Enabled = true
	cfg.GitHubMarketplace.WebhookSecret = "market-secret"
	cfg.GitHubMarketplace.AutoCreateTenant = true
	cfg.GitHubMarketplace.CancellationPolicy = "retain_free"
	cfg.GitHubMarketplace.FreePlanName = "free"
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":42,"login":"Acme","type":"Organization"},"plan":{"id":1,"name":"community"}},"installation":{"id":99}}`)
	mac := hmac.New(sha256.New, []byte(cfg.GitHubMarketplace.WebhookSecret))
	_, _ = mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("X-GitHub-Event", "marketplace_purchase")
	request.Header.Set("X-GitHub-Delivery", "marketplace-1")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"processed"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if tenant, ok := store.ResolveInstallationTenant(context.Background(), 99); !ok || tenant == "" {
		t.Fatalf("installation binding=%q %v", tenant, ok)
	}
}

type marketplaceFailureStore struct {
	db.Backend
	getErr   error
	auditErr error
}

func (s marketplaceFailureStore) GetObject(ctx context.Context, tenantID, kind, id string, out any) (bool, error) {
	if s.getErr != nil && kind == "marketplace_account_index" {
		return false, s.getErr
	}
	return s.Backend.GetObject(ctx, tenantID, kind, id, out)
}

func (s marketplaceFailureStore) RecordAudit(ctx context.Context, event model.AuditEvent) error {
	if s.auditErr != nil && strings.HasPrefix(event.Action, "marketplace.") {
		return s.auditErr
	}
	return s.Backend.RecordAudit(ctx, event)
}

func marketplaceRequest(t *testing.T, handler http.Handler, secret, delivery string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	request.RemoteAddr = "203.0.113.10:1234"
	request.Header.Set("X-GitHub-Event", "marketplace_purchase")
	request.Header.Set("X-GitHub-Delivery", delivery)
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMarketplaceWebhookReturnsServerErrorForStoreFailure(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.GitHubMarketplace.Enabled = true
	cfg.GitHubMarketplace.WebhookSecret = "market-secret"
	cfg.GitHubMarketplace.AutoCreateTenant = true
	base, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	sentinel := errors.New("store unavailable")
	store := marketplaceFailureStore{Backend: base, getErr: sentinel}
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":42,"login":"Acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	response := marketplaceRequest(t, s.http.Handler, cfg.GitHubMarketplace.WebhookSecret, "marketplace-store-failure", body)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), sentinel.Error()) {
		t.Fatalf("internal storage error leaked to caller: %s", response.Body.String())
	}
}

func TestMarketplaceWebhookAcknowledgesPostCommitAuditFailure(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.GitHubMarketplace.Enabled = true
	cfg.GitHubMarketplace.WebhookSecret = "market-secret"
	cfg.GitHubMarketplace.AutoCreateTenant = true
	base, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	store := marketplaceFailureStore{Backend: base, auditErr: errors.New("audit unavailable")}
	s := New(cfg, store, analyzer.New("key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	body := []byte(`{"action":"purchased","marketplace_purchase":{"account":{"id":43,"login":"Acme","type":"Organization"},"plan":{"id":1,"name":"community"}}}`)
	response := marketplaceRequest(t, s.http.Handler, cfg.GitHubMarketplace.WebhookSecret, "marketplace-audit-failure", body)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"audit_recorded":false`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var stored any
	found, getErr := base.GetObject(context.Background(), model.DefaultTenantID, "marketplace_account_index", "43", &stored)
	if getErr != nil || !found {
		t.Fatalf("subscription not persisted: found=%v err=%v", found, getErr)
	}
}

func TestRepairAPIQueuesDraftPullRequest(t *testing.T) {
	cfg := config.Default()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "state.json")
	cfg.AdminToken = "root"
	cfg.DashboardSessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.AllowUnauthenticatedLocalhost = false
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	cfg.Repair.Enabled = true
	store, err := db.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := New(cfg, store, analyzer.New("test-key"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, token, err := store.CreateAPIKey(context.Background(), model.DefaultTenantID, "operator", model.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "repair-api", TenantID: model.DefaultTenantID, Repository: "acme/api", Attribution: model.AttributionCode, CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysisForTenant(context.Background(), model.DefaultTenantID, model.AnalysisInput{TenantID: model.DefaultTenantID, Repository: analysis.Repository}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	enhancement := model.LLMEnhancement{AnalysisID: analysis.ID, TenantID: model.DefaultTenantID, Patch: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-old\n+new\n", CreatedAt: time.Now().UTC()}
	if err := store.PutObject(context.Background(), model.DefaultTenantID, "llm_enhancement", analysis.ID, enhancement); err != nil {
		t.Fatal(err)
	}
	queued := doReq(t, server, http.MethodPost, "/api/v1/analyses/"+analysis.ID+"/repair/draft-pr", token, "", map[string]any{})
	if queued.Code != http.StatusAccepted || !strings.Contains(queued.Body.String(), "queued") {
		t.Fatalf("queued status=%d body=%s", queued.Code, queued.Body.String())
	}
	job, err := store.ClaimJob(context.Background(), "api-test")
	if err != nil || job == nil || job.Type != "repair.draft_pr" || job.TenantID != model.DefaultTenantID {
		t.Fatalf("job=%#v err=%v", job, err)
	}
	missing := doReq(t, server, http.MethodGet, "/api/v1/analyses/"+analysis.ID+"/repair", token, "", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("repair result status=%d body=%s", missing.Code, missing.Body.String())
	}
	result := model.RepairResult{TenantID: model.DefaultTenantID, AnalysisID: analysis.ID, Status: "draft_pr_created", PullRequestURL: "https://github.test/acme/api/pull/7", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := store.PutObject(context.Background(), model.DefaultTenantID, "repair_result", analysis.ID, result); err != nil {
		t.Fatal(err)
	}
	found := doReq(t, server, http.MethodGet, "/api/v1/analyses/"+analysis.ID+"/repair", token, "", nil)
	if found.Code != http.StatusOK || !strings.Contains(found.Body.String(), "draft_pr_created") {
		t.Fatalf("repair result status=%d body=%s", found.Code, found.Body.String())
	}
}

func TestRequestIDRejectsUnsafeOrOversizedValues(t *testing.T) {
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Observed-Request-ID", requestIDFrom(r))
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, supplied := range []string{"contains spaces", "../../logs", strings.Repeat("a", 129)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Request-ID", supplied)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		generated := rr.Header().Get("X-Request-ID")
		if generated == supplied || !validRequestID(generated) {
			t.Fatalf("unsafe request ID %q produced %q", supplied, generated)
		}
		if rr.Header().Get("Observed-Request-ID") != generated {
			t.Fatalf("context request ID does not match response header")
		}
	}

	const valid = "trace_01HZY7Y3:worker-2"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", valid)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Header().Get("X-Request-ID") != valid {
		t.Fatalf("valid request ID was replaced: %q", rr.Header().Get("X-Request-ID"))
	}
}

func TestDecodeJSONBodyRejectsTrailingAndOversizedInput(t *testing.T) {
	for name, tc := range map[string]struct {
		body  string
		limit int64
	}{
		"trailing":  {body: `{"name":"one"}{"name":"two"}`, limit: 1024},
		"oversized": {body: `{"name":"` + strings.Repeat("x", 128) + `"}`, limit: 32},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			recorder := httptest.NewRecorder()
			var value struct {
				Name string `json:"name"`
			}
			if err := decodeJSONBody(recorder, req, tc.limit, &value, false); err == nil {
				t.Fatal("invalid request body was accepted")
			}
		})
	}
}

func TestUnknownRoutesDoNotFallBackToDashboard(t *testing.T) {
	s, _, _ := testServer(t)
	api := doReq(t, s, http.MethodGet, "/api/v1/does-not-exist", "", "", nil)
	if api.Code != http.StatusNotFound {
		t.Fatalf("API status=%d body=%s", api.Code, api.Body.String())
	}
	if contentType := api.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("API content type=%q", contentType)
	}
	if !strings.Contains(api.Body.String(), `"status":404`) || !strings.Contains(api.Body.String(), `"error":"API route not found"`) {
		t.Fatalf("API body=%s", api.Body.String())
	}

	random := doReq(t, s, http.MethodGet, "/totally/random/path", "", "", nil)
	if random.Code != http.StatusNotFound {
		t.Fatalf("random status=%d body=%s", random.Code, random.Body.String())
	}
	if strings.Contains(strings.ToLower(random.Body.String()), "ci radar") {
		t.Fatalf("random route returned dashboard HTML: %s", random.Body.String())
	}

	root := doReq(t, s, http.MethodGet, "/", "", "", nil)
	if root.Code != http.StatusOK || !strings.Contains(strings.ToLower(root.Body.String()), "ci radar") {
		t.Fatalf("root status=%d body=%s", root.Code, root.Body.String())
	}
}

func TestServerBlocksRepeatedFailedTokenAttempts(t *testing.T) {
	s, _, _ := testServer(t)
	for i := 0; i < defaultAuthFailureThreshold; i++ {
		result := doReq(t, s, http.MethodGet, "/api/v1/status", "invalid-token", "", nil)
		if result.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status=%d body=%s", i+1, result.Code, result.Body.String())
		}
	}
	blocked := doReq(t, s, http.MethodGet, "/api/v1/status", "root-secret", "", nil)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	if blocked.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}
