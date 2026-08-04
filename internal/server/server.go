package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/connectors"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/insights"
	"ciradar/internal/llm"
	"ciradar/internal/marketplace"
	mcpserver "ciradar/internal/mcp"
	"ciradar/internal/model"
	"ciradar/internal/notifications"
	"ciradar/internal/providers"
	"ciradar/internal/similarity"
	"ciradar/internal/sso"
	"ciradar/internal/testintelligence"
	"ciradar/internal/testselection"
	"ciradar/internal/version"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	requestIDKey contextKey = "request_id"
)

type Server struct {
	cfg         config.Config
	store       db.Backend
	analyzer    *analyzer.Analyzer
	log         *slog.Logger
	http        *http.Server
	sso         *sso.Manager
	llm         *llm.Enhancer
	marketplace *marketplace.Service
	ipResolver  *clientIPResolver
	mcpRuntime  *mcpserver.Runtime
	mcpServer   *mcpserver.Server
}

func New(cfg config.Config, store db.Backend, a *analyzer.Analyzer, log *slog.Logger) *Server {
	runtime := mcpserver.NewRuntime()
	s := &Server{cfg: cfg, store: store, analyzer: a, log: log, llm: llm.New(cfg.LLM, store), marketplace: marketplace.New(cfg.GitHubMarketplace, store), ipResolver: newClientIPResolver(cfg.TrustedProxyCIDRs), mcpRuntime: runtime}
	s.mcpServer = &mcpserver.Server{Store: store, Semantic: cfg.Semantic, LLM: cfg.LLM, Repair: cfg.Repair, Runtime: runtime}
	if cfg.SSO.Enabled {
		mgr, err := sso.New(cfg.SSO)
		if err != nil {
			log.Error("SSO initialization failed", "error", err)
		} else {
			s.sso = mgr
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.dashboardPage)
	mux.HandleFunc("GET /assets/dashboard.css", s.dashboardCSS)
	mux.HandleFunc("GET /assets/dashboard.js", s.dashboardJS)
	mux.HandleFunc("GET /source", s.sourcePage)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/saml/metadata", s.authSAMLMetadata)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("POST /auth/callback", s.authCallback)
	mux.HandleFunc("GET /auth/logout", s.authLogout)
	mux.HandleFunc("POST /auth/token", s.authToken)
	mux.HandleFunc("GET /api/v1/auth/me", s.require(model.RoleViewer, s.authMe))
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/status", s.require(model.RoleViewer, s.status))
	mux.HandleFunc("GET /api/v1/dashboard", s.require(model.RoleViewer, s.dashboardData))
	mux.HandleFunc("GET /api/v1/incidents", s.require(model.RoleViewer, s.incidents))
	mux.HandleFunc("POST /api/v1/incidents/{fingerprint}/acknowledge", s.require(model.RoleOperator, s.acknowledgeIncident))
	mux.HandleFunc("POST /api/v1/incidents/{fingerprint}/resolve", s.require(model.RoleOperator, s.resolveIncident))
	mux.HandleFunc("POST /api/v1/incidents/{fingerprint}/reopen", s.require(model.RoleOperator, s.reopenIncident))
	mux.HandleFunc("GET /api/v1/providers", s.require(model.RoleViewer, s.providerStatuses))
	mux.HandleFunc("GET /api/v1/analyses", s.require(model.RoleViewer, s.analyses))
	mux.HandleFunc("GET /api/v1/analyses/{id}", s.require(model.RoleViewer, s.analysis))
	mux.HandleFunc("POST /api/v1/analyze", s.require(model.RoleOperator, s.analyze))
	mux.HandleFunc("POST /api/v1/analyses/{id}/feedback", s.require(model.RoleViewer, s.analysisFeedback))
	mux.HandleFunc("GET /api/v1/analyses/{id}/llm", s.require(model.RoleViewer, s.getLLMEnhancement))
	mux.HandleFunc("POST /api/v1/analyses/{id}/llm", s.require(model.RoleOperator, s.createLLMEnhancement))
	mux.HandleFunc("GET /api/v1/analyses/{id}/repair", s.require(model.RoleViewer, s.getRepairResult))
	mux.HandleFunc("POST /api/v1/analyses/{id}/repair/draft-pr", s.require(model.RoleOperator, s.requestDraftRepairPR))
	mux.HandleFunc("GET /api/v1/analyses/{id}/similar", s.require(model.RoleViewer, s.similarAnalyses))
	mux.HandleFunc("GET /api/v1/feedback", s.require(model.RoleViewer, s.feedbackList))
	mux.HandleFunc("POST /api/v1/tests/junit", s.require(model.RoleOperator, s.ingestTestReport))
	mux.HandleFunc("POST /api/v1/tests/report", s.require(model.RoleOperator, s.ingestTestReport))
	mux.HandleFunc("GET /api/v1/tests", s.require(model.RoleViewer, s.testCases))
	mux.HandleFunc("GET /api/v1/tests/quarantines", s.require(model.RoleViewer, s.testQuarantines))
	mux.HandleFunc("POST /api/v1/tests/select", s.require(model.RoleViewer, s.selectTests))
	mux.HandleFunc("GET /api/v1/tests/impact", s.require(model.RoleViewer, s.getTestImpact))
	mux.HandleFunc("PUT /api/v1/tests/impact", s.require(model.RoleOperator, s.putTestImpact))
	mux.HandleFunc("POST /api/v1/tests/coverage", s.require(model.RoleOperator, s.putTestCoverage))
	mux.HandleFunc("GET /api/v1/tests/quarantine-manifest", s.require(model.RoleViewer, s.testQuarantineManifest))
	mux.HandleFunc("POST /api/v1/tests/{key}/quarantine", s.require(model.RoleOperator, s.quarantineTest))
	mux.HandleFunc("DELETE /api/v1/tests/{key}/quarantine", s.require(model.RoleOperator, s.unquarantineTest))
	mux.HandleFunc("POST /api/v1/deployments", s.require(model.RoleOperator, s.recordDeployment))
	mux.HandleFunc("GET /api/v1/metrics/dora", s.require(model.RoleViewer, s.doraMetrics))
	mux.HandleFunc("GET /api/v1/metrics/usage", s.require(model.RoleViewer, s.usageMetrics))
	mux.HandleFunc("GET /api/v1/metrics/trends", s.require(model.RoleViewer, s.trendMetrics))

	mux.HandleFunc("POST /api/v1/baselines", s.require(model.RoleOperator, s.baseline))
	mux.HandleFunc("GET /api/v1/notifications/deliveries", s.require(model.RoleViewer, s.notificationDeliveries))
	mux.HandleFunc("GET /api/v1/audit", s.require(model.RoleAdmin, s.auditEvents))
	mux.HandleFunc("GET /api/v1/repositories", s.require(model.RoleViewer, s.repositoryProfiles))
	mux.HandleFunc("PUT /api/v1/repositories/{owner}/{repo}", s.require(model.RoleAdmin, s.upsertRepositoryProfile))
	mux.HandleFunc("GET /api/v1/api-keys", s.require(model.RoleAdmin, s.apiKeys))
	mux.HandleFunc("POST /api/v1/api-keys", s.require(model.RoleAdmin, s.createAPIKey))
	mux.HandleFunc("DELETE /api/v1/api-keys/{id}", s.require(model.RoleAdmin, s.revokeAPIKey))
	mux.HandleFunc("GET /api/v1/tenants", s.requireRoot(s.tenants))
	mux.HandleFunc("POST /api/v1/tenants", s.requireRoot(s.createTenant))
	mux.HandleFunc("PATCH /api/v1/tenants/{id}", s.requireRoot(s.updateTenant))
	mux.HandleFunc("GET /api/v1/github/installations", s.requireRoot(s.installationBindings))
	mux.HandleFunc("GET /api/v1/marketplace/subscription", s.require(model.RoleAdmin, s.marketplaceSubscription))
	mux.HandleFunc("GET /api/v1/marketplace/subscriptions", s.requireRoot(s.marketplaceSubscriptions))
	mux.HandleFunc("POST /api/v1/github/installations/{id}/bind", s.requireRoot(s.bindInstallation))
	mux.HandleFunc("DELETE /api/v1/github/installations/{id}", s.requireRoot(s.unbindInstallation))
	mux.HandleFunc("GET /metrics", s.require(model.RoleViewer, s.metrics))
	mux.HandleFunc("POST /mcp", s.require(model.RoleViewer, s.mcp))
	mux.HandleFunc("GET /mcp", s.mcpGet)
	mux.HandleFunc("DELETE /mcp", s.require(model.RoleViewer, s.mcpDelete))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.mcpProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.oauthAuthorizationServer)
	mux.HandleFunc("POST /oauth/register", s.oauthRegister)
	mux.HandleFunc("GET /oauth/authorize", s.oauthAuthorize)
	mux.HandleFunc("POST /oauth/token", s.oauthToken)
	mux.HandleFunc("POST /oauth/revoke", s.oauthRevoke)
	mux.HandleFunc("POST /webhooks/github", s.githubWebhook)
	mux.HandleFunc("POST /webhooks/github/marketplace", s.githubMarketplaceWebhook)
	mux.HandleFunc("POST /webhooks/gitlab", s.ciWebhook("gitlab"))
	mux.HandleFunc("POST /webhooks/buildkite", s.ciWebhook("buildkite"))
	mux.HandleFunc("POST /webhooks/circleci", s.ciWebhook("circleci"))
	mux.HandleFunc("POST /webhooks/jenkins", s.ciWebhook("jenkins"))
	mux.HandleFunc("POST /webhooks/azuredevops", s.ciWebhook("azuredevops"))
	mux.HandleFunc("POST /webhooks/bitrise", s.ciWebhook("bitrise"))
	mux.HandleFunc("POST /webhooks/teamcity", s.ciWebhook("teamcity"))
	mux.HandleFunc("POST /webhooks/travis", s.ciWebhook("travis"))
	mux.HandleFunc("POST /webhooks/codebuild", s.ciWebhook("codebuild"))
	mux.HandleFunc("POST /webhooks/bitbucket", s.ciWebhook("bitbucket"))
	mux.HandleFunc("POST /webhooks/drone", s.ciWebhook("drone"))
	mux.HandleFunc("POST /webhooks/semaphore", s.ciWebhook("semaphore"))
	mux.HandleFunc("POST /webhooks/appveyor", s.ciWebhook("appveyor"))
	mux.HandleFunc("POST /webhooks/cloudbuild", s.ciWebhook("cloudbuild"))
	mux.HandleFunc("POST /chatops/slack", s.slackChatOps)
	mux.HandleFunc("POST /chatops/teams", s.teamsChatOps)
	h := requestID(securityHeaders(cfg.PublicBaseURL, s.ipResolver, csrfGuard(cfg, logging(log, rateLimit(newRateLimiter(600, time.Minute), s.ipResolver, mux)))))
	s.http = &http.Server{Addr: cfg.ListenAddress, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	return s
}

func (s *Server) sourcePage(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.SourceURL) != "" {
		http.Redirect(w, r, s.cfg.SourceURL, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<!doctype html><html><head><meta charset=utf-8><title>CI Radar source</title><link rel=stylesheet href=/assets/dashboard.css></head><body><main><section class=panel><h1>CI Radar source code</h1><p>This deployment runs free software licensed under AGPL-3.0-or-later.</p><p>The corresponding source archive is distributed beside the server binary. The administrator should set <code>source_url</code> to the exact public source revision for this deployment.</p><p>Version: "+version.Version+" · Commit: "+version.Commit+"</p></section></main></body></html>")
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("CI Radar server listening", "address", s.cfg.ListenAddress, "github_configured", s.cfg.GitHubConfigured(), "dashboard", s.cfg.DashboardEnabled)
		errCh <- s.http.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) dashboardPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DashboardEnabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, dashboardHTML)
}

func (s *Server) dashboardCSS(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DashboardEnabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, dashboardCSS)
}

func (s *Server) dashboardJS(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DashboardEnabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, dashboardJS)
}

func (s *Server) authSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if s.sso == nil {
		http.NotFound(w, r)
		return
	}
	s.sso.SAMLMetadata(w, r)
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if s.sso == nil {
		http.NotFound(w, r)
		return
	}
	s.sso.Login(w, r)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	if s.sso == nil {
		http.NotFound(w, r)
		return
	}
	s.sso.Callback(w, r)
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	clearDashboardSession(w, s.cfg.DashboardCookieSecure)
	if s.sso == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.sso.Logout(w, r)
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": p.TenantID, "name": p.Name, "role": p.Role, "root": p.Root, "sso_enabled": s.cfg.SSO.Enabled, "sso_mode": s.cfg.SSO.Mode})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "version": version.Version, "time": time.Now().UTC()})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if _, err := s.store.Stats(r.Context()); err != nil {
		writeError(w, 503, "storage not ready")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ready"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	st, err := s.store.StatsForTenant(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	providerList, _ := s.store.ListProviderStatuses(r.Context())
	feedback, _ := s.store.FeedbackMetrics(r.Context(), p.TenantID)
	tests, _ := s.store.ListTestCaseStats(r.Context(), p.TenantID, "", "", 5000)
	flaky, quarantined := 0, 0
	for _, tc := range tests {
		if tc.Classification == "flaky" {
			flaky++
		}
		if tc.Quarantined {
			quarantined++
		}
	}
	connectorsEnabled := []string{}
	for _, co := range s.cfg.Connectors {
		if co.Enabled {
			connectorsEnabled = append(connectorsEnabled, co.Provider)
		}
	}
	writeJSON(w, 200, map[string]any{"version": version.Version, "commit": version.Commit, "tenant_id": p.TenantID, "role": p.Role, "database_driver": s.cfg.DatabaseDriver, "github_configured": s.cfg.GitHubConfigured(), "connectors_enabled": connectorsEnabled, "mcp_enabled": true, "test_intelligence_enabled": s.cfg.TestIntelligence.Enabled, "automatic_retry_enabled": s.cfg.AutomaticRetryEnabled, "cross_tenant_correlation": s.cfg.CrossTenantCorrelation, "store_raw_logs": s.cfg.StoreRawLogs, "notifications_enabled": s.cfg.Notifications.Enabled, "notification_channels": len(s.cfg.Notifications.Channels), "stats": st, "feedback": feedback, "tests": map[string]int{"tracked": len(tests), "flaky": flaky, "quarantined": quarantined}, "providers": providerList})
}

func (s *Server) dashboardData(w http.ResponseWriter, r *http.Request) {
	dur := 7 * 24 * time.Hour
	if raw := r.URL.Query().Get("range"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= time.Hour && d <= 365*24*time.Hour {
			dur = d
		}
	}
	tenantID := principal(r).TenantID
	since := time.Now().UTC().Add(-dur)
	until := time.Now().UTC()
	d, err := s.store.Dashboard(r.Context(), tenantID, since)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	dora, _ := insights.DORA(r.Context(), s.store, tenantID, r.URL.Query().Get("environment"), since, until)
	usage, _ := insights.Usage(r.Context(), s.store, tenantID, since, until)
	trends, _ := insights.Trends(r.Context(), s.store, tenantID, since, until)
	d.DORA = dora
	d.Usage = usage
	d.DailyCost = trends["cost"]
	writeJSON(w, 200, d)
}

func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var ev model.DeploymentEvent
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ev); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	ev.TenantID = p.TenantID
	if strings.TrimSpace(ev.Repository) == "" || strings.TrimSpace(ev.Environment) == "" || strings.TrimSpace(ev.CommitSHA) == "" {
		writeError(w, 400, "repository, environment, and commit_sha are required")
		return
	}
	out, err := insights.RecordDeployment(r.Context(), s.store, ev)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	s.audit(r, "deployment.record", "deployment", out.ID, map[string]string{"repository": out.Repository, "environment": out.Environment, "status": out.Status})
	writeJSON(w, 201, out)
}

func metricRange(r *http.Request) (time.Time, time.Time) {
	until := time.Now().UTC()
	if v := r.URL.Query().Get("until"); v != "" {
		if t, e := time.Parse(time.RFC3339, v); e == nil {
			until = t
		}
	}
	since := until.Add(-30 * 24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if t, e := time.Parse(time.RFC3339, v); e == nil {
			since = t
		}
	}
	return since, until
}
func (s *Server) doraMetrics(w http.ResponseWriter, r *http.Request) {
	since, until := metricRange(r)
	m, e := insights.DORA(r.Context(), s.store, principal(r).TenantID, r.URL.Query().Get("environment"), since, until)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, m)
}
func (s *Server) usageMetrics(w http.ResponseWriter, r *http.Request) {
	since, until := metricRange(r)
	m, e := insights.Usage(r.Context(), s.store, principal(r).TenantID, since, until)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, m)
}
func (s *Server) trendMetrics(w http.ResponseWriter, r *http.Request) {
	since, until := metricRange(r)
	m, e := insights.Trends(r.Context(), s.store, principal(r).TenantID, since, until)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"since": since, "until": until, "series": m})
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListIncidentsForTenant(r.Context(), principal(r).TenantID, limit, r.URL.Query().Get("state"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"incidents": items})
}
func (s *Server) providerStatuses(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListProviderStatuses(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"providers": items})
}
func (s *Server) analyses(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListAnalysesForTenant(r.Context(), principal(r).TenantID, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"analyses": items})
}
func (s *Server) analysis(w http.ResponseWriter, r *http.Request) {
	item, err := s.store.GetAnalysisForTenant(r.Context(), principal(r).TenantID, r.PathValue("id"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if item == nil {
		writeError(w, 404, "analysis not found")
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) requestDraftRepairPR(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Repair.Enabled {
		writeError(w, http.StatusServiceUnavailable, "repair is disabled")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "analysis ID is required")
		return
	}
	p := principal(r)
	analysis, err := s.store.GetAnalysisForTenant(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if analysis == nil {
		writeError(w, http.StatusNotFound, "analysis not found")
		return
	}
	var enhancement model.LLMEnhancement
	found, err := s.store.GetObject(r.Context(), p.TenantID, "llm_enhancement", id, &enhancement)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found || strings.TrimSpace(enhancement.Patch) == "" {
		writeError(w, http.StatusConflict, "analysis has no repair patch")
		return
	}
	if err := s.store.EnqueueForTenant(r.Context(), p.TenantID, "repair.draft_pr", map[string]any{"tenant_id": p.TenantID, "analysis_id": id}, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "repair.draft_pr_requested", "analysis", id, nil)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued", "analysis_id": id})
}

func (s *Server) getRepairResult(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "analysis ID is required")
		return
	}
	var result model.RepairResult
	found, err := s.store.GetObject(r.Context(), principal(r).TenantID, "repair_result", id, &result)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "repair result not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getLLMEnhancement(w http.ResponseWriter, r *http.Request) {
	if s.llm == nil || !s.llm.Enabled() {
		writeError(w, http.StatusNotFound, "LLM enhancement is disabled")
		return
	}
	item, err := s.llm.Get(r.Context(), principal(r).TenantID, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "LLM enhancement not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createLLMEnhancement(w http.ResponseWriter, r *http.Request) {
	if s.llm == nil || !s.llm.Enabled() {
		writeError(w, http.StatusBadRequest, "LLM enhancement is disabled")
		return
	}
	p := principal(r)
	analysis, err := s.store.GetAnalysisForTenant(r.Context(), p.TenantID, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if analysis == nil {
		writeError(w, http.StatusNotFound, "analysis not found")
		return
	}
	var body struct {
		ChangedFiles []string `json:"changed_files"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body)
	result, err := s.llm.Enhance(r.Context(), *analysis, body.ChangedFiles)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "analysis.llm_enhance", "analysis", analysis.ID, map[string]string{"model": result.Model})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) analysisFeedback(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var body struct {
		Verdict     string            `json:"verdict"`
		ActualCause model.Attribution `json:"actual_cause"`
		Comment     string            `json:"comment"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	actor := p.Name
	if actor == "" {
		actor = p.APIKeyID
	}
	if actor == "" {
		actor = "root"
	}
	f, err := s.store.UpsertDiagnosisFeedback(r.Context(), model.DiagnosisFeedback{TenantID: p.TenantID, AnalysisID: r.PathValue("id"), Verdict: body.Verdict, ActualCause: body.ActualCause, Comment: body.Comment, Actor: actor})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "analysis.feedback", "analysis", r.PathValue("id"), map[string]string{"verdict": f.Verdict, "actual_cause": string(f.ActualCause)})
	writeJSON(w, 200, f)
}
func (s *Server) feedbackList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListDiagnosisFeedback(r.Context(), principal(r).TenantID, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	metrics, _ := s.store.FeedbackMetrics(r.Context(), principal(r).TenantID)
	writeJSON(w, 200, map[string]any{"feedback": items, "metrics": metrics})
}
func (s *Server) ingestTestReport(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	q := r.URL.Query()
	runID, _ := strconv.ParseInt(q.Get("run_id"), 10, 64)
	format := firstNonEmpty(q.Get("format"), "junit")
	obs, err := testintelligence.ParseReport(format, http.MaxBytesReader(w, r.Body, 128<<20), testintelligence.Metadata{TenantID: p.TenantID, Repository: q.Get("repository"), Workflow: q.Get("workflow"), Job: q.Get("job"), RunID: runID, CommitSHA: q.Get("commit_sha"), Branch: q.Get("branch"), Framework: firstNonEmpty(q.Get("framework"), format), OccurredAt: time.Now().UTC()})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	stats, err := s.store.RecordTestObservations(r.Context(), p.TenantID, obs)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	auto := []model.TestQuarantine{}
	if s.cfg.TestIntelligence.Enabled && s.cfg.TestIntelligence.AutoQuarantine {
		owner := "ci-radar"
		if profile, _ := s.store.GetRepositoryProfile(r.Context(), p.TenantID, q.Get("repository")); profile != nil {
			if profile.Owner != "" {
				owner = profile.Owner
			} else if profile.Team != "" {
				owner = profile.Team
			}
		}
		for _, st := range stats {
			if st.Classification != "flaky" || st.TotalRuns < s.cfg.TestIntelligence.AutoQuarantineMinRuns || st.FlakeScore < s.cfg.TestIntelligence.AutoQuarantineMinScore || st.Quarantined {
				continue
			}
			qu, e := s.store.SetTestQuarantine(r.Context(), model.TestQuarantine{TenantID: p.TenantID, TestKey: st.TestKey, Reason: "Automatic quarantine: repeated pass/fail transitions", Owner: owner, CreatedBy: "system", ExpiresAt: time.Now().UTC().Add(s.cfg.TestIntelligence.AutoQuarantineDuration)})
			if e == nil {
				auto = append(auto, qu)
				_ = s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: p.TenantID, Actor: "system", Role: model.RoleOperator, Action: "test.auto_quarantine", Resource: "test", ResourceID: st.TestKey, Metadata: map[string]string{"repository": st.Repository, "score": fmt.Sprintf("%.1f", st.FlakeScore)}})
			}
		}
	}
	for _, st := range stats {
		if st.Classification == "flaky" && !st.Quarantined {
			_ = s.store.EnqueueForTenant(r.Context(), p.TenantID, "notify.event", notifications.FlakyTestEvent(st, s.cfg.PublicBaseURL), time.Now().UTC())
		}
	}
	s.audit(r, "tests.ingest", "repository", q.Get("repository"), map[string]string{"tests": strconv.Itoa(len(obs)), "auto_quarantined": strconv.Itoa(len(auto))})
	writeJSON(w, 200, map[string]any{"ingested": len(obs), "updated": stats, "auto_quarantined": auto})
}
func (s *Server) testCases(w http.ResponseWriter, r *http.Request) {
	l, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListTestCaseStats(r.Context(), principal(r).TenantID, r.URL.Query().Get("repository"), r.URL.Query().Get("classification"), l)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tests": items})
}
func (s *Server) testQuarantines(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListTestQuarantines(r.Context(), principal(r).TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"quarantines": items})
}
func (s *Server) testQuarantineManifest(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListTestQuarantines(r.Context(), principal(r).TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	keys := make([]string, 0, len(items))
	for _, q := range items {
		if q.Active {
			keys = append(keys, q.TestKey)
		}
	}
	writeJSON(w, 200, map[string]any{"version": 1, "generated_at": time.Now().UTC(), "test_keys": keys, "quarantines": items})
}

func (s *Server) quarantineTest(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var b struct {
		Reason    string    `json:"reason"`
		Owner     string    `json:"owner"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	actor := p.Name
	if actor == "" {
		actor = p.APIKeyID
	}
	q, err := s.store.SetTestQuarantine(r.Context(), model.TestQuarantine{TenantID: p.TenantID, TestKey: r.PathValue("key"), Reason: b.Reason, Owner: b.Owner, CreatedBy: actor, ExpiresAt: b.ExpiresAt})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "test.quarantine", "test", q.TestKey, map[string]string{"owner": q.Owner, "reason": q.Reason})
	writeJSON(w, 200, q)
}
func (s *Server) unquarantineTest(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if err := s.store.RemoveTestQuarantine(r.Context(), p.TenantID, r.PathValue("key")); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "test.unquarantine", "test", r.PathValue("key"), nil)
	w.WriteHeader(204)
}
func firstNonEmpty(v, d string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return d
}

func (s *Server) similarAnalyses(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, e := similarity.FindConfigured(r.Context(), s.store, principal(r).TenantID, r.PathValue("id"), limit, s.cfg.Semantic, s.cfg.LLM)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"similar": items})
}
func (s *Server) selectTests(w http.ResponseWriter, r *http.Request) {
	var req model.TestSelectionRequest
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); e != nil {
		writeError(w, 400, "invalid JSON: "+e.Error())
		return
	}
	if strings.TrimSpace(req.Repository) == "" {
		writeError(w, 400, "repository is required")
		return
	}
	out, e := testselection.Select(r.Context(), s.store, principal(r).TenantID, req)
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) getTestImpact(w http.ResponseWriter, r *http.Request) {
	repository := strings.TrimSpace(r.URL.Query().Get("repository"))
	if repository == "" {
		writeError(w, http.StatusBadRequest, "repository is required")
		return
	}
	graph, ok, err := testselection.LoadGraph(r.Context(), s.store, principal(r).TenantID, repository)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "impact graph not found")
		return
	}
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) putTestImpact(w http.ResponseWriter, r *http.Request) {
	var graph model.ImpactGraph
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&graph); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := testselection.SaveGraph(r.Context(), s.store, principal(r).TenantID, graph); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "test_impact.update", "repository", graph.Repository, map[string]string{"files": strconv.Itoa(len(graph.LanguageFiles)), "tests": strconv.Itoa(len(graph.TestFiles))})
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) putTestCoverage(w http.ResponseWriter, r *http.Request) {
	var input model.TestCoverageInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	graph, err := testselection.MergeCoverage(r.Context(), s.store, principal(r).TenantID, input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "test_coverage.update", "repository", input.Repository, map[string]string{"tests": strconv.Itoa(len(input.Coverage))})
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) notificationDeliveries(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListNotificationDeliveriesForTenant(r.Context(), principal(r).TenantID, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deliveries": items})
}
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListAudit(r.Context(), principal(r).TenantID, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"events": items})
}
func (s *Server) repositoryProfiles(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListRepositoryProfiles(r.Context(), principal(r).TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"repositories": items})
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxLogBytes+1<<20)
	defer body.Close()
	var in model.AnalysisInput
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Log) == "" {
		writeError(w, 400, "log is required")
		return
	}
	p := principal(r)
	in.TenantID = p.TenantID
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	if in.Organization == "" && strings.Contains(in.Repository, "/") {
		in.Organization = strings.SplitN(in.Repository, "/", 2)[0]
	}
	initial := s.analyzer.Analyze(in, analyzer.Context{})
	corr, err := s.store.CorrelationForTenant(r.Context(), p.TenantID, initial.Fingerprint, in.Repository, in.Organization, time.Now().UTC().Add(-s.cfg.IncidentWindow), s.cfg.CrossTenantCorrelation)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	prev, _ := s.store.LastSuccessfulEnvironmentForTenant(r.Context(), p.TenantID, in.Repository, in.Workflow, in.Job)
	result := s.analyzer.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories, CrossOrgCount: corr.Organizations, RecentOccurrences: corr.Occurrences, ProviderIncident: s.providerIncident(r.Context(), initial.Provider), PreviousEnvironment: prev})
	if err := s.store.RecordAnalysisForTenant(r.Context(), p.TenantID, in, result, s.cfg.StoreRedactedExcerpts, s.cfg.StoreRawLogs); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if s.cfg.Notifications.Enabled {
		_ = s.store.EnqueueForTenant(r.Context(), in.TenantID, "notify.event", notifications.AnalysisEvent(in, result, s.cfg.PublicBaseURL), time.Now().UTC())
	}
	incident, created, _ := s.maybeIncident(r.Context(), p.TenantID, in.Repository, result, corr)
	if incident != nil && s.cfg.Notifications.Enabled {
		kind := "incident_updated"
		if created {
			kind = "incident_opened"
		}
		_ = s.store.EnqueueForTenant(r.Context(), incident.TenantID, "notify.event", notifications.IncidentEvent(kind, *incident, s.cfg.PublicBaseURL), time.Now().UTC())
	}
	s.audit(r, "analysis.create", "analysis", result.ID, map[string]string{"repository": in.Repository, "category": string(result.Category)})
	writeJSON(w, 200, result)
}

func (s *Server) baseline(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxLogBytes+1<<20)
	defer body.Close()
	var in model.AnalysisInput
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Repository) == "" || strings.TrimSpace(in.Workflow) == "" || strings.TrimSpace(in.Job) == "" || strings.TrimSpace(in.Log) == "" {
		writeError(w, 400, "repository, workflow, job, and log are required")
		return
	}
	env := analyzer.ExtractEnvironment(analyzer.NewRedactor().Redact(in.Log))
	if env.RunnerOS == "" && env.RunnerImage == "" && len(env.ToolVersions) == 0 && len(env.ActionVersions) == 0 && len(env.ContainerRefs) == 0 {
		writeError(w, 422, "no environment information could be extracted")
		return
	}
	p := principal(r)
	if err := s.store.RecordSuccessfulEnvironmentForTenant(r.Context(), p.TenantID, in.Repository, in.Workflow, in.Job, in.CommitSHA, env, time.Now().UTC()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	s.audit(r, "baseline.create", "repository", in.Repository, nil)
	writeJSON(w, 201, map[string]any{"status": "baseline_saved", "environment": env})
}

func (s *Server) acknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	s.changeIncidentState(w, r, "acknowledged")
}
func (s *Server) resolveIncident(w http.ResponseWriter, r *http.Request) {
	s.changeIncidentState(w, r, "resolved")
}
func (s *Server) reopenIncident(w http.ResponseWriter, r *http.Request) {
	s.changeIncidentState(w, r, "open")
}
func (s *Server) changeIncidentState(w http.ResponseWriter, r *http.Request, state string) {
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body)
	p := principal(r)
	inc, err := s.store.UpdateIncidentState(r.Context(), p.TenantID, r.PathValue("fingerprint"), state, p.Name, body.Note)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if inc == nil {
		writeError(w, 404, "incident not found")
		return
	}
	kind := "incident_updated"
	if state == "resolved" {
		kind = "incident_resolved"
	}
	if s.cfg.Notifications.Enabled {
		_ = s.store.EnqueueForTenant(r.Context(), inc.TenantID, "notify.event", notifications.IncidentEvent(kind, *inc, s.cfg.PublicBaseURL), time.Now().UTC())
	}
	s.audit(r, "incident."+state, "incident", inc.ID, map[string]string{"note": body.Note})
	writeJSON(w, 200, inc)
}

func (s *Server) upsertRepositoryProfile(w http.ResponseWriter, r *http.Request) {
	var p model.RepositoryProfile
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	p.TenantID = principal(r).TenantID
	p.Repository = r.PathValue("owner") + "/" + r.PathValue("repo")
	configuredChannels := map[string]struct{}{}
	for _, channel := range s.cfg.Notifications.Channels {
		configuredChannels[strings.ToLower(channel.Name)] = struct{}{}
	}
	for _, channel := range p.NotificationChannels {
		if _, ok := configuredChannels[strings.ToLower(strings.TrimSpace(channel))]; !ok {
			writeError(w, 400, fmt.Sprintf("notification channel %q is not configured", channel))
			return
		}
	}
	out, err := s.store.UpsertRepositoryProfile(r.Context(), p)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "repository.update", "repository", p.Repository, nil)
	writeJSON(w, 200, out)
}
func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListAPIKeys(r.Context(), principal(r).TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"api_keys": items})
}
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string     `json:"name"`
		Role model.Role `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	p := principal(r)
	key, token, err := s.store.CreateAPIKey(r.Context(), p.TenantID, body.Name, body.Role)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "api_key.create", "api_key", key.ID, map[string]string{"role": string(key.Role)})
	writeJSON(w, 201, map[string]any{"api_key": key, "token": token, "warning": "This token is shown once. Store it securely."})
}
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if err := s.store.RevokeAPIKey(r.Context(), p.TenantID, r.PathValue("id")); err != nil {
		writeError(w, 404, err.Error())
		return
	}
	s.audit(r, "api_key.revoke", "api_key", r.PathValue("id"), nil)
	w.WriteHeader(204)
}
func (s *Server) tenants(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListTenants(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"tenants": items})
}
func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	t, err := s.store.CreateTenant(r.Context(), body.ID, body.Name)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "tenant.create", "tenant", t.ID, nil)
	writeJSON(w, 201, t)
}
func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil || body.Enabled == nil {
		writeError(w, 400, "enabled is required")
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.PathValue("id")))
	if err := s.store.SetTenantEnabled(r.Context(), id, *body.Enabled); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	tenant, _ := s.store.GetTenant(r.Context(), id)
	s.audit(r, "tenant.update", "tenant", id, map[string]string{"enabled": strconv.FormatBool(*body.Enabled)})
	writeJSON(w, 200, tenant)
}

func (s *Server) installationBindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"bindings": s.store.ListInstallationBindings(r.Context())})
}
func (s *Server) bindInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid installation id")
		return
	}
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := s.store.BindInstallation(r.Context(), body.TenantID, id); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	s.audit(r, "github_installation.bind", "github_installation", r.PathValue("id"), map[string]string{"tenant_id": body.TenantID})
	writeJSON(w, 200, map[string]any{"installation_id": id, "tenant_id": body.TenantID})
}

func (s *Server) unbindInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, 400, "invalid installation id")
		return
	}
	if err := s.store.UnbindInstallation(r.Context(), id); err != nil {
		writeError(w, 404, err.Error())
		return
	}
	s.audit(r, "github_installation.unbind", "github_installation", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.StatsForTenant(r.Context(), principal(r).TenantID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	feedback, _ := s.store.FeedbackMetrics(r.Context(), principal(r).TenantID)
	tests, _ := s.store.ListTestCaseStats(r.Context(), principal(r).TenantID, "", "", 5000)
	flaky, quarantined := 0, 0
	for _, tc := range tests {
		if tc.Classification == "flaky" {
			flaky++
		}
		if tc.Quarantined {
			quarantined++
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "ciradar_analyses_total %d\nciradar_incidents_open %d\nciradar_jobs_queued %d\nciradar_repositories %d\nciradar_notification_failures_total %d\nciradar_feedback_total %d\nciradar_feedback_precision_percent %.2f\nciradar_tests_tracked %d\nciradar_tests_flaky %d\nciradar_tests_quarantined %d\n", st.Analyses, st.OpenIncidents, st.QueuedJobs, st.Repositories, st.NotificationFailures, feedback.Total, feedback.PrecisionPercent, len(tests), flaky, quarantined)
}

func (s *Server) mcpGet(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("MCP-Session-Id")) == "" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p, authenticated := s.authenticate(r)
	if !authenticated || roleRank(p.Role) < roleRank(model.RoleViewer) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
	if !s.validMCPOrigin(r) {
		writeError(w, http.StatusForbidden, "invalid MCP Origin")
		return
	}
	sessionID := strings.TrimSpace(r.Header.Get("MCP-Session-Id"))
	value, ok := s.mcpRuntime.Session(sessionID, p)
	if !ok {
		writeError(w, http.StatusBadRequest, "valid MCP-Session-Id is required")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("MCP-Session-Id", sessionID)
	_, _ = io.WriteString(w, "event: endpoint\ndata: /mcp\n\n")
	flusher.Flush()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case payload, open := <-value.Events:
			if !open {
				return
			}
			encoded, _ := json.Marshal(string(payload))
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", encoded)
			flusher.Flush()
		case <-ticker.C:
			_, _ = io.WriteString(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) mcpDelete(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	sessionID := strings.TrimSpace(r.Header.Get("MCP-Session-Id"))
	if _, ok := s.mcpRuntime.Session(sessionID, p); !ok {
		writeError(w, http.StatusBadRequest, "valid MCP-Session-Id is required")
		return
	}
	s.mcpRuntime.CloseSession(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mcpProtectedResource(w http.ResponseWriter, r *http.Request) {
	resource := strings.TrimRight(s.cfg.PublicBaseURL, "/") + "/mcp"
	if strings.TrimSpace(s.cfg.PublicBaseURL) == "" {
		scheme := "http"
		if requestIsHTTPS(r, s.cfg.PublicBaseURL, s.ipResolver) {
			scheme = "https"
		}
		resource = scheme + "://" + r.Host + "/mcp"
	}
	servers := []string{s.requestBaseURL(r)}
	writeJSON(w, http.StatusOK, map[string]any{"resource": resource, "authorization_servers": servers, "bearer_methods_supported": []string{"header"}, "scopes_supported": []string{"ciradar.read", "ciradar.write"}})
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if !s.validMCPOrigin(r) {
		writeError(w, http.StatusForbidden, "invalid MCP Origin")
		return
	}
	if pv := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); pv != "" && pv != "2025-03-26" && pv != "2025-06-18" && pv != "2025-11-25" {
		writeError(w, http.StatusBadRequest, "unsupported MCP protocol version")
		return
	}
	var req mcpserver.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, mcpserver.Response{JSONRPC: "2.0", Error: &mcpserver.RPCError{Code: -32700, Message: "parse error"}})
		return
	}
	p := principal(r)
	if mcpWriteRequest(req) && !principalHasScope(p, "ciradar.write") {
		writeError(w, http.StatusForbidden, "OAuth token does not include ciradar.write")
		return
	}
	sessionID := strings.TrimSpace(r.Header.Get("MCP-Session-Id"))
	if req.Method == "initialize" && sessionID == "" {
		sessionID = s.mcpRuntime.CreateSession(p)
		w.Header().Set("MCP-Session-Id", sessionID)
	} else if sessionID != "" {
		if _, ok := s.mcpRuntime.Session(sessionID, p); !ok {
			writeError(w, http.StatusBadRequest, "valid MCP-Session-Id is required")
			return
		}
	} else if mcpWriteRequest(req) {
		writeError(w, http.StatusBadRequest, "MCP write tools require an initialized session")
		return
	}
	resp := s.mcpServer.HandlePrincipal(r.Context(), p, req)
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("MCP-Session-Id", sessionID)
	writeJSON(w, http.StatusOK, resp)
	if req.Method == "tools/call" && resp.Error == nil {
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/resources/updated", "params": map[string]any{"tenant_id": p.TenantID}})
		s.mcpRuntime.NotifyTenant(p.TenantID, payload)
	}
}

func mcpWriteRequest(req mcpserver.Request) bool {
	if req.Method != "tools/call" {
		return false
	}
	var params mcpserver.CallParams
	if json.Unmarshal(req.Params, &params) != nil {
		return false
	}
	switch params.Name {
	case "prepare_action", "acknowledge_incident", "resolve_incident", "quarantine_test", "unquarantine_test", "create_draft_repair_pr":
		return true
	default:
		return false
	}
}

func (s *Server) validMCPOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	if strings.TrimSpace(s.cfg.PublicBaseURL) != "" {
		p, err := url.Parse(s.cfg.PublicBaseURL)
		return err == nil && strings.EqualFold(p.Scheme, u.Scheme) && strings.EqualFold(p.Host, u.Host)
	}
	return false
}

func (s *Server) ciWebhook(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		co := s.cfg.Connector(provider)
		if co == nil {
			writeError(w, http.StatusServiceUnavailable, provider+" connector is not enabled")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read webhook")
			return
		}
		if !connectors.VerifyWebhook(provider, co.WebhookSecret, r.Header, body, time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "invalid webhook signature")
			return
		}
		delivery := r.Header.Get("X-Gitlab-Webhook-UUID")
		if delivery == "" {
			delivery = r.Header.Get("webhook-id")
		}
		if delivery == "" {
			delivery = r.Header.Get("X-Request-ID")
		}
		if delivery == "" {
			delivery = r.Header.Get("X-Buildkite-Event") + ":" + shortBodyHash(body)
		}
		delivery = provider + ":" + delivery
		fresh, err := s.store.RecordDelivery(r.Context(), delivery, provider)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		if !fresh {
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "duplicate_ignored"})
			return
		}
		ev, err := connectors.ParseWebhook(provider, co.TenantID, delivery, body)
		if err != nil {
			_ = s.store.UpdateDelivery(r.Context(), delivery, "invalid", err.Error())
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if ev.Conclusion == "" || (ev.Conclusion != "success" && !failedCIConclusion(ev.Conclusion)) {
			_ = s.store.UpdateDelivery(r.Context(), delivery, "ignored", "not terminal")
			writeJSON(w, http.StatusAccepted, map[string]any{"status": "ignored"})
			return
		}
		if err := s.store.EnqueueForTenant(r.Context(), ev.TenantID, "ci.event", ev, time.Now().UTC()); err != nil {
			_ = s.store.UpdateDelivery(r.Context(), delivery, "error", err.Error())
			writeError(w, 500, err.Error())
			return
		}
		_ = s.store.UpdateDelivery(r.Context(), delivery, "queued", "")
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued", "provider": provider, "repository": ev.Repository, "job": ev.Job})
	}
}

func shortBodyHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:12]) }
func failedCIConclusion(v string) bool {
	switch strings.ToLower(v) {
	case "failure", "failed", "error", "cancelled", "canceled", "timed_out", "timeout":
		return true
	}
	return false
}

func (s *Server) marketplaceSubscription(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListObjects(r.Context(), principal(r).TenantID, "marketplace_subscription", 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": items, "feature_gates": false})
}

func (s *Server) marketplaceSubscriptions(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListObjects(r.Context(), model.DefaultTenantID, "marketplace_account_index", 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": items, "feature_gates": false})
}

func (s *Server) githubMarketplaceWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.GitHubMarketplace.Enabled {
		http.NotFound(w, r)
		return
	}
	if event := strings.TrimSpace(r.Header.Get("X-GitHub-Event")); event != "" && event != "marketplace_purchase" {
		writeError(w, http.StatusBadRequest, "unexpected GitHub event")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	secret := strings.TrimSpace(s.cfg.GitHubMarketplace.WebhookSecret)
	if secret == "" {
		secret = s.cfg.GitHubWebhookSecret
	}
	if !gh.VerifyWebhook(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, http.StatusUnauthorized, "invalid webhook signature")
		return
	}
	delivery := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if delivery == "" {
		hash := sha256.Sum256(body)
		delivery = "marketplace-" + hex.EncodeToString(hash[:16])
	}
	fresh, err := s.store.RecordDelivery(r.Context(), delivery, "github.marketplace_purchase")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !fresh {
		writeJSON(w, http.StatusOK, map[string]any{"status": "duplicate"})
		return
	}
	subscription, err := s.marketplace.Handle(r.Context(), body)
	if err != nil {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "error", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.UpdateDelivery(r.Context(), delivery, "processed", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "processed", "tenant_id": subscription.TenantID, "plan": subscription.PlanName, "subscription_status": subscription.Status})
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-GitHub-Event")), "marketplace_purchase") && s.cfg.GitHubMarketplace.Enabled {
		s.githubMarketplaceWebhook(w, r)
		return
	}
	if !s.cfg.GitHubConfigured() {
		writeError(w, 503, "GitHub App and webhook are not fully configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		writeError(w, 400, "could not read webhook")
		return
	}
	if !gh.VerifyWebhook(s.cfg.GitHubWebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, 401, "invalid webhook signature")
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	eventType := r.Header.Get("X-GitHub-Event")
	if delivery == "" {
		writeError(w, 400, "missing X-GitHub-Delivery")
		return
	}
	fresh, err := s.store.RecordDelivery(r.Context(), delivery, eventType)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if !fresh {
		writeJSON(w, 202, map[string]any{"status": "duplicate_ignored"})
		return
	}
	if eventType != "workflow_run" {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "ignored", "")
		writeJSON(w, 202, map[string]any{"status": "ignored", "event": eventType})
		return
	}
	var ev model.GitHubWorkflowRunEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "invalid", err.Error())
		writeError(w, 400, "invalid workflow_run payload")
		return
	}
	var bound bool
	ev.TenantID, bound = s.store.ResolveInstallationTenant(r.Context(), ev.Installation.ID)
	if s.cfg.RequireInstallationBinding && !bound {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "unbound", "GitHub installation is not assigned to a tenant")
		writeError(w, http.StatusConflict, "GitHub installation is not assigned to a tenant; use `ciradar github-installation bind`")
		return
	}
	ev.DeliveryID = delivery
	if ev.Action != "completed" || ev.WorkflowRun.Status != "completed" {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "ignored", "")
		writeJSON(w, 202, map[string]any{"status": "ignored", "reason": "not completed"})
		return
	}
	switch ev.WorkflowRun.Conclusion {
	case "success", "failure", "timed_out", "cancelled", "startup_failure", "stale":
	default:
		_ = s.store.UpdateDelivery(r.Context(), delivery, "ignored", "")
		writeJSON(w, 202, map[string]any{"status": "ignored", "reason": "unsupported conclusion"})
		return
	}
	if err := s.store.EnqueueForTenant(r.Context(), ev.TenantID, "github.workflow_run", ev, time.Now().UTC()); err != nil {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "error", err.Error())
		writeError(w, 500, err.Error())
		return
	}
	_ = s.store.UpdateDelivery(r.Context(), delivery, "queued", "")
	writeJSON(w, 202, map[string]any{"status": "queued", "tenant_id": ev.TenantID, "run_id": ev.WorkflowRun.ID, "conclusion": ev.WorkflowRun.Conclusion})
}

func (s *Server) providerIncident(ctx context.Context, provider string) bool {
	statuses, err := s.store.ListProviderStatuses(ctx)
	if err != nil {
		return false
	}
	for _, st := range statuses {
		if st.Incident && providers.MatchesStatusProvider(provider, st.Provider) {
			return true
		}
	}
	return false
}
func (s *Server) maybeIncident(ctx context.Context, tenantID, repository string, r model.AnalysisResult, c db.CorrelationStats) (*model.Incident, bool, error) {
	repos := c.Repositories + 1
	orgs := c.Organizations + 1
	occ := c.Occurrences + 1
	if !r.ProviderIncident && repos < s.cfg.IncidentRepoThreshold && orgs < s.cfg.IncidentOrgThreshold {
		return nil, false, nil
	}
	severity := "minor"
	if repos >= 10 || r.ProviderIncident {
		severity = "major"
	}
	if repos >= 50 {
		severity = "critical"
	}
	if profile, _ := s.store.GetRepositoryProfile(ctx, tenantID, repository); profile != nil {
		switch strings.ToLower(profile.Criticality) {
		case "critical":
			severity = "critical"
		case "high":
			if severity == "minor" {
				severity = "major"
			}
		}
	}
	now := time.Now().UTC()
	i := model.Incident{ID: "inc_" + tenantID + "_" + r.Fingerprint, TenantID: tenantID, Fingerprint: r.Fingerprint, Provider: r.Provider, ErrorFamily: r.ErrorFamily, Category: r.Category, Attribution: r.Attribution, State: "open", Severity: severity, RepositoryCount: repos, OrganizationCount: orgs, OccurrenceCount: occ, FirstSeenAt: now, LastSeenAt: now, Title: fmt.Sprintf("%s: %s", r.Provider, r.Summary)}
	old, err := s.store.GetIncidentForTenant(ctx, tenantID, r.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	created := old == nil || old.State == "resolved"
	if err := s.store.UpsertIncidentForTenant(ctx, tenantID, i); err != nil {
		return nil, false, err
	}
	out, _ := s.store.GetIncidentForTenant(ctx, tenantID, r.Fingerprint)
	return out, created, nil
}

func (s *Server) require(min model.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authenticate(r)
		if !ok {
			writeError(w, 401, "unauthorized")
			return
		}
		if roleRank(p.Role) < roleRank(min) {
			writeError(w, 403, "forbidden")
			return
		}
		if requestWrites(r) && !principalHasScope(p, "ciradar.write") {
			writeError(w, 403, "OAuth token does not include ciradar.write")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}
func requestWrites(r *http.Request) bool {
	if r.URL.Path == "/mcp" {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func principalHasScope(p model.Principal, scope string) bool {
	if len(p.Scopes) == 0 {
		return true
	}
	for _, value := range p.Scopes {
		if value == scope {
			return true
		}
	}
	return false
}

func (s *Server) requireRoot(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authenticate(r)
		if !ok {
			writeError(w, 401, "unauthorized")
			return
		}
		if !p.Root {
			writeError(w, 403, "root administrator required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}
func (s *Server) authenticate(r *http.Request) (model.Principal, bool) {
	token := ""
	parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		token = parts[1]
	}
	tenant := strings.ToLower(strings.TrimSpace(r.Header.Get("X-CI-Radar-Tenant")))
	if tenant == "" {
		tenant = s.cfg.DefaultTenantID
	}
	if token != "" {
		if p, ok := s.authenticateToken(r.Context(), token, tenant); ok {
			return p, true
		}
	}
	if p, ok := s.authenticateDashboardSession(r); ok {
		return p, true
	}
	if s.sso != nil {
		if p, ok := s.sso.Authenticate(r); ok {
			t, _ := s.store.GetTenant(r.Context(), p.TenantID)
			if t != nil && t.Enabled {
				return *p, true
			}
		}
	}
	if token == "" && s.cfg.AllowUnauthenticatedLocalhost && isLoopback(s.ipResolver.resolve(r)) {
		t, _ := s.store.GetTenant(r.Context(), s.cfg.DefaultTenantID)
		if t == nil || !t.Enabled {
			return model.Principal{}, false
		}
		return model.Principal{TenantID: t.ID, Name: "local-root", Role: model.RoleAdmin, Root: true}, true
	}
	return model.Principal{}, false
}
func principal(r *http.Request) model.Principal {
	if p, ok := r.Context().Value(principalKey).(model.Principal); ok {
		return p
	}
	return model.Principal{TenantID: model.DefaultTenantID, Name: "unknown", Role: model.RoleViewer}
}
func roleRank(r model.Role) int {
	switch r {
	case model.RoleAdmin:
		return 3
	case model.RoleOperator:
		return 2
	default:
		return 1
	}
}
func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
func (s *Server) audit(r *http.Request, action, resource, id string, metadata map[string]string) {
	p := principal(r)
	_ = s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: p.TenantID, Actor: p.Name, Role: p.Role, Action: action, Resource: resource, ResourceID: id, RemoteIP: s.ipResolver.resolve(r), RequestID: requestIDFrom(r), Metadata: metadata})
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Info("http request", "request_id", requestIDFrom(r), "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr)
	})
}
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" {
			b := make([]byte, 12)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}
func requestIDFrom(r *http.Request) string {
	v, _ := r.Context().Value(requestIDKey).(string)
	return v
}
func securityHeaders(publicBaseURL string, resolver *clientIPResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
		if requestIsHTTPS(r, publicBaseURL, resolver) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func requestIsHTTPS(r *http.Request, publicBaseURL string, resolver *clientIPResolver) bool {
	if r.TLS != nil {
		return true
	}
	if parsed, err := url.Parse(strings.TrimSpace(publicBaseURL)); err == nil && strings.EqualFold(parsed.Scheme, "https") {
		return true
	}
	peer := remoteIP(r.RemoteAddr)
	return resolver != nil && resolver.trustedIP(peer) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func csrfGuard(cfg config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Authorization"))), "bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		hasSession := false
		if _, err := r.Cookie(dashboardSessionCookie); err == nil {
			hasSession = true
		}
		if cfg.SSO.CookieName != "" {
			if _, err := r.Cookie(cfg.SSO.CookieName); err == nil {
				hasSession = true
			}
		}
		if !hasSession {
			next.ServeHTTP(w, r)
			return
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			origin = strings.TrimSpace(r.Header.Get("Referer"))
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, r.Host) {
			writeError(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}
