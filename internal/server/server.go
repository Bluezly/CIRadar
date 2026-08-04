package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/notifications"
	"ciradar/internal/providers"
	"ciradar/internal/version"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	requestIDKey contextKey = "request_id"
)

type Server struct {
	cfg      config.Config
	store    db.Backend
	analyzer *analyzer.Analyzer
	log      *slog.Logger
	http     *http.Server
}

func New(cfg config.Config, store db.Backend, a *analyzer.Analyzer, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: store, analyzer: a, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.dashboardPage)
	mux.HandleFunc("GET /healthz", s.health)
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
	mux.HandleFunc("POST /api/v1/github/installations/{id}/bind", s.requireRoot(s.bindInstallation))
	mux.HandleFunc("DELETE /api/v1/github/installations/{id}", s.requireRoot(s.unbindInstallation))
	mux.HandleFunc("GET /metrics", s.require(model.RoleViewer, s.metrics))
	mux.HandleFunc("POST /webhooks/github", s.githubWebhook)
	h := requestID(securityHeaders(logging(log, rateLimit(newRateLimiter(600, time.Minute), mux))))
	s.http = &http.Server{Addr: cfg.ListenAddress, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	return s
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	_, _ = io.WriteString(w, dashboardHTML)
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
	writeJSON(w, 200, map[string]any{"version": version.Version, "commit": version.Commit, "tenant_id": p.TenantID, "role": p.Role, "github_configured": s.cfg.GitHubConfigured(), "automatic_retry_enabled": s.cfg.AutomaticRetryEnabled, "cross_tenant_correlation": s.cfg.CrossTenantCorrelation, "store_raw_logs": s.cfg.StoreRawLogs, "notifications_enabled": s.cfg.Notifications.Enabled, "notification_channels": len(s.cfg.Notifications.Channels), "stats": st, "providers": providerList})
}

func (s *Server) dashboardData(w http.ResponseWriter, r *http.Request) {
	dur := 7 * 24 * time.Hour
	if raw := r.URL.Query().Get("range"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= time.Hour && d <= 365*24*time.Hour {
			dur = d
		}
	}
	d, err := s.store.Dashboard(r.Context(), principal(r).TenantID, time.Now().UTC().Add(-dur))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, d)
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
	corr, err := s.store.CorrelationForTenant(r.Context(), p.TenantID, initial.Fingerprint, time.Now().UTC().Add(-s.cfg.IncidentWindow), s.cfg.CrossTenantCorrelation)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	prev, _ := s.store.LastSuccessfulEnvironmentForTenant(r.Context(), p.TenantID, in.Repository, in.Workflow, in.Job)
	result := s.analyzer.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: s.providerIncident(r.Context(), initial.Provider), PreviousEnvironment: prev})
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
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "ciradar_analyses_total %d\nciradar_incidents_open %d\nciradar_jobs_queued %d\nciradar_repositories %d\nciradar_notification_failures_total %d\n", st.Analyses, st.OpenIncidents, st.QueuedJobs, st.Repositories, st.NotificationFailures)
}

func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
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
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
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
	if s.cfg.AdminToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) == 1 {
		t, _ := s.store.GetTenant(r.Context(), tenant)
		if t == nil || !t.Enabled {
			return model.Principal{}, false
		}
		return model.Principal{TenantID: t.ID, Name: "root", Role: model.RoleAdmin, Root: true}, true
	}
	if p, _ := s.store.AuthenticateAPIKey(r.Context(), token); p != nil {
		return *p, true
	}
	if token == "" && s.cfg.AllowUnauthenticatedLocalhost && isLoopback(r.RemoteAddr) {
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
	_ = s.store.RecordAudit(r.Context(), model.AuditEvent{TenantID: p.TenantID, Actor: p.Name, Role: p.Role, Action: action, Resource: resource, ResourceID: id, RemoteIP: r.RemoteAddr, RequestID: requestIDFrom(r), Metadata: metadata})
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
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
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
