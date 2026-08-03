package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/providers"
	"ciradar/internal/version"
)

type Server struct {
	cfg      config.Config
	store    *db.Store
	analyzer *analyzer.Analyzer
	log      *slog.Logger
	http     *http.Server
}

func New(cfg config.Config, store *db.Store, a *analyzer.Analyzer, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: store, analyzer: a, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	mux.HandleFunc("GET /api/v1/incidents", s.auth(s.incidents))
	mux.HandleFunc("GET /api/v1/providers", s.auth(s.providerStatuses))
	mux.HandleFunc("GET /api/v1/analyses", s.auth(s.analyses))
	mux.HandleFunc("GET /api/v1/analyses/{id}", s.auth(s.analysis))
	mux.HandleFunc("POST /api/v1/analyze", s.auth(s.analyze))
	mux.HandleFunc("POST /api/v1/baselines", s.auth(s.baseline))
	mux.HandleFunc("POST /webhooks/github", s.githubWebhook)
	s.http = &http.Server{Addr: cfg.ListenAddress, Handler: logging(log, securityHeaders(mux)), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	return s
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("CI Radar server listening", "address", s.cfg.ListenAddress, "github_configured", s.cfg.GitHubConfigured())
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

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version.Version, "time": time.Now().UTC()})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if _, err := s.store.Stats(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	providersList, _ := s.store.ListProviderStatuses(r.Context())
	writeJSON(w, 200, map[string]any{"version": version.Version, "commit": version.Commit, "github_configured": s.cfg.GitHubConfigured(), "automatic_retry_enabled": s.cfg.AutomaticRetryEnabled, "cross_repository_sharing": s.cfg.CrossRepositorySharing, "store_raw_logs": s.cfg.StoreRawLogs, "stats": st, "providers": providersList})
}
func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListIncidents(r.Context(), limit, r.URL.Query().Get("state"))
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
	items, err := s.store.ListAnalyses(r.Context(), limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"analyses": items})
}
func (s *Server) analysis(w http.ResponseWriter, r *http.Request) {
	item, err := s.store.GetAnalysis(r.Context(), r.PathValue("id"))
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
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	initial := s.analyzer.Analyze(in, analyzer.Context{})
	corr, err := s.store.Correlation(r.Context(), initial.Fingerprint, time.Now().UTC().Add(-s.cfg.IncidentWindow))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	prev, _ := s.store.LastSuccessfulEnvironment(r.Context(), in.Repository, in.Workflow, in.Job)
	providerIncident := s.providerIncident(r.Context(), initial.Provider)
	result := s.analyzer.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: providerIncident, PreviousEnvironment: prev})
	if err := s.store.RecordAnalysis(r.Context(), in, result, s.cfg.StoreRedactedExcerpts, s.cfg.StoreRawLogs); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	_ = s.maybeIncident(r.Context(), result, corr)
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
	if err := s.store.RecordSuccessfulEnvironment(r.Context(), in.Repository, in.Workflow, in.Job, in.CommitSHA, env, time.Now().UTC()); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"status": "baseline_saved", "environment": env})
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
	if err := s.store.Enqueue(r.Context(), "github.workflow_run", ev, time.Now().UTC()); err != nil {
		_ = s.store.UpdateDelivery(r.Context(), delivery, "error", err.Error())
		writeError(w, 500, err.Error())
		return
	}
	_ = s.store.UpdateDelivery(r.Context(), delivery, "queued", "")
	writeJSON(w, 202, map[string]any{"status": "queued", "run_id": ev.WorkflowRun.ID, "conclusion": ev.WorkflowRun.Conclusion})
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
func (s *Server) maybeIncident(ctx context.Context, r model.AnalysisResult, c db.CorrelationStats) error {
	repos := c.Repositories + 1
	orgs := c.Organizations + 1
	occ := c.Occurrences + 1
	if !r.ProviderIncident && repos < s.cfg.IncidentRepoThreshold && orgs < s.cfg.IncidentOrgThreshold {
		return nil
	}
	severity := "minor"
	if repos >= 10 || r.ProviderIncident {
		severity = "major"
	}
	if repos >= 50 {
		severity = "critical"
	}
	now := time.Now().UTC()
	return s.store.UpsertIncident(ctx, model.Incident{ID: "inc_" + r.Fingerprint, Fingerprint: r.Fingerprint, Provider: r.Provider, ErrorFamily: r.ErrorFamily, State: "open", Severity: severity, RepositoryCount: repos, OrganizationCount: orgs, OccurrenceCount: occ, FirstSeenAt: now, LastSeenAt: now, Title: fmt.Sprintf("%s: %s", r.Provider, r.Summary)})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			next(w, r)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) != 1 {
			writeError(w, 401, "unauthorized")
			return
		}
		next(w, r)
	}
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Info("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr)
	})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
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
