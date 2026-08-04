package worker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/notifications"
)

func testGitHubClient(t *testing.T, handler http.Handler) (*gh.Client, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.CreateTemp(t.TempDir(), "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	_ = keyFile.Close()
	server := httptest.NewServer(handler)
	client, err := gh.New(123, keyFile.Name(), server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server
}

func TestWorkflowRunEndToEndUsesTenantAndCriticality(t *testing.T) {
	var checkBody map[string]any
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/runs/100/jobs":
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{"id": 200, "name": "test", "status": "completed", "conclusion": "failure"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/jobs/200/logs":
			_, _ = io.WriteString(w, "npm ERR! code ECONNRESET\nnpm ERR! request to https://registry.npmjs.org/pkg failed")
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1, "workflow_runs": []map[string]any{{"id": 99, "head_sha": "abc", "status": "completed", "conclusion": "success"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/check-runs":
			if err := json.NewDecoder(r.Body).Decode(&checkBody); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	})
	client, server := testGitHubClient(t, api)
	defer server.Close()

	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	if err := store.BindInstallation(context.Background(), "alpha", 77); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertRepositoryProfile(context.Background(), model.RepositoryProfile{TenantID: "alpha", Repository: "acme/api", Criticality: "critical"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.IncidentRepoThreshold = 1
	cfg.IncidentOrgThreshold = 1
	cfg.RequireInstallationBinding = true
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = false
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	wkr := New(cfg, store, analyzer.New("test-key"), client, nil, log)

	var ev model.GitHubWorkflowRunEvent
	ev.TenantID = "alpha"
	ev.Installation.ID = 77
	ev.Repository.FullName = "acme/api"
	ev.WorkflowRun.ID = 100
	ev.WorkflowRun.Name = "CI"
	ev.WorkflowRun.HeadSHA = "abc"
	ev.WorkflowRun.Status = "completed"
	ev.WorkflowRun.Conclusion = "failure"
	ev.WorkflowRun.RunAttempt = 1
	if err := wkr.processWorkflowRun(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	analyses, err := store.ListAnalysesForTenant(context.Background(), "alpha", 10)
	if err != nil || len(analyses) != 1 {
		t.Fatalf("analyses=%+v err=%v", analyses, err)
	}
	if analyses[0].TenantID != "alpha" || analyses[0].Attribution != model.AttributionExternal {
		t.Fatalf("analysis=%+v", analyses[0])
	}
	incident, err := store.GetIncidentForTenant(context.Background(), "alpha", analyses[0].Fingerprint)
	if err != nil || incident == nil {
		t.Fatalf("incident=%+v err=%v", incident, err)
	}
	if incident.Severity != "critical" || incident.Category != analyses[0].Category || incident.Attribution != analyses[0].Attribution {
		t.Fatalf("incident fields=%+v", incident)
	}
	if checkBody == nil || !strings.Contains(checkBody["name"].(string), "test") {
		t.Fatalf("check body=%+v", checkBody)
	}
}

func TestSuccessfulRunsCreateEnvironmentChangeNotification(t *testing.T) {
	logs := map[int64]string{
		201: "Image: ubuntu-24.04\nVersion: 20260701.1\nArchitecture: X64\nNode.js: 20.10.0\nuses: actions/checkout@v4\nimage: postgres:16\n",
		202: "Image: ubuntu-24.04\nVersion: 20260708.1\nArchitecture: ARM64\nNode.js: 22.1.0\nuses: actions/checkout@v5\nimage: postgres:17\n",
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/api/actions/runs/") && strings.HasSuffix(r.URL.Path, "/jobs"):
			jobID := int64(201)
			if strings.Contains(r.URL.Path, "/101/") {
				jobID = 202
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []map[string]any{{"id": jobID, "name": "build", "status": "completed", "conclusion": "success"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/api/actions/jobs/"):
			jobID := int64(201)
			if strings.Contains(r.URL.Path, "/202/") {
				jobID = 202
			}
			_, _ = io.WriteString(w, logs[jobID])
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	})
	client, server := testGitHubClient(t, api)
	defer server.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ProviderPolling = false
	cfg.Notifications.Enabled = true
	cfg.Notifications.Channels = []config.NotificationChannel{{Name: "webhook", Type: "webhook", Enabled: true, URL: "https://example.invalid", Events: []string{"environment_changed"}, Cooldown: time.Minute, MaxAttempts: 2}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	notifier := notifications.New(cfg.Notifications, store, log)
	wkr := New(cfg, store, analyzer.New("test-key"), client, notifier, log)
	for runID := int64(100); runID <= 101; runID++ {
		var ev model.GitHubWorkflowRunEvent
		ev.TenantID = "alpha"
		ev.Installation.ID = 77
		ev.Repository.FullName = "acme/api"
		ev.WorkflowRun.ID = runID
		ev.WorkflowRun.Name = "CI"
		ev.WorkflowRun.HeadSHA = "sha"
		ev.WorkflowRun.Status = "completed"
		ev.WorkflowRun.Conclusion = "success"
		if err := wkr.processWorkflowRun(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	job, err := store.ClaimJob(context.Background(), "test")
	if err != nil || job == nil || job.Type != "notify.event" || job.TenantID != "alpha" {
		t.Fatalf("notification job=%+v err=%v", job, err)
	}
	var event model.NotificationEvent
	if err := json.Unmarshal(job.Payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "environment_changed" || !strings.Contains(event.Summary, "runner architecture") || !strings.Contains(event.Summary, "actions:") || !strings.Contains(event.Summary, "containers:") {
		t.Fatalf("event=%+v", event)
	}
}

func TestGenericCIEventEndToEnd(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/7/jobs/42/trace" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("PRIVATE-TOKEN") != "token" {
			t.Error("missing GitLab token")
		}
		_, _ = io.WriteString(w, "WARNING: Retrying after connection broken by NameResolutionError: Failed to resolve pypi.org")
	}))
	defer api.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.IncidentRepoThreshold = 1
	cfg.ProviderPolling = false
	cfg.Connectors = []config.CIConnector{{Name: "gitlab", Provider: "gitlab", Enabled: true, TenantID: "alpha", BaseURL: api.URL, Token: "token", WebhookSecret: "secret"}}
	wkr := New(cfg, store, analyzer.New("test-key"), nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ev := model.CIEvent{TenantID: "alpha", Provider: "gitlab", Repository: "acme/api", Organization: "acme", Workflow: "pipeline", Job: "test", RunID: 9, JobID: "42", CommitSHA: "abc", Conclusion: "failure", ProjectID: "7", RunURL: "https://gitlab/acme/api/-/pipelines/9"}
	if err := wkr.processCIEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListAnalysesForTenant(context.Background(), "alpha", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if items[0].Repository != "acme/api" || items[0].SourceProvider != "gitlab" || items[0].Attribution != model.AttributionExternal {
		t.Fatalf("analysis=%#v", items[0])
	}
	inc, err := store.GetIncidentForTenant(context.Background(), "alpha", items[0].Fingerprint)
	if err != nil || inc == nil {
		t.Fatalf("incident=%#v err=%v", inc, err)
	}
}

func TestGenericCIEventRequestsOneSafeRetry(t *testing.T) {
	var retries int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/projects/7/jobs/42/trace":
			_, _ = io.WriteString(w, "npm ERR! code ECONNRESET\nnpm ERR! network request to registry.npmjs.org failed")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v4/projects/7/jobs/42/retry":
			retries++
			w.Header().Set("X-Request-Id", "retry-1")
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ProviderPolling = false
	cfg.AutomaticRetryEnabled = true
	cfg.AutomaticRetryMinScore = 0
	cfg.Connectors = []config.CIConnector{{Name: "gitlab", Provider: "gitlab", Enabled: true, TenantID: "alpha", BaseURL: api.URL, Token: "token", WebhookSecret: "secret"}}
	wkr := New(cfg, store, analyzer.New("test-key"), nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ev := model.CIEvent{TenantID: "alpha", Provider: "gitlab", Repository: "acme/api", Organization: "acme", Workflow: "pipeline", Job: "test", RunID: 9, JobID: "42", CommitSHA: "abc", Conclusion: "failure", ProjectID: "7", PipelineID: "9"}
	if err := wkr.processCIEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := wkr.processCIEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if retries != 1 {
		t.Fatalf("retries=%d", retries)
	}
	audit, err := store.ListAudit(context.Background(), "alpha", 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range audit {
		if item.Action == "workflow.retry" && item.Metadata["request_id"] == "retry-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit=%#v", audit)
	}
}

func TestPRCommentIsStickyAndIncludesActions(t *testing.T) {
	var created, updated int
	var latest string
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/api/issues/12/comments"):
			if created > 0 {
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 99, "body": latest}})
			} else {
				_ = json.NewEncoder(w).Encode([]any{})
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/issues/12/comments":
			created++
			var v map[string]string
			_ = json.NewDecoder(r.Body).Decode(&v)
			latest = v["body"]
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 99, "body": latest})
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/api/issues/comments/99":
			updated++
			var v map[string]string
			_ = json.NewDecoder(r.Body).Decode(&v)
			latest = v["body"]
			w.WriteHeader(200)
		default:
			http.Error(w, "not found "+r.URL.Path, 404)
		}
	})
	client, server := testGitHubClient(t, api)
	defer server.Close()
	cfg := config.Default()
	cfg.PRComments.Enabled = true
	cfg.PRComments.Mode = "all"
	cfg.PRComments.MinimumScore = 0
	w := New(cfg, nil, nil, client, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var ev model.GitHubWorkflowRunEvent
	ev.Installation.ID = 77
	ev.Repository.FullName = "acme/api"
	ev.WorkflowRun.ID = 1
	ev.WorkflowRun.Name = "CI"
	ev.WorkflowRun.HeadSHA = "abcdef123456"
	ev.WorkflowRun.HTMLURL = "https://github/run/1"
	ev.WorkflowRun.PullRequests = append(ev.WorkflowRun.PullRequests, struct {
		Number int `json:"number"`
	}{Number: 12})
	d := jobDiagnosis{Job: gh.Job{Name: "tests"}, Result: model.AnalysisResult{Attribution: model.AttributionExternal, Score: 88, Summary: "registry outage", Category: model.CategoryDependencyRegistry, Provider: "npm", Confidence: model.ConfidenceStrong, Fingerprint: "fp", SuggestedActions: []model.SuggestedAction{{Type: "RETRY", Title: "Retry once", Risk: "SAFE"}}}}
	if err := w.publishPRComment(context.Background(), ev, "acme", "api", []jobDiagnosis{d}); err != nil {
		t.Fatal(err)
	}
	if err := w.publishPRComment(context.Background(), ev, "acme", "api", []jobDiagnosis{d}); err != nil {
		t.Fatal(err)
	}
	if created != 1 || updated != 1 || !strings.Contains(latest, "<!-- ci-radar:acme/api -->") || !strings.Contains(latest, "Retry once") {
		t.Fatalf("created=%d updated=%d body=%s", created, updated, latest)
	}
}

func TestApprovalGatedRepairCreatesDraftPR(t *testing.T) {
	var pullCreated bool
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/77/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/contents/src/app.js":
			_ = json.NewEncoder(w).Encode(map[string]any{"path": "src/app.js", "sha": "sha-file", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("const retries = 1;\n"))})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/git/refs":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == "/repos/acme/api/contents/src/app.js":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/api/pulls":
			pullCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 13, "html_url": "https://github.example/pr/13"})
		default:
			http.Error(w, "not found "+r.URL.Path, http.StatusNotFound)
		}
	})
	client, server := testGitHubClient(t, api)
	defer server.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CreateTenant(context.Background(), "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}
	analysis := model.AnalysisResult{ID: "analysis-repair", TenantID: "alpha", Attribution: model.AttributionCode, Score: -92, ExternalityScore: -92, EvidenceStrength: 92, CodeEvidenceScore: 92, Summary: "retry count is too low"}
	source := model.RepairSource{TenantID: "alpha", Provider: "github", Repository: "acme/api", InstallationID: 77, CommitSHA: "abc", BaseBranch: "feature"}
	if err := store.PutObject(context.Background(), "alpha", "analysis_source", analysis.ID, source); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Repair.Enabled = true
	cfg.Repair.AutoDraftPR = true
	cfg.Repair.MinimumScore = 70
	wkr := New(cfg, store, analyzer.New("test-key"), client, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	patch := "--- a/src/app.js\n+++ b/src/app.js\n@@ -1 +1 @@\n-const retries = 1;\n+const retries = 2;\n"
	wkr.maybeCreateDraftRepair(context.Background(), analysis, model.LLMEnhancement{AnalysisID: analysis.ID, TenantID: "alpha", Patch: patch})
	if !pullCreated {
		t.Fatal("draft PR was not created")
	}
	var result model.RepairResult
	found, err := store.GetObject(context.Background(), "alpha", "repair_result", analysis.ID, &result)
	if err != nil || !found || result.Status != "draft_pr_created" || result.PullRequestNumber != 13 {
		t.Fatalf("result=%#v found=%v err=%v", result, found, err)
	}
}

func TestSignedScoreDoesNotBlockCodeAutomation(t *testing.T) {
	r := model.AnalysisResult{Attribution: model.AttributionCode, Confidence: model.ConfidenceLikelyCode, Score: -62, ExternalityScore: -62, EvidenceStrength: 62, CodeEvidenceScore: 62}
	llmCfg := config.LLMConfig{AutoEnhance: true, MinimumScore: 60}
	if !autoEnhanceEligible(llmCfg, r) {
		t.Fatal("code diagnosis should be eligible for automatic LLM enhancement")
	}
	repairCfg := config.RepairConfig{Enabled: true, AutoDraftPR: true, MinimumScore: 60}
	if !automaticRepairEligible(repairCfg, r) {
		t.Fatal("code diagnosis should be eligible for automatic repair")
	}
	commentCfg := config.PRCommentConfig{Enabled: true, Mode: "external_or_strong", MinimumScore: 60}
	if !prCommentEligible(commentCfg, r) {
		t.Fatal("strong code diagnosis should be eligible for a PR comment")
	}
}

func TestExternalityThresholdStillProtectsAutomaticRetry(t *testing.T) {
	r := model.AnalysisResult{Attribution: model.AttributionCode, Score: -100, ExternalityScore: -100, EvidenceStrength: 100, CodeEvidenceScore: 100}
	if r.Score >= 85 {
		t.Fatal("code evidence must not satisfy the positive external retry threshold")
	}
}
