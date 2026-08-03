package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/notifications"
	"ciradar/internal/providers"
)

type Worker struct {
	cfg      config.Config
	store    *db.Store
	analyzer *analyzer.Analyzer
	github   *gh.Client
	notifier *notifications.Dispatcher
	log      *slog.Logger
}

func New(cfg config.Config, store *db.Store, a *analyzer.Analyzer, github *gh.Client, notifier *notifications.Dispatcher, log *slog.Logger) *Worker {
	return &Worker{cfg: cfg, store: store, analyzer: a, github: github, notifier: notifier, log: log}
}

func (w *Worker) Run(ctx context.Context) {
	_ = w.store.RequeueStaleJobs(ctx, 10*time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); w.loop(ctx, fmt.Sprintf("worker-%d", n+1)) }(i)
	}
	<-ctx.Done()
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context, id string) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.store.ClaimJob(ctx, id)
		if err != nil {
			w.log.Error("claim job failed", "error", err)
			sleep(ctx, 2*time.Second)
			continue
		}
		if job == nil {
			sleep(ctx, 750*time.Millisecond)
			continue
		}
		err = w.process(ctx, *job)
		if err != nil {
			w.log.Error("job failed", "job_id", job.ID, "type", job.Type, "error", err)
			_ = w.store.FailJob(ctx, job.ID, job.Attempts, err.Error())
		} else {
			_ = w.store.CompleteJob(ctx, job.ID)
		}
	}
}

func (w *Worker) process(ctx context.Context, job db.Job) error {
	switch job.Type {
	case "notify.event":
		var ev model.NotificationEvent
		if err := json.Unmarshal(job.Payload, &ev); err != nil {
			return err
		}
		if w.notifier == nil {
			return nil
		}
		return w.notifier.Dispatch(ctx, ev)
	case "github.workflow_run":
		var ev model.GitHubWorkflowRunEvent
		if err := json.Unmarshal(job.Payload, &ev); err != nil {
			return err
		}
		return w.processWorkflowRun(ctx, ev)
	default:
		return fmt.Errorf("unknown job type %q", job.Type)
	}
}

func (w *Worker) processWorkflowRun(ctx context.Context, ev model.GitHubWorkflowRunEvent) error {
	if w.github == nil {
		return fmt.Errorf("GitHub client is not configured")
	}
	parts := strings.SplitN(ev.Repository.FullName, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid repository %q", ev.Repository.FullName)
	}
	owner, repo := parts[0], parts[1]
	jobs, err := w.github.ListJobs(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.ID)
	if err != nil {
		return err
	}
	if ev.WorkflowRun.Conclusion == "success" {
		return w.captureSuccessfulEnvironment(ctx, ev, jobs, owner, repo)
	}
	previousSuccess, err := w.github.HasPreviousSuccessfulRun(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.HeadSHA, ev.WorkflowRun.ID)
	if err != nil {
		w.log.Warn("could not check previous successful run", "error", err)
	}
	workflowChanged, dependencyChanged := false, false
	changeInfoAvailable := false
	if len(ev.WorkflowRun.PullRequests) > 0 {
		files, err := w.github.ListPullRequestFiles(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.PullRequests[0].Number)
		if err != nil {
			w.log.Warn("could not inspect PR files", "error", err)
		} else {
			workflowChanged, dependencyChanged = classifyChangedFiles(files)
			changeInfoAvailable = true
		}
	}
	processed := 0
	bestScore := -999
	bestRetryEligible := false
	for _, job := range jobs {
		if !failedConclusion(job.Conclusion) {
			continue
		}
		logText, err := w.github.DownloadJobLog(ctx, ev.Installation.ID, owner, repo, job.ID, w.cfg.MaxLogBytes)
		if err != nil {
			w.log.Warn("download job log failed", "job", job.Name, "error", err)
			continue
		}
		input := model.AnalysisInput{Repository: ev.Repository.FullName, Organization: owner, Workflow: ev.WorkflowRun.Name, Job: job.Name, RunID: ev.WorkflowRun.ID, JobID: job.ID, CommitSHA: ev.WorkflowRun.HeadSHA, PreviousSuccess: previousSuccess, WorkflowChanged: workflowChanged, DependencyChanged: dependencyChanged, ChangeInfoAvailable: changeInfoAvailable, Log: logText, OccurredAt: time.Now().UTC()}
		initial := w.analyzer.Analyze(input, analyzer.Context{})
		corr, err := w.store.Correlation(ctx, initial.Fingerprint, time.Now().UTC().Add(-w.cfg.IncidentWindow))
		if err != nil {
			return err
		}
		prevEnv, err := w.store.LastSuccessfulEnvironment(ctx, input.Repository, input.Workflow, input.Job)
		if err != nil {
			return err
		}
		providerIncident := w.providerIncident(ctx, initial.Provider)
		result := w.analyzer.Analyze(input, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: providerIncident, PreviousEnvironment: prevEnv})
		if err := w.store.RecordAnalysis(ctx, input, result, w.cfg.StoreRedactedExcerpts, w.cfg.StoreRawLogs); err != nil {
			return err
		}
		if w.notifier != nil && w.notifier.Enabled() {
			_ = w.store.Enqueue(ctx, "notify.event", notifications.AnalysisEvent(input, result, w.cfg.PublicBaseURL), time.Now().UTC())
		}
		incident, created, err := w.maybeCreateIncident(ctx, result, corr)
		if err != nil {
			w.log.Warn("incident update failed", "error", err)
		} else if incident != nil && w.notifier != nil && w.notifier.Enabled() {
			kind := "incident_updated"
			if created {
				kind = "incident_opened"
			}
			_ = w.store.Enqueue(ctx, "notify.event", notifications.IncidentEvent(kind, *incident, w.cfg.PublicBaseURL), time.Now().UTC())
		}
		if err := w.publishCheck(ctx, ev, job, result, owner, repo); err != nil {
			w.log.Warn("publish GitHub check failed", "error", err)
		}
		processed++
		if result.Score > bestScore {
			bestScore = result.Score
			bestRetryEligible = !result.ProviderIncident && retryEligible(result.Category)
		}
	}
	if processed == 0 {
		return fmt.Errorf("no failed job logs could be processed")
	}
	if w.cfg.AutomaticRetryEnabled && bestRetryEligible && bestScore >= w.cfg.AutomaticRetryMinScore && ev.WorkflowRun.RunAttempt < 2 {
		if err := w.github.RerunFailedJobs(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.ID); err != nil {
			w.log.Warn("automatic retry failed", "error", err)
		} else {
			w.log.Info("automatic retry requested", "repository", ev.Repository.FullName, "run_id", ev.WorkflowRun.ID)
		}
	}
	return nil
}

func (w *Worker) captureSuccessfulEnvironment(ctx context.Context, ev model.GitHubWorkflowRunEvent, jobs []gh.Job, owner, repo string) error {
	captured := 0
	for _, job := range jobs {
		if job.Conclusion != "success" {
			continue
		}
		logText, err := w.github.DownloadJobLog(ctx, ev.Installation.ID, owner, repo, job.ID, w.cfg.MaxLogBytes)
		if err != nil {
			continue
		}
		env := analyzer.ExtractEnvironment(logText)
		if env.RunnerOS == "" && env.RunnerImage == "" && len(env.ToolVersions) == 0 {
			continue
		}
		if err := w.store.RecordSuccessfulEnvironment(ctx, ev.Repository.FullName, ev.WorkflowRun.Name, job.Name, ev.WorkflowRun.HeadSHA, env, time.Now().UTC()); err != nil {
			return err
		}
		captured++
	}
	w.log.Info("successful environment captured", "repository", ev.Repository.FullName, "snapshots", captured)
	return nil
}

func (w *Worker) providerIncident(ctx context.Context, provider string) bool {
	statuses, err := w.store.ListProviderStatuses(ctx)
	if err != nil {
		return false
	}
	for _, s := range statuses {
		if s.Incident && providers.MatchesStatusProvider(provider, s.Provider) {
			return true
		}
	}
	return false
}

func (w *Worker) maybeCreateIncident(ctx context.Context, r model.AnalysisResult, c db.CorrelationStats) (*model.Incident, bool, error) {
	repos := c.Repositories + 1
	orgs := c.Organizations + 1
	occ := c.Occurrences + 1
	if !r.ProviderIncident && repos < w.cfg.IncidentRepoThreshold && orgs < w.cfg.IncidentOrgThreshold {
		return nil, false, nil
	}
	severity := "minor"
	if repos >= 10 || r.ProviderIncident {
		severity = "major"
	}
	if repos >= 50 {
		severity = "critical"
	}
	now := time.Now().UTC()
	i := model.Incident{ID: "inc_" + r.Fingerprint, Fingerprint: r.Fingerprint, Provider: r.Provider, ErrorFamily: r.ErrorFamily, State: "open", Severity: severity, RepositoryCount: repos, OrganizationCount: orgs, OccurrenceCount: occ, FirstSeenAt: now, LastSeenAt: now, Title: fmt.Sprintf("%s: %s", r.Provider, r.Summary)}
	old, err := w.store.GetIncident(ctx, r.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	created := old == nil || old.State != "open"
	if err := w.store.UpsertIncident(ctx, i); err != nil {
		return nil, false, err
	}
	return &i, created, nil
}

func (w *Worker) publishCheck(ctx context.Context, ev model.GitHubWorkflowRunEvent, job gh.Job, r model.AnalysisResult, owner, repo string) error {
	title := fmt.Sprintf("%s evidence — %s", prettyConfidence(r.Confidence), r.Category)
	var b strings.Builder
	fmt.Fprintf(&b, "**Diagnosis:** %s\n\n", r.Summary)
	fmt.Fprintf(&b, "**Provider:** %s  \n**Operation:** %s  \n**Evidence score:** %d/100  \n**Fingerprint:** `%s`\n\n", r.Provider, r.Operation, r.Score, r.Fingerprint)
	if len(r.Evidence) > 0 {
		b.WriteString("### Evidence\n")
		for _, e := range r.Evidence {
			fmt.Fprintf(&b, "- %s (`%+d`)\n", e.Description, e.Weight)
		}
	}
	if len(r.EnvironmentChanges) > 0 {
		b.WriteString("\n### Environment changes\n")
		for _, x := range r.EnvironmentChanges {
			fmt.Fprintf(&b, "- %s\n", x)
		}
	}
	fmt.Fprintf(&b, "\n### Recommendation\n%s\n", r.Recommendation)
	if r.Confidence == model.ConfidenceInsufficient {
		b.WriteString("\nCI Radar is intentionally reporting insufficient evidence rather than guessing.\n")
	}
	details := ""
	if w.cfg.PublicBaseURL != "" {
		details = strings.TrimRight(w.cfg.PublicBaseURL, "/") + "/api/v1/analyses/" + r.ID
	}
	return w.github.CreateCheckRun(ctx, ev.Installation.ID, owner, repo, gh.CheckRunRequest{Name: "CI Radar / " + job.Name, HeadSHA: ev.WorkflowRun.HeadSHA, Status: "completed", Conclusion: "neutral", DetailsURL: details, Output: gh.CheckOutput{Title: title, Summary: r.Summary, Text: b.String()}})
}

func classifyChangedFiles(files []string) (workflow, dependency bool) {
	for _, f := range files {
		f = strings.ToLower(filepath.ToSlash(f))
		if strings.HasPrefix(f, ".github/workflows/") || f == ".github/ciradar.yml" {
			workflow = true
		}
		base := filepath.Base(f)
		switch base {
		case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "pyproject.toml", "cargo.lock", "cargo.toml", "go.mod", "go.sum", "dockerfile", "compose.yml", "docker-compose.yml":
			dependency = true
		}
	}
	return
}
func failedConclusion(s string) bool {
	switch s {
	case "failure", "timed_out", "cancelled", "startup_failure", "stale":
		return true
	}
	return false
}
func prettyConfidence(c model.Confidence) string {
	switch c {
	case model.ConfidenceStrong:
		return "Strong external"
	case model.ConfidenceModerate:
		return "Moderate external"
	case model.ConfidenceMixed:
		return "Mixed"
	case model.ConfidenceLikelyCode:
		return "Likely code-related"
	default:
		return "Insufficient"
	}
}
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func retryEligible(c model.Category) bool {
	switch c {
	case model.CategoryDependencyRegistry, model.CategoryNetworkFailure, model.CategoryRunnerFailure, model.CategoryCacheFailure:
		return true
	default:
		return false
	}
}
