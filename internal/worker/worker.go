package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ciradar/internal/analyzer"
	"ciradar/internal/config"
	"ciradar/internal/connectors"
	"ciradar/internal/db"
	gh "ciradar/internal/github"
	"ciradar/internal/model"
	"ciradar/internal/notifications"
	"ciradar/internal/providers"
)

type jobDiagnosis struct {
	Job    gh.Job
	Input  model.AnalysisInput
	Result model.AnalysisResult
}

type Worker struct {
	cfg      config.Config
	store    db.Backend
	analyzer *analyzer.Analyzer
	github   *gh.Client
	notifier *notifications.Dispatcher
	log      *slog.Logger
}

func New(cfg config.Config, store db.Backend, a *analyzer.Analyzer, github *gh.Client, notifier *notifications.Dispatcher, log *slog.Logger) *Worker {
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
	case "ci.event":
		var ev model.CIEvent
		if err := json.Unmarshal(job.Payload, &ev); err != nil {
			return err
		}
		err := w.processCIEvent(ctx, ev)
		if ev.DeliveryID != "" {
			status, detail := "processed", ""
			if err != nil {
				status, detail = "error", err.Error()
			}
			_ = w.store.UpdateDelivery(ctx, ev.DeliveryID, status, detail)
		}
		return err
	case "github.workflow_run":
		var ev model.GitHubWorkflowRunEvent
		if err := json.Unmarshal(job.Payload, &ev); err != nil {
			return err
		}
		err := w.processWorkflowRun(ctx, ev)
		if ev.DeliveryID != "" {
			status, detail := "processed", ""
			if err != nil {
				status, detail = "error", err.Error()
			}
			_ = w.store.UpdateDelivery(ctx, ev.DeliveryID, status, detail)
		}
		return err
	default:
		return fmt.Errorf("unknown job type %q", job.Type)
	}
}

func (w *Worker) processCIEvent(ctx context.Context, ev model.CIEvent) error {
	co := w.cfg.Connector(ev.Provider)
	if co == nil {
		return fmt.Errorf("%s connector is not enabled", ev.Provider)
	}
	tenantID := strings.TrimSpace(ev.TenantID)
	if tenantID == "" {
		tenantID = co.TenantID
	}
	tenant, _ := w.store.GetTenant(ctx, tenantID)
	if tenant == nil || !tenant.Enabled {
		return fmt.Errorf("tenant %q is missing or disabled", tenantID)
	}
	logText, err := connectors.FetchLog(ctx, *co, ev, w.cfg.MaxLogBytes)
	if err != nil {
		return fmt.Errorf("fetch %s log: %w", ev.Provider, err)
	}
	if ev.Conclusion == "success" {
		env := analyzer.ExtractEnvironment(logText)
		prev, err := w.store.LastSuccessfulEnvironmentForTenant(ctx, tenantID, ev.Repository, ev.Workflow, ev.Job)
		if err != nil {
			return err
		}
		changes := []string{}
		if prev != nil {
			changes = analyzer.CompareEnvironment(*prev, env)
		}
		if err := w.store.RecordSuccessfulEnvironmentForTenant(ctx, tenantID, ev.Repository, ev.Workflow, ev.Job, ev.CommitSHA, env, time.Now().UTC()); err != nil {
			return err
		}
		if len(changes) > 0 && w.notifier != nil && w.notifier.Enabled() {
			_ = w.store.EnqueueForTenant(ctx, tenantID, "notify.event", notifications.EnvironmentChangedEvent(tenantID, ev.Repository, ev.Organization, ev.Workflow, ev.Job, ev.CommitSHA, ev.RunURL, changes), time.Now().UTC())
		}
		return nil
	}
	jobID, _ := strconv.ParseInt(ev.JobID, 10, 64)
	in := model.AnalysisInput{TenantID: tenantID, SourceProvider: ev.Provider, SourceRunURL: ev.RunURL, Repository: ev.Repository, Organization: ev.Organization, Workflow: ev.Workflow, Job: ev.Job, RunID: ev.RunID, JobID: jobID, CommitSHA: ev.CommitSHA, PullRequestNumber: ev.PullRequestNumber, MergeRequestNumber: ev.MergeRequestIID, Log: logText, OccurredAt: ev.OccurredAt}
	initial := w.analyzer.Analyze(in, analyzer.Context{})
	corr, err := w.store.CorrelationForTenant(ctx, tenantID, initial.Fingerprint, time.Now().UTC().Add(-w.cfg.IncidentWindow), w.cfg.CrossTenantCorrelation)
	if err != nil {
		return err
	}
	prevEnv, err := w.store.LastSuccessfulEnvironmentForTenant(ctx, tenantID, in.Repository, in.Workflow, in.Job)
	if err != nil {
		return err
	}
	result := w.analyzer.Analyze(in, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: w.providerIncident(ctx, initial.Provider), PreviousEnvironment: prevEnv})
	if err := w.store.RecordAnalysisForTenant(ctx, tenantID, in, result, w.cfg.StoreRedactedExcerpts, w.cfg.StoreRawLogs); err != nil {
		return err
	}
	if w.notifier != nil && w.notifier.Enabled() {
		_ = w.store.EnqueueForTenant(ctx, tenantID, "notify.event", notifications.AnalysisEvent(in, result, w.cfg.PublicBaseURL), time.Now().UTC())
	}
	incident, created, err := w.maybeCreateIncident(ctx, tenantID, in.Repository, result, corr)
	if err != nil {
		return err
	}
	if incident != nil && w.notifier != nil && w.notifier.Enabled() {
		kind := "incident_updated"
		if created {
			kind = "incident_opened"
		}
		_ = w.store.EnqueueForTenant(ctx, tenantID, "notify.event", notifications.IncidentEvent(kind, *incident, w.cfg.PublicBaseURL), time.Now().UTC())
	}
	if ev.Provider == "gitlab" && ev.MergeRequestIID > 0 && w.cfg.PRComments.Enabled && result.Score >= w.cfg.PRComments.MinimumScore {
		if shouldPublishDeveloperComment(w.cfg.PRComments.Mode, result) {
			body := renderDeveloperComment(result, ev.RunURL)
			if err := connectors.UpsertGitLabMRComment(ctx, *co, ev, "<!-- ci-radar-diagnosis -->", body, w.cfg.PRComments.UpdateExisting); err != nil {
				w.log.Warn("could not publish GitLab MR comment", "error", err, "repository", ev.Repository, "mr", ev.MergeRequestIID)
			}
		}
	}
	return nil
}

func shouldPublishDeveloperComment(mode string, r model.AnalysisResult) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "disabled":
		return false
	case "external_only":
		return r.Attribution == model.AttributionExternal
	case "strong_only":
		return r.Confidence == model.ConfidenceStrong
	case "all", "all_diagnoses":
		return true
	default:
		return r.Attribution == model.AttributionExternal || r.Confidence == model.ConfidenceStrong
	}
}

func renderDeveloperComment(r model.AnalysisResult, runURL string) string {
	var b strings.Builder
	b.WriteString("## CI Radar diagnosis\n\n")
	fmt.Fprintf(&b, "**%s** · %s confidence · score %d/100\n\n", r.Attribution, r.Confidence, r.Score)
	fmt.Fprintf(&b, "**Cause:** %s\n\n", r.Summary)
	if len(r.Evidence) > 0 {
		b.WriteString("**Evidence:**\n")
		for i, e := range r.Evidence {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "- [%+d] %s\n", e.Weight, e.Description)
		}
		b.WriteString("\n")
	}
	if len(r.SuggestedActions) > 0 {
		b.WriteString("**Recommended next actions:**\n")
		for i, a := range r.SuggestedActions {
			if i >= 4 {
				break
			}
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", a.Title, a.Risk, a.Description)
		}
	} else if r.Recommendation != "" {
		fmt.Fprintf(&b, "**Recommendation:** %s\n", r.Recommendation)
	}
	if runURL != "" {
		fmt.Fprintf(&b, "\n[Open CI run](%s)\n", runURL)
	}
	b.WriteString("\n<sub>Update this diagnosis using CI Radar feedback after the root cause is confirmed.</sub>")
	return b.String()
}

func (w *Worker) processWorkflowRun(ctx context.Context, ev model.GitHubWorkflowRunEvent) error {
	if w.github == nil {
		return fmt.Errorf("GitHub client is not configured")
	}
	tenantID := strings.TrimSpace(ev.TenantID)
	if tenantID == "" {
		var bound bool
		tenantID, bound = w.store.ResolveInstallationTenant(ctx, ev.Installation.ID)
		if w.cfg.RequireInstallationBinding && !bound {
			return fmt.Errorf("GitHub installation %d is not assigned to a tenant", ev.Installation.ID)
		}
	}
	tenant, _ := w.store.GetTenant(ctx, tenantID)
	if tenant == nil || !tenant.Enabled {
		return fmt.Errorf("tenant %q is missing or disabled", tenantID)
	}
	ev.TenantID = tenantID
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
		return w.captureSuccessfulEnvironment(ctx, tenantID, ev, jobs, owner, repo)
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
	diagnoses := make([]jobDiagnosis, 0)
	for _, job := range jobs {
		if !failedConclusion(job.Conclusion) {
			continue
		}
		logText, err := w.github.DownloadJobLog(ctx, ev.Installation.ID, owner, repo, job.ID, w.cfg.MaxLogBytes)
		if err != nil {
			w.log.Warn("download job log failed", "job", job.Name, "error", err)
			continue
		}
		input := model.AnalysisInput{TenantID: tenantID, SourceProvider: "github", SourceRunURL: ev.WorkflowRun.HTMLURL, Repository: ev.Repository.FullName, Organization: owner, Workflow: ev.WorkflowRun.Name, Job: job.Name, RunID: ev.WorkflowRun.ID, JobID: job.ID, CommitSHA: ev.WorkflowRun.HeadSHA, PreviousSuccess: previousSuccess, WorkflowChanged: workflowChanged, DependencyChanged: dependencyChanged, ChangeInfoAvailable: changeInfoAvailable, Log: logText, OccurredAt: time.Now().UTC()}
		if len(ev.WorkflowRun.PullRequests) > 0 {
			input.PullRequestNumber = ev.WorkflowRun.PullRequests[0].Number
		}
		initial := w.analyzer.Analyze(input, analyzer.Context{})
		corr, err := w.store.CorrelationForTenant(ctx, tenantID, initial.Fingerprint, time.Now().UTC().Add(-w.cfg.IncidentWindow), w.cfg.CrossTenantCorrelation)
		if err != nil {
			return err
		}
		prevEnv, err := w.store.LastSuccessfulEnvironmentForTenant(ctx, tenantID, input.Repository, input.Workflow, input.Job)
		if err != nil {
			return err
		}
		providerIncident := w.providerIncident(ctx, initial.Provider)
		result := w.analyzer.Analyze(input, analyzer.Context{CrossRepoCount: corr.Repositories + 1, CrossOrgCount: corr.Organizations + 1, RecentOccurrences: corr.Occurrences + 1, ProviderIncident: providerIncident, PreviousEnvironment: prevEnv})
		if err := w.store.RecordAnalysisForTenant(ctx, tenantID, input, result, w.cfg.StoreRedactedExcerpts, w.cfg.StoreRawLogs); err != nil {
			return err
		}
		diagnoses = append(diagnoses, jobDiagnosis{Job: job, Input: input, Result: result})
		if w.notifier != nil && w.notifier.Enabled() {
			_ = w.store.EnqueueForTenant(ctx, input.TenantID, "notify.event", notifications.AnalysisEvent(input, result, w.cfg.PublicBaseURL), time.Now().UTC())
		}
		incident, created, err := w.maybeCreateIncident(ctx, tenantID, input.Repository, result, corr)
		if err != nil {
			w.log.Warn("incident update failed", "error", err)
		} else if incident != nil && w.notifier != nil && w.notifier.Enabled() {
			kind := "incident_updated"
			if created {
				kind = "incident_opened"
			}
			_ = w.store.EnqueueForTenant(ctx, incident.TenantID, "notify.event", notifications.IncidentEvent(kind, *incident, w.cfg.PublicBaseURL), time.Now().UTC())
		}
		if err := w.publishCheck(ctx, ev, job, result, owner, repo); err != nil {
			w.log.Warn("publish GitHub check failed", "error", err)
		}
		processed++
		if result.Score > bestScore {
			bestScore = result.Score
			bestRetryEligible = result.Attribution == model.AttributionExternal && !result.ProviderIncident && retryEligible(result.Category)
		}
	}
	if len(ev.WorkflowRun.PullRequests) > 0 && w.cfg.PRComments.Enabled && len(diagnoses) > 0 {
		if err := w.publishPRComment(ctx, ev, owner, repo, diagnoses); err != nil {
			w.log.Warn("publish PR comment failed", "error", err)
		}
	}
	if processed == 0 {
		return fmt.Errorf("no failed job logs could be processed")
	}
	if w.cfg.AutomaticRetryEnabled && bestRetryEligible && bestScore >= w.cfg.AutomaticRetryMinScore && ev.WorkflowRun.RunAttempt < 2 {
		if err := w.github.RerunFailedJobs(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.ID); err != nil {
			w.log.Warn("automatic retry failed", "error", err)
		} else {
			w.log.Info("automatic retry requested", "tenant", tenantID, "repository", ev.Repository.FullName, "run_id", ev.WorkflowRun.ID)
			_ = w.store.RecordAudit(ctx, model.AuditEvent{TenantID: tenantID, Actor: "system", Role: model.RoleOperator, Action: "workflow.retry", Resource: "workflow_run", ResourceID: fmt.Sprint(ev.WorkflowRun.ID), Metadata: map[string]string{"repository": ev.Repository.FullName}})
		}
	}
	return nil
}

func (w *Worker) captureSuccessfulEnvironment(ctx context.Context, tenantID string, ev model.GitHubWorkflowRunEvent, jobs []gh.Job, owner, repo string) error {
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
		previous, err := w.store.LastSuccessfulEnvironmentForTenant(ctx, tenantID, ev.Repository.FullName, ev.WorkflowRun.Name, job.Name)
		if err != nil {
			return err
		}
		changes := []string{}
		if previous != nil {
			changes = analyzer.CompareEnvironment(*previous, env)
		}
		if err := w.store.RecordSuccessfulEnvironmentForTenant(ctx, tenantID, ev.Repository.FullName, ev.WorkflowRun.Name, job.Name, ev.WorkflowRun.HeadSHA, env, time.Now().UTC()); err != nil {
			return err
		}
		if len(changes) > 0 {
			w.log.Info("CI environment changed", "tenant", tenantID, "repository", ev.Repository.FullName, "job", job.Name, "changes", len(changes))
			_ = w.store.RecordAudit(ctx, model.AuditEvent{TenantID: tenantID, Actor: "system", Role: model.RoleOperator, Action: "environment.changed", Resource: "repository", ResourceID: ev.Repository.FullName, Metadata: map[string]string{"workflow": ev.WorkflowRun.Name, "job": job.Name, "changes": strings.Join(changes, "; ")}})
			if w.notifier != nil && w.notifier.Enabled() {
				event := notifications.EnvironmentChangedEvent(tenantID, ev.Repository.FullName, owner, ev.WorkflowRun.Name, job.Name, ev.WorkflowRun.HeadSHA, ev.WorkflowRun.HTMLURL, changes)
				_ = w.store.Enqueue(ctx, "notify.event", event, time.Now().UTC())
			}
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

func (w *Worker) maybeCreateIncident(ctx context.Context, tenantID, repository string, r model.AnalysisResult, c db.CorrelationStats) (*model.Incident, bool, error) {
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
	if profile, err := w.store.GetRepositoryProfile(ctx, tenantID, repository); err == nil && profile != nil {
		switch strings.ToLower(strings.TrimSpace(profile.Criticality)) {
		case "critical":
			severity = "critical"
		case "high":
			if severity == "minor" {
				severity = "major"
			}
		}
	}
	now := time.Now().UTC()
	i := model.Incident{
		ID:                "inc_" + tenantID + "_" + r.Fingerprint,
		TenantID:          tenantID,
		Fingerprint:       r.Fingerprint,
		Provider:          r.Provider,
		Category:          r.Category,
		Attribution:       r.Attribution,
		ErrorFamily:       r.ErrorFamily,
		State:             "open",
		Severity:          severity,
		RepositoryCount:   repos,
		OrganizationCount: orgs,
		OccurrenceCount:   occ,
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Title:             fmt.Sprintf("%s: %s", r.Provider, r.Summary),
		SuggestedActions:  r.SuggestedActions,
	}
	old, err := w.store.GetIncidentForTenant(ctx, tenantID, r.Fingerprint)
	if err != nil {
		return nil, false, err
	}
	created := old == nil || old.State == "resolved"
	if err := w.store.UpsertIncidentForTenant(ctx, tenantID, i); err != nil {
		return nil, false, err
	}
	out, _ := w.store.GetIncidentForTenant(ctx, tenantID, r.Fingerprint)
	return out, created, nil
}

func (w *Worker) publishCheck(ctx context.Context, ev model.GitHubWorkflowRunEvent, job gh.Job, r model.AnalysisResult, owner, repo string) error {
	title := fmt.Sprintf("%s evidence — %s", prettyConfidence(r.Confidence), r.Category)
	var b strings.Builder
	fmt.Fprintf(&b, "**Diagnosis:** %s\n\n", r.Summary)
	fmt.Fprintf(&b, "**Attribution:** %s  \n**Provider:** %s  \n**Operation:** %s  \n**Evidence score:** %d/100  \n**Fingerprint:** `%s`\n\n", r.Attribution, r.Provider, r.Operation, r.Score, r.Fingerprint)
	if r.DecisionReason != "" {
		fmt.Fprintf(&b, "**Decision:** %s\n\n", r.DecisionReason)
	}
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

func (w *Worker) publishPRComment(ctx context.Context, ev model.GitHubWorkflowRunEvent, owner, repo string, diagnoses []jobDiagnosis) error {
	filtered := make([]jobDiagnosis, 0, len(diagnoses))
	for _, d := range diagnoses {
		if d.Result.Score < w.cfg.PRComments.MinimumScore {
			continue
		}
		strong := d.Result.Confidence == model.ConfidenceStrong || d.Result.Confidence == model.ConfidenceLikelyCode
		external := d.Result.Attribution == model.AttributionExternal
		switch w.cfg.PRComments.Mode {
		case "strong_only":
			if !strong {
				continue
			}
		case "external_only":
			if !external {
				continue
			}
		case "external_or_strong":
			if !external && !strong {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	if len(filtered) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("## CI Radar diagnosis\n\n")
	fmt.Fprintf(&b, "Workflow: **%s** · Run [%d](%s) · Commit `%s`\n\n", ev.WorkflowRun.Name, ev.WorkflowRun.ID, ev.WorkflowRun.HTMLURL, shortSHA(ev.WorkflowRun.HeadSHA))
	for _, d := range filtered {
		fmt.Fprintf(&b, "### %s — %s (%d/100)\n\n", d.Job.Name, d.Result.Attribution, d.Result.Score)
		fmt.Fprintf(&b, "**Cause:** %s  \n**Category:** `%s` · **Provider:** `%s` · **Confidence:** `%s`\n\n", d.Result.Summary, d.Result.Category, d.Result.Provider, d.Result.Confidence)
		if len(d.Result.Evidence) > 0 {
			b.WriteString("**Evidence**\n")
			for i, e := range d.Result.Evidence {
				if i >= 4 {
					break
				}
				fmt.Fprintf(&b, "- %s (`%+d`)\n", e.Description, e.Weight)
			}
			b.WriteString("\n")
		}
		if len(d.Result.SuggestedActions) > 0 {
			b.WriteString("**Suggested next actions**\n")
			for i, a := range d.Result.SuggestedActions {
				if i >= 4 {
					break
				}
				fmt.Fprintf(&b, "- **%s** — %s _[%s]_\n", a.Type, a.Title, a.Risk)
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Fingerprint: `%s`\n\n", d.Result.Fingerprint)
	}
	b.WriteString("---\nCI Radar updates this comment instead of creating a new one for every run.")
	marker := fmt.Sprintf("<!-- ci-radar:%s -->", ev.Repository.FullName)
	return w.github.UpsertPRComment(ctx, ev.Installation.ID, owner, repo, ev.WorkflowRun.PullRequests[0].Number, marker, b.String(), w.cfg.PRComments.UpdateExisting)
}
func shortSHA(v string) string {
	if len(v) > 10 {
		return v[:10]
	}
	return v
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
