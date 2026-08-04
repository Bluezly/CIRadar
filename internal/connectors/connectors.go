package connectors

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/model"
)

func VerifyWebhook(provider, secret string, h http.Header, body []byte, now time.Time) bool {
	if secret == "" {
		return false
	}
	switch strings.ToLower(provider) {
	case "gitlab":
		if sig := h.Get("webhook-signature"); sig != "" {
			id, ts := h.Get("webhook-id"), h.Get("webhook-timestamp")
			keyText := strings.TrimPrefix(secret, "whsec_")
			key, err := base64.StdEncoding.DecodeString(keyText)
			if err != nil {
				return false
			}
			message := id + "." + ts + "." + string(body)
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(message))
			expected := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			for _, part := range strings.Fields(sig) {
				if hmac.Equal([]byte(part), []byte(expected)) {
					return true
				}
			}
			return false
		}
		return constant(secret, h.Get("X-Gitlab-Token"))
	case "buildkite":
		if sig := h.Get("X-Buildkite-Signature"); sig != "" {
			vals := parsePairs(sig)
			ts := vals["timestamp"]
			got := vals["signature"]
			n, err := strconv.ParseInt(ts, 10, 64)
			if err != nil || absDuration(now.Sub(time.Unix(n, 0))) > 5*time.Minute {
				return false
			}
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write([]byte(ts + "." + string(body)))
			return hmac.Equal([]byte(got), []byte(hex.EncodeToString(mac.Sum(nil))))
		}
		return constant(secret, h.Get("X-Buildkite-Token"))
	case "circleci":
		vals := parsePairs(h.Get("circleci-signature"))
		got := vals["v1"]
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		return got != "" && hmac.Equal([]byte(got), []byte(hex.EncodeToString(mac.Sum(nil))))
	case "bitbucket":
		got := strings.TrimPrefix(h.Get("X-Hub-Signature"), "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		return got != "" && hmac.Equal([]byte(got), []byte(hex.EncodeToString(mac.Sum(nil))))
	case "jenkins", "azuredevops", "bitrise", "teamcity", "travis", "codebuild", "drone", "semaphore", "appveyor", "cloudbuild":
		if constant(secret, h.Get("X-CI-Radar-Token")) {
			return true
		}
		got := strings.TrimPrefix(h.Get("X-CI-Radar-Signature-256"), "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		return got != "" && hmac.Equal([]byte(got), []byte(hex.EncodeToString(mac.Sum(nil))))
	default:
		return false
	}
}
func constant(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func parsePairs(s string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func ParseWebhook(provider, tenant, delivery string, body []byte) (model.CIEvent, error) {
	switch strings.ToLower(provider) {
	case "gitlab":
		return parseGitLab(tenant, delivery, body)
	case "buildkite":
		return parseBuildkite(tenant, delivery, body)
	case "circleci":
		return parseCircleCI(tenant, delivery, body)
	case "jenkins":
		return parseJenkins(tenant, delivery, body)
	case "azuredevops":
		return parseAzureDevOps(tenant, delivery, body)
	case "bitrise":
		return parseBitrise(tenant, delivery, body)
	case "teamcity":
		return parseTeamCity(tenant, delivery, body)
	case "travis":
		return parseTravis(tenant, delivery, body)
	case "codebuild":
		return parseCodeBuild(tenant, delivery, body)
	case "bitbucket":
		return parseBitbucket(tenant, delivery, body)
	case "drone":
		return parseDrone(tenant, delivery, body)
	case "semaphore":
		return parseSemaphore(tenant, delivery, body)
	case "appveyor":
		return parseAppVeyor(tenant, delivery, body)
	case "cloudbuild":
		return parseCloudBuild(tenant, delivery, body)
	default:
		return model.CIEvent{}, fmt.Errorf("unsupported provider %q", provider)
	}
}

func parseGitLab(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		ObjectKind  string `json:"object_kind"`
		BuildID     int64  `json:"build_id"`
		BuildName   string `json:"build_name"`
		BuildStatus string `json:"build_status"`
		PipelineID  int64  `json:"pipeline_id"`
		ProjectID   int64  `json:"project_id"`
		Project     struct {
			ID     int64  `json:"id"`
			Path   string `json:"path_with_namespace"`
			WebURL string `json:"web_url"`
		} `json:"project"`
		Commit struct {
			SHA string `json:"sha"`
			ID  string `json:"id"`
		} `json:"commit"`
		Repository struct {
			Homepage string `json:"homepage"`
		} `json:"repository"`
		MergeRequest struct {
			IID int `json:"iid"`
		} `json:"merge_request"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.ObjectKind != "build" && p.ObjectKind != "pipeline" && p.ObjectKind != "job" {
		return model.CIEvent{}, fmt.Errorf("unsupported GitLab object_kind %q", p.ObjectKind)
	}
	pid := p.Project.ID
	if pid == 0 {
		pid = p.ProjectID
	}
	sha := p.Commit.SHA
	if sha == "" {
		sha = p.Commit.ID
	}
	ev := model.CIEvent{TenantID: tenant, Provider: "gitlab", DeliveryID: delivery, Repository: p.Project.Path, Organization: firstPath(p.Project.Path), Workflow: "GitLab pipeline", Job: p.BuildName, RunID: p.PipelineID, JobID: strconv.FormatInt(p.BuildID, 10), CommitSHA: sha, Conclusion: normalizeConclusion(p.BuildStatus), Status: p.BuildStatus, RunURL: p.Project.WebURL, MergeRequestIID: p.MergeRequest.IID, ProjectID: strconv.FormatInt(pid, 10), PipelineID: strconv.FormatInt(p.PipelineID, 10), OccurredAt: time.Now().UTC(), Metadata: map[string]string{}}
	if ev.Repository == "" {
		ev.Repository = p.Repository.Homepage
	}
	return ev, nil
}
func parseBuildkite(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		Event        string `json:"event"`
		Organization struct {
			Slug string `json:"slug"`
		} `json:"organization"`
		Pipeline struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		} `json:"pipeline"`
		Build struct {
			ID     string `json:"id"`
			Number int64  `json:"number"`
			State  string `json:"state"`
			Commit string `json:"commit"`
			Branch string `json:"branch"`
			WebURL string `json:"web_url"`
		} `json:"build"`
		Job struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			State  string `json:"state"`
			WebURL string `json:"web_url"`
		} `json:"job"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if !strings.Contains(p.Event, "job") && !strings.Contains(p.Event, "build") {
		return model.CIEvent{}, fmt.Errorf("unsupported Buildkite event %q", p.Event)
	}
	state := p.Job.State
	if state == "" {
		state = p.Build.State
	}
	ev := model.CIEvent{TenantID: tenant, Provider: "buildkite", DeliveryID: delivery, Repository: p.Organization.Slug + "/" + p.Pipeline.Slug, Organization: p.Organization.Slug, Workflow: p.Pipeline.Name, Job: p.Job.Name, RunID: p.Build.Number, JobID: p.Job.ID, CommitSHA: p.Build.Commit, Branch: p.Build.Branch, Conclusion: normalizeConclusion(state), Status: state, RunURL: firstNonEmpty(p.Job.WebURL, p.Build.WebURL), PipelineID: p.Build.ID, OccurredAt: time.Now().UTC(), Metadata: map[string]string{"organization": p.Organization.Slug, "pipeline_slug": p.Pipeline.Slug, "build_number": strconv.FormatInt(p.Build.Number, 10), "job_uuid": p.Job.ID}}
	return ev, nil
}
func parseCircleCI(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		} `json:"project"`
		Organization struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organization"`
		Workflow struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"workflow"`
		Pipeline struct {
			ID     string `json:"id"`
			Number int64  `json:"number"`
			VCS    struct {
				Revision string `json:"revision"`
				Branch   string `json:"branch"`
			} `json:"vcs"`
		} `json:"pipeline"`
		Job struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
			Number int64  `json:"number"`
		} `json:"job"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	state := p.Job.Status
	if state == "" {
		state = p.Workflow.Status
	}
	repo := p.Project.Slug
	if repo == "" {
		repo = p.Organization.Name + "/" + p.Project.Name
	}
	ev := model.CIEvent{TenantID: tenant, Provider: "circleci", DeliveryID: firstNonEmpty(delivery, p.ID), Repository: repo, Organization: p.Organization.Name, Workflow: p.Workflow.Name, Job: p.Job.Name, RunID: p.Pipeline.Number, JobID: firstNonEmpty(p.Job.ID, strconv.FormatInt(p.Job.Number, 10)), CommitSHA: p.Pipeline.VCS.Revision, Branch: p.Pipeline.VCS.Branch, Conclusion: normalizeConclusion(state), Status: state, PipelineID: p.Pipeline.ID, OccurredAt: time.Now().UTC(), Metadata: map[string]string{"project_slug": p.Project.Slug, "job_number": strconv.FormatInt(p.Job.Number, 10), "workflow_id": p.Workflow.ID}}
	return ev, nil
}
func parseJenkins(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Build struct {
			Number     int64          `json:"number"`
			Phase      string         `json:"phase"`
			Status     string         `json:"status"`
			URL        string         `json:"url"`
			FullURL    string         `json:"full_url"`
			Parameters map[string]any `json:"parameters"`
		} `json:"build"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Branch     string `json:"branch"`
		Log        string `json:"log"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	buildURL := firstNonEmpty(p.Build.FullURL, p.Build.URL)
	if buildURL == "" && p.URL != "" {
		buildURL = strings.TrimRight(p.URL, "/") + "/" + strconv.FormatInt(p.Build.Number, 10) + "/"
	}
	repo := p.Repository
	if repo == "" {
		repo = stringParam(p.Build.Parameters, "GIT_URL")
	}
	ev := model.CIEvent{TenantID: tenant, Provider: "jenkins", DeliveryID: delivery, Repository: repo, Organization: firstPath(repo), Workflow: p.Name, Job: p.Name, RunID: p.Build.Number, JobID: strconv.FormatInt(p.Build.Number, 10), CommitSHA: firstNonEmpty(p.Commit, stringParam(p.Build.Parameters, "GIT_COMMIT")), Branch: firstNonEmpty(p.Branch, stringParam(p.Build.Parameters, "GIT_BRANCH")), Conclusion: normalizeConclusion(p.Build.Status), Status: p.Build.Phase, RunURL: buildURL, InlineLog: p.Log, OccurredAt: time.Now().UTC(), Metadata: map[string]string{"build_url": buildURL}}
	return ev, nil
}

func parseAzureDevOps(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		EventType string `json:"eventType"`
		Resource  struct {
			ID            int64     `json:"id"`
			BuildNumber   string    `json:"buildNumber"`
			Status        string    `json:"status"`
			Result        string    `json:"result"`
			SourceVersion string    `json:"sourceVersion"`
			SourceBranch  string    `json:"sourceBranch"`
			StartTime     time.Time `json:"startTime"`
			FinishTime    time.Time `json:"finishTime"`
			Definition    struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"definition"`
			Project struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"project"`
			Repository struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"repository"`
			Links struct {
				Web struct {
					Href string `json:"href"`
				} `json:"web"`
			} `json:"_links"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.Resource.ID == 0 {
		return model.CIEvent{}, errors.New("Azure DevOps webhook missing build id")
	}
	repo := p.Resource.Project.Name + "/" + p.Resource.Repository.Name
	if p.Resource.Repository.Name == "" {
		repo = p.Resource.Project.Name + "/" + p.Resource.Definition.Name
	}
	dur := int64(0)
	if !p.Resource.StartTime.IsZero() && !p.Resource.FinishTime.IsZero() {
		dur = int64(p.Resource.FinishTime.Sub(p.Resource.StartTime).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "azuredevops", DeliveryID: delivery, Repository: strings.Trim(repo, "/"), Organization: p.Resource.Project.Name, Workflow: p.Resource.Definition.Name, Job: p.Resource.Definition.Name, RunID: p.Resource.ID, JobID: strconv.FormatInt(p.Resource.ID, 10), CommitSHA: p.Resource.SourceVersion, Branch: strings.TrimPrefix(p.Resource.SourceBranch, "refs/heads/"), Conclusion: normalizeConclusion(p.Resource.Result), Status: p.Resource.Status, RunURL: p.Resource.Links.Web.Href, ProjectID: p.Resource.Project.ID, PipelineID: strconv.FormatInt(p.Resource.Definition.ID, 10), StartedAt: p.Resource.StartTime, CompletedAt: p.Resource.FinishTime, DurationSeconds: dur, OccurredAt: firstTime(p.Resource.FinishTime, time.Now().UTC()), Metadata: map[string]string{"build_id": strconv.FormatInt(p.Resource.ID, 10), "project": p.Resource.Project.Name, "project_id": p.Resource.Project.ID, "repository_id": p.Resource.Repository.ID}}, nil
}

func parseBitrise(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		BuildSlug   string `json:"build_slug"`
		AppSlug     string `json:"app_slug"`
		BuildStatus int    `json:"build_status"`
		BuildNumber int64  `json:"build_number"`
		CommitHash  string `json:"commit_hash"`
		Branch      string `json:"branch"`
		BuildURL    string `json:"build_url"`
		WorkflowID  string `json:"workflow_id"`
		Repository  struct {
			Slug string `json:"slug"`
			URL  string `json:"repository_url"`
		} `json:"repository"`
		TriggeredAt time.Time `json:"triggered_at"`
		FinishedAt  time.Time `json:"finished_at"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.BuildSlug == "" {
		return model.CIEvent{}, errors.New("Bitrise webhook missing build_slug")
	}
	state := "failure"
	if p.BuildStatus == 1 {
		state = "success"
	} else if p.BuildStatus == 0 {
		state = "running"
	} else if p.BuildStatus == 2 {
		state = "cancelled"
	}
	repo := firstNonEmpty(p.Repository.Slug, p.AppSlug)
	dur := int64(0)
	if !p.TriggeredAt.IsZero() && !p.FinishedAt.IsZero() {
		dur = int64(p.FinishedAt.Sub(p.TriggeredAt).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "bitrise", DeliveryID: delivery, Repository: repo, Organization: firstPath(repo), Workflow: p.WorkflowID, Job: p.WorkflowID, RunID: p.BuildNumber, JobID: p.BuildSlug, CommitSHA: p.CommitHash, Branch: p.Branch, Conclusion: state, Status: state, RunURL: p.BuildURL, PipelineID: p.BuildSlug, StartedAt: p.TriggeredAt, CompletedAt: p.FinishedAt, DurationSeconds: dur, OccurredAt: firstTime(p.FinishedAt, time.Now().UTC()), Metadata: map[string]string{"app_slug": p.AppSlug, "build_slug": p.BuildSlug}}, nil
}

func parseTeamCity(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		Build struct {
			ID          int64  `json:"id"`
			BuildTypeID string `json:"buildTypeId"`
			Number      string `json:"number"`
			Status      string `json:"status"`
			State       string `json:"state"`
			BranchName  string `json:"branchName"`
			WebURL      string `json:"webUrl"`
			StartDate   string `json:"startDate"`
			FinishDate  string `json:"finishDate"`
		} `json:"build"`
		BuildType struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			ProjectID   string `json:"projectId"`
			ProjectName string `json:"projectName"`
		} `json:"buildType"`
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
		VCSRoot struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"vcsRoot"`
		Commit   string `json:"commit"`
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.Build.ID == 0 {
		return model.CIEvent{}, errors.New("TeamCity webhook missing build id")
	}
	project := firstNonEmpty(p.Project.Name, p.BuildType.ProjectName)
	workflow := firstNonEmpty(p.BuildType.Name, p.Build.BuildTypeID)
	repo := strings.Trim(project+"/"+workflow, "/")
	start := parseTeamCityTime(p.Build.StartDate)
	finish := parseTeamCityTime(p.Build.FinishDate)
	dur := int64(0)
	if !start.IsZero() && !finish.IsZero() {
		dur = int64(finish.Sub(start).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "teamcity", DeliveryID: delivery, Repository: repo, Organization: project, Workflow: workflow, Job: workflow, RunID: p.Build.ID, JobID: strconv.FormatInt(p.Build.ID, 10), CommitSHA: firstNonEmpty(p.Commit, p.Revision), Branch: p.Build.BranchName, Conclusion: normalizeConclusion(p.Build.Status), Status: p.Build.State, RunURL: p.Build.WebURL, ProjectID: firstNonEmpty(p.Project.ID, p.BuildType.ProjectID), PipelineID: firstNonEmpty(p.BuildType.ID, p.Build.BuildTypeID), StartedAt: start, CompletedAt: finish, DurationSeconds: dur, OccurredAt: firstTime(finish, time.Now().UTC()), Metadata: map[string]string{"build_id": strconv.FormatInt(p.Build.ID, 10)}}, nil
}

func parseTravis(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		ID         int64     `json:"id"`
		Number     string    `json:"number"`
		State      string    `json:"state"`
		StartedAt  time.Time `json:"started_at"`
		FinishedAt time.Time `json:"finished_at"`
		BuildURL   string    `json:"build_url"`
		Commit     struct {
			SHA    string `json:"sha"`
			Branch string `json:"branch"`
		} `json:"commit"`
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Repository struct {
			Slug  string `json:"slug"`
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repository"`
		Job struct {
			ID     int64  `json:"id"`
			Number string `json:"number"`
			State  string `json:"state"`
			Name   string `json:"name"`
			WebURL string `json:"web_url"`
		} `json:"job"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.ID == 0 && p.Job.ID == 0 {
		return model.CIEvent{}, errors.New("Travis webhook missing build id")
	}
	state := firstNonEmpty(p.Job.State, p.State)
	repo := p.Repository.Slug
	if repo == "" {
		repo = strings.Trim(p.Repository.Owner.Login+"/"+p.Repository.Name, "/")
	}
	dur := int64(0)
	if !p.StartedAt.IsZero() && !p.FinishedAt.IsZero() {
		dur = int64(p.FinishedAt.Sub(p.StartedAt).Seconds())
	}
	jobID := p.Job.ID
	if jobID == 0 {
		jobID = p.ID
	}
	return model.CIEvent{TenantID: tenant, Provider: "travis", DeliveryID: delivery, Repository: repo, Organization: firstPath(repo), Workflow: "Travis CI", Job: firstNonEmpty(p.Job.Name, p.Job.Number), RunID: p.ID, JobID: strconv.FormatInt(jobID, 10), CommitSHA: p.Commit.SHA, Branch: firstNonEmpty(p.Branch.Name, p.Commit.Branch), Conclusion: normalizeConclusion(state), Status: state, RunURL: firstNonEmpty(p.Job.WebURL, p.BuildURL), PipelineID: strconv.FormatInt(p.ID, 10), StartedAt: p.StartedAt, CompletedAt: p.FinishedAt, DurationSeconds: dur, OccurredAt: firstTime(p.FinishedAt, time.Now().UTC()), Metadata: map[string]string{"job_id": strconv.FormatInt(jobID, 10), "build_id": strconv.FormatInt(p.ID, 10)}}, nil
}

func parseCodeBuild(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		ID         string    `json:"id"`
		DetailType string    `json:"detail-type"`
		Time       time.Time `json:"time"`
		Region     string    `json:"region"`
		Account    string    `json:"account"`
		Detail     struct {
			BuildStatus         string `json:"build-status"`
			ProjectName         string `json:"project-name"`
			BuildID             string `json:"build-id"`
			CurrentPhase        string `json:"current-phase"`
			CurrentPhaseContext string `json:"current-phase-context"`
			Version             string `json:"version"`
			Additional          struct {
				Source struct {
					Location string `json:"location"`
					Version  string `json:"version"`
				} `json:"source"`
				Logs struct {
					DeepLink string `json:"deep-link"`
				} `json:"logs"`
				Phases []struct {
					PhaseType    string    `json:"phase-type"`
					PhaseStatus  string    `json:"phase-status"`
					PhaseContext []string  `json:"phase-context"`
					StartTime    time.Time `json:"start-time"`
					EndTime      time.Time `json:"end-time"`
				} `json:"phases"`
			} `json:"additional-information"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.Detail.BuildID == "" {
		return model.CIEvent{}, errors.New("CodeBuild event missing build-id")
	}
	var log strings.Builder
	var start, finish time.Time
	for _, ph := range p.Detail.Additional.Phases {
		if start.IsZero() || (!ph.StartTime.IsZero() && ph.StartTime.Before(start)) {
			start = ph.StartTime
		}
		if ph.EndTime.After(finish) {
			finish = ph.EndTime
		}
		for _, line := range ph.PhaseContext {
			fmt.Fprintf(&log, "%s %s: %s\n", ph.PhaseType, ph.PhaseStatus, line)
		}
	}
	dur := int64(0)
	if !start.IsZero() && !finish.IsZero() {
		dur = int64(finish.Sub(start).Seconds())
	}
	repo := firstNonEmpty(p.Detail.Additional.Source.Location, p.Detail.ProjectName)
	return model.CIEvent{TenantID: tenant, Provider: "codebuild", DeliveryID: firstNonEmpty(delivery, p.ID), Repository: repo, Organization: p.Account, Workflow: p.Detail.ProjectName, Job: p.Detail.CurrentPhase, JobID: p.Detail.BuildID, CommitSHA: firstNonEmpty(p.Detail.Version, p.Detail.Additional.Source.Version), Conclusion: normalizeConclusion(p.Detail.BuildStatus), Status: p.Detail.BuildStatus, RunURL: p.Detail.Additional.Logs.DeepLink, StartedAt: start, CompletedAt: finish, DurationSeconds: dur, RunnerClass: "aws-codebuild", RunnerLabels: []string{p.Region}, InlineLog: log.String(), OccurredAt: firstTime(p.Time, time.Now().UTC()), Metadata: map[string]string{"build_id": p.Detail.BuildID, "region": p.Region, "account": p.Account}}, nil
}

func parseBitbucket(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		Repository struct {
			FullName  string `json:"full_name"`
			Name      string `json:"name"`
			Workspace struct {
				Slug string `json:"slug"`
			} `json:"workspace"`
			Links struct {
				HTML struct {
					Href string `json:"href"`
				} `json:"html"`
			} `json:"links"`
		} `json:"repository"`
		Pipeline struct {
			UUID        string `json:"uuid"`
			BuildNumber int64  `json:"build_number"`
			State       struct {
				Name   string `json:"name"`
				Result struct {
					Name string `json:"name"`
				} `json:"result"`
			} `json:"state"`
			Target struct {
				RefName string `json:"ref_name"`
				Commit  struct {
					Hash string `json:"hash"`
				} `json:"commit"`
			} `json:"target"`
			CreatedOn   time.Time `json:"created_on"`
			CompletedOn time.Time `json:"completed_on"`
			Links       struct {
				HTML struct {
					Href string `json:"href"`
				} `json:"html"`
			} `json:"links"`
		} `json:"pipeline"`
		Step struct {
			UUID  string `json:"uuid"`
			Name  string `json:"name"`
			State struct {
				Name   string `json:"name"`
				Result struct {
					Name string `json:"name"`
				} `json:"result"`
			} `json:"state"`
			StartedOn   time.Time `json:"started_on"`
			CompletedOn time.Time `json:"completed_on"`
			Links       struct {
				HTML struct {
					Href string `json:"href"`
				} `json:"html"`
			} `json:"links"`
		} `json:"step"`
		CommitStatus struct {
			State  string `json:"state"`
			Name   string `json:"name"`
			Key    string `json:"key"`
			URL    string `json:"url"`
			Commit struct {
				Hash string `json:"hash"`
			} `json:"commit"`
		} `json:"commit_status"`
		InlineLog string `json:"inline_log"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	repo := p.Repository.FullName
	if repo == "" {
		repo = p.Repository.Workspace.Slug + "/" + p.Repository.Name
	}
	state := firstNonEmpty(p.Step.State.Result.Name, p.Step.State.Name, p.Pipeline.State.Result.Name, p.Pipeline.State.Name, p.CommitStatus.State)
	if repo == "" || state == "" {
		return model.CIEvent{}, errors.New("Bitbucket event missing repository or state")
	}
	started := firstTime(p.Step.StartedOn, p.Pipeline.CreatedOn)
	finished := firstTime(p.Step.CompletedOn, p.Pipeline.CompletedOn)
	dur := int64(0)
	if !started.IsZero() && !finished.IsZero() {
		dur = int64(finished.Sub(started).Seconds())
	}
	workspace, slug := splitRepo(repo)
	return model.CIEvent{TenantID: tenant, Provider: "bitbucket", DeliveryID: delivery, Repository: repo, Organization: workspace, Workflow: "Bitbucket pipeline", Job: firstNonEmpty(p.Step.Name, p.CommitStatus.Name), RunID: p.Pipeline.BuildNumber, JobID: firstNonEmpty(p.Step.UUID, p.CommitStatus.Key), CommitSHA: firstNonEmpty(p.Pipeline.Target.Commit.Hash, p.CommitStatus.Commit.Hash), Branch: p.Pipeline.Target.RefName, Conclusion: normalizeConclusion(state), Status: state, RunURL: firstNonEmpty(p.Step.Links.HTML.Href, p.Pipeline.Links.HTML.Href, p.CommitStatus.URL, p.Repository.Links.HTML.Href), PipelineID: p.Pipeline.UUID, StartedAt: started, CompletedAt: finished, DurationSeconds: dur, InlineLog: p.InlineLog, OccurredAt: firstTime(finished, time.Now().UTC()), Metadata: map[string]string{"workspace": workspace, "repo_slug": slug, "pipeline_uuid": p.Pipeline.UUID, "step_uuid": p.Step.UUID}}, nil
}

func parseDrone(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		Event string `json:"event"`
		Repo  struct {
			Slug      string `json:"slug"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Link      string `json:"link"`
		} `json:"repo"`
		Repository struct {
			Slug      string `json:"slug"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Link      string `json:"link"`
		} `json:"repository"`
		Build struct {
			ID       int64  `json:"id"`
			Number   int64  `json:"number"`
			Status   string `json:"status"`
			After    string `json:"after"`
			Ref      string `json:"ref"`
			Source   string `json:"source"`
			Link     string `json:"link"`
			Started  int64  `json:"started"`
			Finished int64  `json:"finished"`
		} `json:"build"`
		Stage struct {
			Number int64  `json:"number"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"stage"`
		Step struct {
			Number int64  `json:"number"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"step"`
		InlineLog string `json:"inline_log"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	r := p.Repository
	if r.Slug == "" {
		r = p.Repo
	}
	repo := r.Slug
	if repo == "" {
		repo = strings.Trim(r.Namespace+"/"+r.Name, "/")
	}
	state := firstNonEmpty(p.Step.Status, p.Stage.Status, p.Build.Status)
	if repo == "" || state == "" {
		return model.CIEvent{}, errors.New("Drone event missing repository or status")
	}
	start, finish := unixTime(p.Build.Started), unixTime(p.Build.Finished)
	dur := int64(0)
	if !start.IsZero() && !finish.IsZero() {
		dur = int64(finish.Sub(start).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "drone", DeliveryID: delivery, Repository: repo, Organization: firstPath(repo), Workflow: firstNonEmpty(p.Stage.Name, "Drone build"), Job: p.Step.Name, RunID: p.Build.Number, JobID: strconv.FormatInt(p.Step.Number, 10), CommitSHA: p.Build.After, Branch: firstNonEmpty(p.Build.Source, p.Build.Ref), Conclusion: normalizeConclusion(state), Status: state, RunURL: firstNonEmpty(p.Build.Link, r.Link), PipelineID: strconv.FormatInt(p.Build.ID, 10), StartedAt: start, CompletedAt: finish, DurationSeconds: dur, InlineLog: p.InlineLog, OccurredAt: firstTime(finish, time.Now().UTC()), Metadata: map[string]string{"repo_slug": repo, "build_number": strconv.FormatInt(p.Build.Number, 10), "stage_number": strconv.FormatInt(p.Stage.Number, 10), "step_number": strconv.FormatInt(p.Step.Number, 10)}}, nil
}

func parseSemaphore(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		OrganizationName string `json:"organization_name"`
		ProjectName      string `json:"project_name"`
		PipelineID       string `json:"pipeline_id"`
		WorkflowID       string `json:"workflow_id"`
		BranchName       string `json:"branch_name"`
		CommitSHA        string `json:"commit_sha"`
		Result           string `json:"result"`
		State            string `json:"state"`
		URL              string `json:"url"`
		InlineLog        string `json:"inline_log"`
		Pipeline         struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Result    string    `json:"result"`
			State     string    `json:"state"`
			CreatedAt time.Time `json:"created_at"`
			DoneAt    time.Time `json:"done_at"`
		} `json:"pipeline"`
		Project struct {
			Name string `json:"name"`
		} `json:"project"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	project := firstNonEmpty(p.ProjectName, p.Project.Name)
	repo := strings.Trim(p.OrganizationName+"/"+project, "/")
	state := firstNonEmpty(p.Result, p.Pipeline.Result, p.State, p.Pipeline.State)
	if repo == "" || state == "" {
		return model.CIEvent{}, errors.New("Semaphore event missing project or result")
	}
	start, finish := p.Pipeline.CreatedAt, p.Pipeline.DoneAt
	dur := int64(0)
	if !start.IsZero() && !finish.IsZero() {
		dur = int64(finish.Sub(start).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "semaphore", DeliveryID: delivery, Repository: repo, Organization: p.OrganizationName, Workflow: firstNonEmpty(p.Pipeline.Name, "Semaphore pipeline"), Job: "pipeline", CommitSHA: p.CommitSHA, Branch: p.BranchName, Conclusion: normalizeConclusion(state), Status: state, RunURL: p.URL, PipelineID: firstNonEmpty(p.PipelineID, p.Pipeline.ID, p.WorkflowID), StartedAt: start, CompletedAt: finish, DurationSeconds: dur, InlineLog: p.InlineLog, OccurredAt: firstTime(finish, time.Now().UTC()), Metadata: map[string]string{"workflow_id": p.WorkflowID}}, nil
}

func parseAppVeyor(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var p struct {
		EventName string `json:"eventName"`
		EventData struct {
			AccountName  string    `json:"accountName"`
			ProjectName  string    `json:"projectName"`
			BuildVersion string    `json:"buildVersion"`
			BuildID      int64     `json:"buildId"`
			Status       string    `json:"status"`
			Branch       string    `json:"branch"`
			CommitID     string    `json:"commitId"`
			BuildURL     string    `json:"buildUrl"`
			Started      time.Time `json:"started"`
			Finished     time.Time `json:"finished"`
			Jobs         []struct {
				JobID  string `json:"jobId"`
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"jobs"`
		} `json:"eventData"`
		InlineLog string `json:"inline_log"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return model.CIEvent{}, err
	}
	d := p.EventData
	repo := strings.Trim(d.AccountName+"/"+d.ProjectName, "/")
	state := d.Status
	jobID, jobName := "", ""
	if len(d.Jobs) > 0 {
		jobID = d.Jobs[0].JobID
		jobName = d.Jobs[0].Name
		if d.Jobs[0].Status != "" {
			state = d.Jobs[0].Status
		}
	}
	if repo == "" || state == "" {
		return model.CIEvent{}, errors.New("AppVeyor event missing project or status")
	}
	dur := int64(0)
	if !d.Started.IsZero() && !d.Finished.IsZero() {
		dur = int64(d.Finished.Sub(d.Started).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "appveyor", DeliveryID: delivery, Repository: repo, Organization: d.AccountName, Workflow: d.BuildVersion, Job: jobName, RunID: d.BuildID, JobID: jobID, CommitSHA: d.CommitID, Branch: d.Branch, Conclusion: normalizeConclusion(state), Status: state, RunURL: d.BuildURL, StartedAt: d.Started, CompletedAt: d.Finished, DurationSeconds: dur, InlineLog: p.InlineLog, OccurredAt: firstTime(d.Finished, time.Now().UTC()), Metadata: map[string]string{"job_id": jobID}}, nil
}

func parseCloudBuild(tenant, delivery string, b []byte) (model.CIEvent, error) {
	var env struct {
		ID      string `json:"id"`
		Message struct {
			Data        string    `json:"data"`
			MessageID   string    `json:"messageId"`
			PublishTime time.Time `json:"publishTime"`
		} `json:"message"`
	}
	payload := b
	if json.Unmarshal(b, &env) == nil && env.Message.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(env.Message.Data)
		if err != nil {
			return model.CIEvent{}, err
		}
		payload = decoded
		if delivery == "" {
			delivery = firstNonEmpty(env.Message.MessageID, env.ID)
		}
	}
	var p struct {
		ID               string            `json:"id"`
		ProjectID        string            `json:"projectId"`
		Status           string            `json:"status"`
		LogURL           string            `json:"logUrl"`
		CreateTime       time.Time         `json:"createTime"`
		StartTime        time.Time         `json:"startTime"`
		FinishTime       time.Time         `json:"finishTime"`
		Substitutions    map[string]string `json:"substitutions"`
		SourceProvenance struct {
			ResolvedRepoSource struct {
				RepoName   string `json:"repoName"`
				CommitSHA  string `json:"commitSha"`
				BranchName string `json:"branchName"`
			} `json:"resolvedRepoSource"`
		} `json:"sourceProvenance"`
		Results struct {
			BuildStepImages []string `json:"buildStepImages"`
		} `json:"results"`
		Steps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Timing struct {
				StartTime time.Time `json:"startTime"`
				EndTime   time.Time `json:"endTime"`
			} `json:"timing"`
		} `json:"steps"`
		InlineLog string `json:"inline_log"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return model.CIEvent{}, err
	}
	if p.ID == "" || p.Status == "" {
		return model.CIEvent{}, errors.New("Cloud Build event missing id or status")
	}
	repo := firstNonEmpty(p.Substitutions["REPO_NAME"], p.SourceProvenance.ResolvedRepoSource.RepoName, p.ProjectID)
	org := p.ProjectID
	job := ""
	var logs strings.Builder
	for _, st := range p.Steps {
		if st.Status != "SUCCESS" && st.Status != "" {
			job = st.Name
		}
		if st.Status != "" {
			fmt.Fprintf(&logs, "%s: %s\n", st.Name, st.Status)
		}
	}
	inline := p.InlineLog
	if inline == "" {
		inline = logs.String()
	}
	start := firstTime(p.StartTime, p.CreateTime)
	dur := int64(0)
	if !start.IsZero() && !p.FinishTime.IsZero() {
		dur = int64(p.FinishTime.Sub(start).Seconds())
	}
	return model.CIEvent{TenantID: tenant, Provider: "cloudbuild", DeliveryID: delivery, Repository: repo, Organization: org, Workflow: "Google Cloud Build", Job: job, JobID: p.ID, CommitSHA: firstNonEmpty(p.Substitutions["COMMIT_SHA"], p.SourceProvenance.ResolvedRepoSource.CommitSHA), Branch: firstNonEmpty(p.Substitutions["BRANCH_NAME"], p.SourceProvenance.ResolvedRepoSource.BranchName), Conclusion: normalizeConclusion(p.Status), Status: p.Status, RunURL: p.LogURL, LogURL: p.LogURL, StartedAt: start, CompletedAt: p.FinishTime, DurationSeconds: dur, RunnerClass: "google-cloud-build", InlineLog: inline, OccurredAt: firstTime(p.FinishTime, time.Now().UTC()), Metadata: map[string]string{"project_id": p.ProjectID, "build_id": p.ID, "build_name": "projects/" + p.ProjectID + "/locations/global/builds/" + p.ID, "location": "global"}}, nil
}

func splitRepo(v string) (string, string) {
	parts := strings.SplitN(strings.Trim(v, "/"), "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return "", parts[0]
	}
	return "", ""
}
func unixTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func parseTeamCityTime(v string) time.Time {
	for _, f := range []string{"20060102T150405-0700", time.RFC3339, time.RFC3339Nano} {
		if t, err := time.Parse(f, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

func firstTime(a, b time.Time) time.Time {
	if !a.IsZero() {
		return a
	}
	return b
}

func FetchLog(ctx context.Context, co config.CIConnector, ev model.CIEvent, max int64) (string, error) {
	if ev.InlineLog != "" {
		if int64(len(ev.InlineLog)) > max {
			return ev.InlineLog[:max], nil
		}
		return ev.InlineLog, nil
	}
	client := &http.Client{Timeout: 45 * time.Second}
	switch co.Provider {
	case "gitlab":
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/api/v4/projects/" + url.PathEscape(ev.ProjectID) + "/jobs/" + url.PathEscape(ev.JobID) + "/trace"
		return fetchText(ctx, client, endpoint, max, map[string]string{"PRIVATE-TOKEN": co.Token})
	case "buildkite":
		m := ev.Metadata
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/v2/organizations/" + url.PathEscape(m["organization"]) + "/pipelines/" + url.PathEscape(m["pipeline_slug"]) + "/builds/" + url.PathEscape(m["build_number"]) + "/jobs/" + url.PathEscape(m["job_uuid"]) + "/log"
		raw, err := fetchBytes(ctx, client, endpoint, max, map[string]string{"Authorization": "Bearer " + co.Token})
		if err != nil {
			return "", err
		}
		var obj struct {
			Content string `json:"content"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.Content != "" {
			return obj.Content, nil
		}
		return string(raw), nil
	case "circleci":
		return fetchCircleCILog(ctx, client, co, ev, max)
	case "azuredevops":
		project := firstNonEmpty(co.Project, ev.Metadata["project"])
		buildID := firstNonEmpty(ev.Metadata["build_id"], ev.JobID)
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/" + url.PathEscape(project) + "/_apis/build/builds/" + url.PathEscape(buildID) + "/logs?api-version=7.1"
		headers := connectorHeaders(co)
		if co.Token != "" {
			headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+co.Token))
		}
		raw, err := fetchBytes(ctx, client, endpoint, 4<<20, headers)
		if err != nil {
			return "", err
		}
		var list struct {
			Value []struct {
				ID int64 `json:"id"`
			} `json:"value"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", err
		}
		var out strings.Builder
		for _, item := range list.Value {
			text, e := fetchText(ctx, client, strings.TrimSuffix(endpoint, "?api-version=7.1")+"/"+strconv.FormatInt(item.ID, 10)+"?api-version=7.1", max-int64(out.Len()), headers)
			if e == nil {
				out.WriteString(text)
				out.WriteByte('\n')
			}
			if int64(out.Len()) >= max {
				break
			}
		}
		if out.Len() == 0 {
			return "", errors.New("Azure DevOps returned no build logs")
		}
		return truncateText(out.String(), max), nil
	case "bitrise":
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/v0.1/apps/" + url.PathEscape(ev.Metadata["app_slug"]) + "/builds/" + url.PathEscape(ev.Metadata["build_slug"]) + "/log"
		headers := connectorHeaders(co)
		if co.Token != "" {
			headers["Authorization"] = "token " + co.Token
		}
		raw, err := fetchBytes(ctx, client, endpoint, max, headers)
		if err != nil {
			return "", err
		}
		var obj struct {
			LogChunks []struct {
				Chunk string `json:"chunk"`
			} `json:"log_chunks"`
			Log string `json:"log"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			if obj.Log != "" {
				return truncateText(obj.Log, max), nil
			}
			var out strings.Builder
			for _, c := range obj.LogChunks {
				out.WriteString(c.Chunk)
			}
			if out.Len() > 0 {
				return truncateText(out.String(), max), nil
			}
		}
		return string(raw), nil
	case "teamcity":
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/app/rest/builds/id:" + url.PathEscape(ev.JobID) + "/log"
		headers := connectorHeaders(co)
		if co.Token != "" {
			headers["Authorization"] = "Bearer " + co.Token
		}
		return fetchText(ctx, client, endpoint, max, headers)
	case "travis":
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/job/" + url.PathEscape(ev.Metadata["job_id"]) + "/log.txt"
		headers := connectorHeaders(co)
		headers["Travis-API-Version"] = "3"
		if co.Token != "" {
			headers["Authorization"] = "token " + co.Token
		}
		return fetchText(ctx, client, endpoint, max, headers)
	case "codebuild", "cloudbuild":
		return "", errors.New("cloud build event did not include inline phase context")
	case "bitbucket":
		m := ev.Metadata
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/2.0/repositories/" + url.PathEscape(m["workspace"]) + "/" + url.PathEscape(m["repo_slug"]) + "/pipelines/" + url.PathEscape(m["pipeline_uuid"]) + "/steps/" + url.PathEscape(m["step_uuid"]) + "/log"
		headers := connectorHeaders(co)
		if co.Token != "" {
			if co.Username != "" {
				headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(co.Username+":"+co.Token))
			} else {
				headers["Authorization"] = "Bearer " + co.Token
			}
		}
		return fetchText(ctx, client, endpoint, max, headers)
	case "drone":
		m := ev.Metadata
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/api/repos/" + strings.Trim(m["repo_slug"], "/") + "/builds/" + url.PathEscape(m["build_number"]) + "/logs/" + url.PathEscape(m["stage_number"]) + "/" + url.PathEscape(m["step_number"])
		headers := connectorHeaders(co)
		if co.Token != "" {
			headers["Authorization"] = "Bearer " + co.Token
		}
		return fetchText(ctx, client, endpoint, max, headers)
	case "appveyor":
		jobID := firstNonEmpty(ev.Metadata["job_id"], ev.JobID)
		endpoint := strings.TrimRight(co.BaseURL, "/") + "/api/buildjobs/" + url.PathEscape(jobID) + "/log"
		headers := connectorHeaders(co)
		if co.Token != "" {
			headers["Authorization"] = "Bearer " + co.Token
		}
		return fetchText(ctx, client, endpoint, max, headers)
	case "semaphore":
		return "", errors.New("Semaphore webhook must include inline_log; external log URLs are not fetched")
	case "jenkins":
		raw := ev.Metadata["build_url"]
		if raw == "" {
			raw = ev.RunURL
		}
		endpoint := strings.TrimRight(raw, "/") + "/consoleText"
		if !sameBase(co.BaseURL, endpoint) {
			return "", errors.New("Jenkins build URL is outside configured base_url")
		}
		headers := map[string]string{}
		if co.Token != "" {
			basic := base64.StdEncoding.EncodeToString([]byte(co.Username + ":" + co.Token))
			headers["Authorization"] = "Basic " + basic
		}
		return fetchText(ctx, client, endpoint, max, headers)
	default:
		return "", fmt.Errorf("unsupported connector %q", co.Provider)
	}
}
func connectorHeaders(co config.CIConnector) map[string]string {
	h := map[string]string{}
	for k, v := range co.Headers {
		h[k] = v
	}
	return h
}
func truncateText(v string, max int64) string {
	if max > 0 && int64(len(v)) > max {
		return v[:max]
	}
	return v
}
func fetchCircleCILog(ctx context.Context, c *http.Client, co config.CIConnector, ev model.CIEvent, max int64) (string, error) {
	slug := ev.Metadata["project_slug"]
	num := ev.Metadata["job_number"]
	if slug == "" || num == "" {
		return "", errors.New("CircleCI webhook did not include project slug/job number")
	}
	endpoint := strings.TrimRight(co.BaseURL, "/") + "/api/v2/project/" + slug + "/" + url.PathEscape(num) + "/steps"
	raw, err := fetchBytes(ctx, c, endpoint, 4<<20, map[string]string{"Circle-Token": co.Token})
	if err != nil {
		return "", err
	}
	var resp struct {
		Items []struct {
			Actions []struct {
				OutputURL string `json:"output_url"`
				Name      string `json:"name"`
			} `json:"actions"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", err
	}
	var out strings.Builder
	for _, step := range resp.Items {
		for _, a := range step.Actions {
			if a.OutputURL == "" {
				continue
			}
			b, e := fetchBytes(ctx, c, a.OutputURL, max-int64(out.Len()), nil)
			if e != nil {
				continue
			}
			var lines []struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(b, &lines) == nil {
				for _, x := range lines {
					out.WriteString(x.Message)
					if !strings.HasSuffix(x.Message, "\n") {
						out.WriteByte('\n')
					}
				}
			} else {
				out.Write(b)
			}
			if int64(out.Len()) >= max {
				return out.String()[:max], nil
			}
		}
	}
	if out.Len() == 0 {
		return "", errors.New("CircleCI did not expose step output URLs")
	}
	return out.String(), nil
}
func fetchText(ctx context.Context, c *http.Client, endpoint string, max int64, h map[string]string) (string, error) {
	b, e := fetchBytes(ctx, c, endpoint, max, h)
	return string(b), e
}
func fetchBytes(ctx context.Context, c *http.Client, endpoint string, max int64, h map[string]string) ([]byte, error) {
	if max <= 0 {
		max = 32 << 20
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return nil, e
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, e := c.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if e != nil {
		return nil, e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if int64(len(b)) > max {
		b = b[:max]
	}
	return b, nil
}
func sameBase(base, endpoint string) bool {
	b, e1 := url.Parse(base)
	e, e2 := url.Parse(endpoint)
	return e1 == nil && e2 == nil && strings.EqualFold(b.Scheme, e.Scheme) && strings.EqualFold(b.Host, e.Host) && strings.HasPrefix(e.Path, strings.TrimRight(b.Path, "/"))
}
func normalizeConclusion(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passed", "success", "successful", "fixed":
		return "success"
	case "failed", "failure", "error", "broken", "unstable":
		return "failure"
	case "canceled", "cancelled", "aborted":
		return "cancelled"
	case "timedout", "timed_out", "timeout":
		return "timed_out"
	default:
		return strings.ToLower(s)
	}
}
func firstPath(s string) string {
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func stringParam(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func UpsertGitLabMRComment(ctx context.Context, co config.CIConnector, ev model.CIEvent, marker, body string, update bool) error {
	if co.Provider != "gitlab" || ev.ProjectID == "" || ev.MergeRequestIID < 1 {
		return nil
	}
	base := strings.TrimRight(co.BaseURL, "/") + "/api/v4/projects/" + url.PathEscape(ev.ProjectID) + "/merge_requests/" + strconv.Itoa(ev.MergeRequestIID) + "/notes"
	client := &http.Client{Timeout: 20 * time.Second}
	headers := map[string]string{"PRIVATE-TOKEN": co.Token}
	if update {
		raw, err := fetchBytes(ctx, client, base+"?per_page=100&sort=desc", 4<<20, headers)
		if err == nil {
			var notes []struct {
				ID   int64  `json:"id"`
				Body string `json:"body"`
			}
			if json.Unmarshal(raw, &notes) == nil {
				for _, n := range notes {
					if strings.Contains(n.Body, marker) {
						return postForm(ctx, client, http.MethodPut, base+"/"+strconv.FormatInt(n.ID, 10), headers, url.Values{"body": {marker + "\n" + body}})
					}
				}
			}
		}
	}
	return postForm(ctx, client, http.MethodPost, base, headers, url.Values{"body": {marker + "\n" + body}})
}

func postForm(ctx context.Context, client *http.Client, method, endpoint string, headers map[string]string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

type RetryResult struct {
	Provider   string `json:"provider"`
	Endpoint   string `json:"endpoint"`
	HTTPStatus int    `json:"http_status"`
	RequestID  string `json:"request_id,omitempty"`
}

func Retry(ctx context.Context, co config.CIConnector, ev model.CIEvent) (RetryResult, error) {
	endpoint, method, body, headers, err := retryRequest(co, ev)
	if err != nil {
		return RetryResult{}, err
	}
	if !sameBase(co.BaseURL, endpoint) {
		return RetryResult{}, errors.New("retry endpoint is outside configured base_url")
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return RetryResult{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return RetryResult{}, err
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	result := RetryResult{Provider: co.Provider, Endpoint: endpoint, HTTPStatus: resp.StatusCode, RequestID: firstNonEmpty(resp.Header.Get("X-Request-Id"), resp.Header.Get("X-Gitlab-Trace-Id"), resp.Header.Get("X-Circleci-Request-Id"))}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("retry HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return result, nil
}

func retryRequest(co config.CIConnector, ev model.CIEvent) (string, string, string, map[string]string, error) {
	method := strings.ToUpper(strings.TrimSpace(co.RetryMethod))
	body := expandRetryTemplate(co.RetryBody, ev)
	headers := connectorHeaders(co)
	endpoint := expandRetryTemplate(co.RetryURL, ev)
	if endpoint != "" {
		if method == "" {
			method = http.MethodPost
		}
		applyRetryAuthorization(co, headers)
		return endpoint, method, body, headers, nil
	}
	base := strings.TrimRight(co.BaseURL, "/")
	switch strings.ToLower(co.Provider) {
	case "gitlab":
		if ev.ProjectID == "" || ev.JobID == "" {
			return "", "", "", nil, errors.New("GitLab retry requires project_id and job_id")
		}
		endpoint = base + "/api/v4/projects/" + url.PathEscape(ev.ProjectID) + "/jobs/" + url.PathEscape(ev.JobID) + "/retry"
		headers["PRIVATE-TOKEN"] = co.Token
	case "circleci":
		workflowID := firstNonEmpty(ev.Metadata["workflow_id"], ev.PipelineID)
		if workflowID == "" {
			return "", "", "", nil, errors.New("CircleCI retry requires workflow_id")
		}
		endpoint = base + "/api/v2/workflow/" + url.PathEscape(workflowID) + "/rerun"
		body = `{"from_failed":true}`
		headers["Circle-Token"] = co.Token
	case "buildkite":
		m := ev.Metadata
		if m["organization"] == "" || m["pipeline_slug"] == "" || m["build_number"] == "" {
			return "", "", "", nil, errors.New("Buildkite retry requires organization, pipeline_slug, and build_number")
		}
		endpoint = base + "/v2/organizations/" + url.PathEscape(m["organization"]) + "/pipelines/" + url.PathEscape(m["pipeline_slug"]) + "/builds/" + url.PathEscape(m["build_number"]) + "/rebuild"
		headers["Authorization"] = "Bearer " + co.Token
	case "travis":
		buildID := firstNonEmpty(ev.Metadata["build_id"], ev.PipelineID, strconv.FormatInt(ev.RunID, 10))
		if buildID == "" || buildID == "0" {
			return "", "", "", nil, errors.New("Travis retry requires build_id")
		}
		endpoint = base + "/build/" + url.PathEscape(buildID) + "/restart"
		headers["Travis-API-Version"] = "3"
		headers["Authorization"] = "token " + co.Token
	case "cloudbuild":
		name := ev.Metadata["build_name"]
		if name == "" {
			project := firstNonEmpty(ev.Metadata["project_id"], co.Project)
			location := firstNonEmpty(ev.Metadata["location"], co.Region, "global")
			buildID := firstNonEmpty(ev.Metadata["build_id"], ev.JobID, ev.PipelineID)
			if project == "" || buildID == "" {
				return "", "", "", nil, errors.New("Cloud Build retry requires project_id and build_id")
			}
			name = "projects/" + project + "/locations/" + location + "/builds/" + buildID
		}
		endpoint = base + "/v1/" + strings.TrimPrefix(name, "/") + ":retry"
		headers["Authorization"] = "Bearer " + co.Token
	case "azuredevops":
		organization := firstNonEmpty(co.Organization, ev.Organization)
		project := firstNonEmpty(ev.Metadata["project_id"], ev.Metadata["project"], co.Project, ev.ProjectID)
		buildID := firstNonEmpty(ev.Metadata["build_id"], ev.JobID, strconv.FormatInt(ev.RunID, 10))
		if organization == "" || project == "" || buildID == "" || buildID == "0" {
			return "", "", "", nil, errors.New("Azure DevOps retry requires organization, project, and build_id")
		}
		endpoint = base + "/" + url.PathEscape(organization) + "/" + url.PathEscape(project) + "/_apis/build/builds/" + url.PathEscape(buildID) + "?retry=true&api-version=7.1"
		method = http.MethodPatch
		body = `{}`
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+co.Token))
	case "bitbucket":
		workspace := firstNonEmpty(ev.Metadata["workspace"], co.Organization, ev.Organization)
		repo := firstNonEmpty(ev.Metadata["repo_slug"], lastPath(ev.Repository))
		branch := firstNonEmpty(ev.Branch, "main")
		if workspace == "" || repo == "" {
			return "", "", "", nil, errors.New("Bitbucket retry requires workspace and repo_slug")
		}
		endpoint = base + "/2.0/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repo) + "/pipelines/"
		bodyBytes, _ := json.Marshal(map[string]any{"target": map[string]any{"type": "pipeline_ref_target", "ref_type": "branch", "ref_name": branch}})
		body = string(bodyBytes)
		headers["Authorization"] = "Bearer " + co.Token
	case "drone":
		repo := firstNonEmpty(ev.Metadata["repo_slug"], ev.Repository)
		parts := strings.SplitN(strings.Trim(repo, "/"), "/", 2)
		build := firstNonEmpty(ev.Metadata["build_number"], strconv.FormatInt(ev.RunID, 10))
		if len(parts) != 2 || build == "" || build == "0" {
			return "", "", "", nil, errors.New("Drone retry requires owner, repository, and build_number")
		}
		endpoint = base + "/api/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/builds/" + url.PathEscape(build)
		headers["Authorization"] = "Bearer " + co.Token
	case "semaphore":
		workflowID := firstNonEmpty(ev.Metadata["workflow_id"], ev.PipelineID)
		if workflowID == "" {
			return "", "", "", nil, errors.New("Semaphore retry requires workflow_id")
		}
		endpoint = base + "/api/v1alpha/plumber-workflows/" + url.PathEscape(workflowID) + "/reschedule?request_token=" + url.QueryEscape(retryToken(ev))
		headers["Authorization"] = "Token " + co.Token
	case "appveyor":
		buildID := firstNonEmpty(ev.Metadata["build_id"], strconv.FormatInt(ev.RunID, 10))
		if buildID == "" || buildID == "0" {
			return "", "", "", nil, errors.New("AppVeyor retry requires build_id")
		}
		endpoint = base + "/api/builds"
		method = http.MethodPut
		body = `{"buildId":` + buildID + `,"reRunIncomplete":true}`
		headers["Authorization"] = "Bearer " + co.Token
	case "bitrise":
		app := firstNonEmpty(ev.Metadata["app_slug"], co.Project)
		pipeline := firstNonEmpty(ev.Metadata["pipeline_id"], ev.Metadata["build_slug"], ev.PipelineID)
		if app == "" || pipeline == "" {
			return "", "", "", nil, errors.New("Bitrise retry requires app_slug and pipeline_id")
		}
		endpoint = base + "/v0.1/apps/" + url.PathEscape(app) + "/pipelines/" + url.PathEscape(pipeline) + "/rebuild"
		headers["Authorization"] = co.Token
	case "teamcity":
		buildType := firstNonEmpty(ev.PipelineID, ev.Metadata["build_type_id"])
		if buildType == "" {
			return "", "", "", nil, errors.New("TeamCity retry requires build_type_id")
		}
		endpoint = base + "/app/rest/buildQueue"
		bodyBytes, _ := json.Marshal(map[string]any{"buildType": map[string]string{"id": buildType}, "branchName": ev.Branch, "comment": map[string]string{"text": "Safe rerun requested by CI Radar"}})
		body = string(bodyBytes)
		headers["Authorization"] = "Bearer " + co.Token
	default:
		return "", "", "", nil, fmt.Errorf("%s automatic retry requires retry_url", co.Provider)
	}
	if method == "" {
		method = http.MethodPost
	}
	if body == "" {
		body = `{}`
	}
	return endpoint, method, body, headers, nil
}

func retryToken(ev model.CIEvent) string {
	value := strings.Join([]string{ev.Provider, ev.Repository, ev.PipelineID, ev.JobID, strconv.FormatInt(ev.RunID, 10), ev.CommitSHA}, "|")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:16])
}

func lastPath(value string) string {
	value = strings.Trim(value, "/")
	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[index+1:]
	}
	return value
}

func applyRetryAuthorization(co config.CIConnector, headers map[string]string) {
	if co.Token == "" || headers["Authorization"] != "" {
		return
	}
	switch strings.ToLower(co.Provider) {
	case "gitlab":
		headers["PRIVATE-TOKEN"] = co.Token
	case "circleci":
		headers["Circle-Token"] = co.Token
	case "travis":
		headers["Travis-API-Version"] = "3"
		headers["Authorization"] = "token " + co.Token
	case "jenkins":
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(co.Username+":"+co.Token))
	default:
		headers["Authorization"] = "Bearer " + co.Token
	}
}

func expandRetryTemplate(raw string, ev model.CIEvent) string {
	if raw == "" {
		return ""
	}
	values := map[string]string{
		"tenant_id":    ev.TenantID,
		"provider":     ev.Provider,
		"repository":   ev.Repository,
		"organization": ev.Organization,
		"workflow":     ev.Workflow,
		"job":          ev.Job,
		"run_id":       strconv.FormatInt(ev.RunID, 10),
		"job_id":       ev.JobID,
		"commit_sha":   ev.CommitSHA,
		"branch":       ev.Branch,
		"project_id":   ev.ProjectID,
		"pipeline_id":  ev.PipelineID,
	}
	for k, v := range ev.Metadata {
		values[k] = v
	}
	for k, v := range values {
		raw = strings.ReplaceAll(raw, "${"+k+"}", v)
	}
	return raw
}
