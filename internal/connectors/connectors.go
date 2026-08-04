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
	case "jenkins":
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
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
func stringParam(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// UpsertGitLabMRComment creates or updates one sticky CI Radar note on a GitLab merge request.
// It deliberately uses a marker so repeated jobs do not spam the discussion.
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
