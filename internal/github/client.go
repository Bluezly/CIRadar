package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Bluezly/CIRadar/internal/httpguard"
)

type Client struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    string
	http       *http.Client
	download   *http.Client
	mu         sync.Mutex
	tokens     map[int64]cachedToken
}

type cachedToken struct {
	Token     string
	ExpiresAt time.Time
}

type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Status     string
	Body       string
}

func (e *APIError) Error() string {
	if e == nil {
		return "GitHub API error"
	}
	return fmt.Sprintf("GitHub API %s %s: %s: %s", e.Method, e.Path, e.Status, e.Body)
}

func IsStatus(err error, code int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == code
}

type Job struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	Conclusion      string    `json:"conclusion"`
	RunnerName      string    `json:"runner_name"`
	RunnerGroupName string    `json:"runner_group_name"`
	Labels          []string  `json:"labels"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	Steps           []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Number     int    `json:"number"`
	} `json:"steps"`
}

type jobsResponse struct {
	TotalCount int   `json:"total_count"`
	Jobs       []Job `json:"jobs"`
}

type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CheckOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Text    string `json:"text,omitempty"`
}

type CheckRunRequest struct {
	Name       string      `json:"name"`
	HeadSHA    string      `json:"head_sha"`
	Status     string      `json:"status"`
	Conclusion string      `json:"conclusion"`
	DetailsURL string      `json:"details_url,omitempty"`
	Output     CheckOutput `json:"output"`
}

func New(appID int64, privateKeyPath, baseURL string, allowPrivateNetwork ...bool) (*Client, error) {
	if appID <= 0 {
		return nil, errors.New("GitHub App ID is required")
	}
	b, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read GitHub private key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key: %v / %v", err, err2)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	allowPrivate := len(allowPrivateNetwork) > 0 && allowPrivateNetwork[0]
	if err := httpguard.ValidateURL(baseURL, allowPrivate); err != nil {
		return nil, fmt.Errorf("invalid GitHub API URL: %w", err)
	}
	download := httpguard.NewClientWithOptions(60*time.Second, httpguard.ClientOptions{
		AllowPrivateNetwork:       allowPrivate,
		AllowCrossOriginRedirects: true,
	})
	return &Client{
		appID:      appID,
		privateKey: key,
		baseURL:    strings.TrimRight(baseURL, "/"),
		http:       httpguard.NewClient(60*time.Second, allowPrivate),
		download:   download,
		tokens:     map[int64]cachedToken{},
	}, nil
}

func (c *Client) AppJWT() (string, error) {
	now := time.Now().UTC()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":"%d"}`, now.Add(-30*time.Second).Unix(), now.Add(9*time.Minute).Unix(), c.appID)
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	unsigned := header + "." + payload
	h := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(nil, c.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	c.mu.Lock()
	cached, ok := c.tokens[installationID]
	if ok && time.Until(cached.ExpiresAt) > 5*time.Minute {
		c.mu.Unlock()
		return cached.Token, nil
	}
	c.mu.Unlock()
	jwt, err := c.AppJWT()
	if err != nil {
		return "", err
	}
	var out installationTokenResponse
	if err := c.doJSON(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installationID), jwt, nil, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("GitHub returned empty installation token")
	}
	c.mu.Lock()
	c.tokens[installationID] = cachedToken(out)
	c.mu.Unlock()
	return out.Token, nil
}

func (c *Client) ListJobs(ctx context.Context, installationID int64, owner, repo string, runID int64) ([]Job, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var all []Job
	for page := 1; page <= 20; page++ {
		var out jobsResponse
		path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/jobs?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), runID, page)
		if err := c.doJSON(ctx, "GET", path, token, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Jobs...)
		if len(out.Jobs) < 100 {
			break
		}
	}
	return all, nil
}

func (c *Client) DownloadJobLog(ctx context.Context, installationID int64, owner, repo string, jobID int64, maxBytes int64) (string, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/repos/%s/%s/actions/jobs/%d/logs", url.PathEscape(owner), url.PathEscape(repo), jobID)
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	setHeaders(req, token)
	resp, err := c.download.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, readErr := readLimitedBody(resp.Body, 1<<20)
		if readErr != nil {
			return "", fmt.Errorf("GitHub logs API %s: read error response: %w", resp.Status, readErr)
		}
		return "", fmt.Errorf("GitHub logs API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(b)) > maxBytes {
		return "", fmt.Errorf("job log exceeds %d bytes", maxBytes)
	}
	return string(b), nil
}

func (c *Client) CreateCheckRun(ctx context.Context, installationID int64, owner, repo string, check CheckRunRequest) error {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/repos/%s/%s/check-runs", url.PathEscape(owner), url.PathEscape(repo))
	return c.doJSON(ctx, "POST", path, token, check, nil)
}

func (c *Client) RerunFailedJobs(ctx context.Context, installationID int64, owner, repo string, runID int64) error {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/rerun-failed-jobs", url.PathEscape(owner), url.PathEscape(repo), runID)
	return c.doJSON(ctx, "POST", path, token, map[string]any{}, nil)
}

func (c *Client) ListPullRequestFiles(ctx context.Context, installationID int64, owner, repo string, number int) ([]string, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var names []string
	for page := 1; page <= 20; page++ {
		var out []struct {
			Filename string `json:"filename"`
		}
		path := fmt.Sprintf("/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), number, page)
		if err := c.doJSON(ctx, "GET", path, token, nil, &out); err != nil {
			return nil, err
		}
		for _, x := range out {
			names = append(names, x.Filename)
		}
		if len(out) < 100 {
			break
		}
	}
	return names, nil
}

func (c *Client) doJSON(ctx context.Context, method, path, token string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	setHeaders(req, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, readErr := readLimitedBody(resp.Body, 8<<20)
	if readErr != nil {
		return fmt.Errorf("GitHub API %s %s: read response: %w", method, path, readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(responseBody) > 2<<20 {
			responseBody = responseBody[:2<<20]
		}
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Status: resp.Status, Body: strings.TrimSpace(string(responseBody))}
	}
	if out == nil {
		return nil
	}
	if len(responseBody) == 0 {
		return errors.New("GitHub API returned an empty JSON response")
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return err
	}
	return nil
}

func readLimitedBody(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("response body limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response body exceeds %d bytes", max)
	}
	return body, nil
}

func setHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "CI-Radar/0.1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

type workflowRunsResponse struct {
	TotalCount   int `json:"total_count"`
	WorkflowRuns []struct {
		ID         int64  `json:"id"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"workflow_runs"`
}

func (c *Client) HasPreviousSuccessfulRun(ctx context.Context, installationID int64, owner, repo, headSHA string, excludeRunID int64) (bool, error) {
	if strings.TrimSpace(headSHA) == "" {
		return false, nil
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return false, err
	}
	path := fmt.Sprintf("/repos/%s/%s/actions/runs?head_sha=%s&status=success&per_page=20", url.PathEscape(owner), url.PathEscape(repo), url.QueryEscape(headSHA))
	var out workflowRunsResponse
	if err := c.doJSON(ctx, "GET", path, token, nil, &out); err != nil {
		return false, err
	}
	for _, run := range out.WorkflowRuns {
		if run.ID != excludeRunID && run.HeadSHA == headSHA && run.Conclusion == "success" {
			return true, nil
		}
	}
	return false, nil
}

type IssueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

func (c *Client) ListIssueComments(ctx context.Context, installationID int64, owner, repo string, number int) ([]IssueComment, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	var all []IssueComment
	for page := 1; page <= 20; page++ {
		var out []IssueComment
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), number, page)
		if err := c.doJSON(ctx, "GET", path, token, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out...)
		if len(out) < 100 {
			break
		}
	}
	return all, nil
}
func (c *Client) CreateIssueComment(ctx context.Context, installationID int64, owner, repo string, number int, body string) (IssueComment, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return IssueComment{}, err
	}
	var out IssueComment
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), number)
	err = c.doJSON(ctx, "POST", path, token, map[string]string{"body": body}, &out)
	return out, err
}
func (c *Client) UpdateIssueComment(ctx context.Context, installationID int64, owner, repo string, id int64, body string) error {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", url.PathEscape(owner), url.PathEscape(repo), id)
	return c.doJSON(ctx, "PATCH", path, token, map[string]string{"body": body}, nil)
}
func (c *Client) UpsertPRComment(ctx context.Context, installationID int64, owner, repo string, number int, marker, body string, update bool) error {
	body = marker + "\n" + body
	if update {
		comments, err := c.ListIssueComments(ctx, installationID, owner, repo, number)
		if err != nil {
			return err
		}
		for _, comment := range comments {
			if strings.Contains(comment.Body, marker) {
				return c.UpdateIssueComment(ctx, installationID, owner, repo, comment.ID, body)
			}
		}
	}
	_, err := c.CreateIssueComment(ctx, installationID, owner, repo, number, body)
	return err
}

type RepositoryInfo struct {
	DefaultBranch string `json:"default_branch"`
}

type ContentFile struct {
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type PullRequestResult struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

type branchReference struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

func (c *Client) BranchSHA(ctx context.Context, installationID int64, owner, repo, branch string) (string, bool, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return "", false, err
	}
	var out branchReference
	endpoint := fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", url.PathEscape(owner), url.PathEscape(repo), escapePath(strings.TrimPrefix(branch, "refs/heads/")))
	if err := c.doJSON(ctx, http.MethodGet, endpoint, token, nil, &out); err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(out.Object.SHA), true, nil
}

func (c *Client) FindPullRequestByHead(ctx context.Context, installationID int64, owner, repo, branch, base string) (PullRequestResult, bool, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return PullRequestResult{}, false, err
	}
	query := url.Values{}
	query.Set("state", "all")
	query.Set("head", owner+":"+strings.TrimPrefix(branch, "refs/heads/"))
	if strings.TrimSpace(base) != "" {
		query.Set("base", strings.TrimSpace(base))
	}
	query.Set("per_page", "10")
	var out []PullRequestResult
	endpoint := fmt.Sprintf("/repos/%s/%s/pulls?%s", url.PathEscape(owner), url.PathEscape(repo), query.Encode())
	if err := c.doJSON(ctx, http.MethodGet, endpoint, token, nil, &out); err != nil {
		return PullRequestResult{}, false, err
	}
	if len(out) == 0 {
		return PullRequestResult{}, false, nil
	}
	return out[0], true, nil
}

func (c *Client) Repository(ctx context.Context, installationID int64, owner, repo string) (RepositoryInfo, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return RepositoryInfo{}, err
	}
	var out RepositoryInfo
	err = c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo)), token, nil, &out)
	return out, err
}

func (c *Client) CreateBranch(ctx context.Context, installationID int64, owner, repo, branch, sha string) error {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/repos/%s/%s/git/refs", url.PathEscape(owner), url.PathEscape(repo))
	return c.doJSON(ctx, http.MethodPost, path, token, map[string]any{"ref": "refs/heads/" + strings.TrimPrefix(branch, "refs/heads/"), "sha": sha}, nil)
}

func (c *Client) GetContent(ctx context.Context, installationID int64, owner, repo, path, ref string) (ContentFile, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return ContentFile{}, err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), escapePath(path))
	if ref != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}
	var out ContentFile
	if err := c.doJSON(ctx, http.MethodGet, endpoint, token, nil, &out); err != nil {
		return ContentFile{}, err
	}
	if out.Encoding != "base64" {
		return ContentFile{}, fmt.Errorf("GitHub returned unsupported content encoding %q", out.Encoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return ContentFile{}, err
	}
	out.Content = string(decoded)
	return out, nil
}

func (c *Client) PutContent(ctx context.Context, installationID int64, owner, repo, path, branch, message, content, sha string) error {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	body := map[string]any{"message": message, "content": base64.StdEncoding.EncodeToString([]byte(content)), "branch": branch}
	if sha != "" {
		body["sha"] = sha
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), escapePath(path))
	return c.doJSON(ctx, http.MethodPut, endpoint, token, body, nil)
}

func (c *Client) CreateDraftPullRequest(ctx context.Context, installationID int64, owner, repo, title, body, head, base string) (PullRequestResult, error) {
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return PullRequestResult{}, err
	}
	var out PullRequestResult
	endpoint := fmt.Sprintf("/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	err = c.doJSON(ctx, http.MethodPost, endpoint, token, map[string]any{"title": title, "body": body, "head": head, "base": base, "draft": true, "maintainer_can_modify": true}, &out)
	return out, err
}

func escapePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}
