package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	gh "ciradar/internal/github"
	"ciradar/internal/model"
)

type githubIssueCreateBody struct {
	Repository       string               `json:"repository,omitempty"`
	InstallationID   int64                `json:"installation_id,omitempty"`
	Title            string               `json:"title,omitempty"`
	Body             string               `json:"body,omitempty"`
	Labels           []string             `json:"labels,omitempty"`
	Assignees        []string             `json:"assignees,omitempty"`
	Milestone        *int                 `json:"milestone,omitempty"`
	Type             *string              `json:"type,omitempty"`
	IssueFieldValues []gh.IssueFieldValue `json:"issue_field_values,omitempty"`
}

type githubIssueUpdateBody struct {
	Title            *string               `json:"title,omitempty"`
	Body             *string               `json:"body,omitempty"`
	State            *string               `json:"state,omitempty"`
	StateReason      *string               `json:"state_reason,omitempty"`
	DuplicateIssueID *int64                `json:"duplicate_issue_id,omitempty"`
	Labels           *[]string             `json:"labels,omitempty"`
	Assignees        *[]string             `json:"assignees,omitempty"`
	Milestone        json.RawMessage       `json:"milestone,omitempty"`
	Type             *string               `json:"type,omitempty"`
	IssueFieldValues *[]gh.IssueFieldValue `json:"issue_field_values,omitempty"`
	Locked           *bool                 `json:"locked,omitempty"`
	LockReason       string                `json:"lock_reason,omitempty"`
}

func (s *Server) getAnalysisGitHubIssue(w http.ResponseWriter, r *http.Request) {
	if s.github == nil {
		writeError(w, http.StatusServiceUnavailable, "GitHub App API client is not configured")
		return
	}
	analysisID := strings.TrimSpace(r.PathValue("id"))
	link, found, err := s.loadGitHubIssueLink(r, analysisID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "GitHub issue link not found")
		return
	}
	owner, repo, ok := splitRepository(link.Repository)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stored GitHub repository is invalid")
		return
	}
	issue, err := s.github.GetIssue(r.Context(), link.InstallationID, owner, repo, link.Number)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	link = githubIssueLinkFromRemote(link, issue)
	if err := s.store.PutObject(r.Context(), principal(r).TenantID, "github_issue", analysisID, link); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"link": link, "issue": issue})
}

func (s *Server) createAnalysisGitHubIssue(w http.ResponseWriter, r *http.Request) {
	if s.github == nil {
		writeError(w, http.StatusServiceUnavailable, "GitHub App API client is not configured")
		return
	}
	p := principal(r)
	analysisID := strings.TrimSpace(r.PathValue("id"))
	analysis, err := s.store.GetAnalysisForTenant(r.Context(), p.TenantID, analysisID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if analysis == nil {
		writeError(w, http.StatusNotFound, "analysis not found")
		return
	}
	if _, found, err := s.loadGitHubIssueLink(r, analysisID); err != nil {
		s.internalError(w, r, err)
		return
	} else if found {
		writeError(w, http.StatusConflict, "analysis already has a linked GitHub issue")
		return
	}
	var body githubIssueCreateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	var source model.RepairSource
	foundSource, err := s.store.GetObject(r.Context(), p.TenantID, "analysis_source", analysisID, &source)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	repository := strings.TrimSpace(body.Repository)
	installationID := body.InstallationID
	if repository == "" && foundSource {
		repository = source.Repository
	}
	if installationID <= 0 && foundSource {
		installationID = source.InstallationID
	}
	owner, repo, ok := splitRepository(repository)
	if !ok || installationID <= 0 {
		writeError(w, http.StatusBadRequest, "repository OWNER/REPO and installation_id are required for GitHub issue creation")
		return
	}
	if s.cfg.RequireInstallationBinding {
		boundTenant, bound := s.store.ResolveInstallationTenant(r.Context(), installationID)
		if !bound || boundTenant != p.TenantID {
			writeError(w, http.StatusForbidden, "GitHub installation is not bound to this tenant")
			return
		}
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		title = defaultGitHubIssueTitle(*analysis)
	}
	issueBody := strings.TrimSpace(body.Body)
	if issueBody == "" {
		issueBody = renderGitHubIssueBody(*analysis)
	}
	labels := sanitizeIssueList(body.Labels, 20, 100)
	if len(labels) == 0 {
		labels = []string{"ci-radar", strings.ToLower(string(analysis.Category))}
	}
	request := gh.CreateIssueRequest{Title: truncateRunes(title, 256), Body: truncateRunes(issueBody, 60000), Labels: labels, Assignees: sanitizeIssueList(body.Assignees, 10, 100), Milestone: body.Milestone, Type: body.Type, IssueFieldValues: body.IssueFieldValues}
	issue, err := s.github.CreateIssue(r.Context(), installationID, owner, repo, request)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	now := time.Now().UTC()
	link := model.ExternalIssueLink{TenantID: p.TenantID, AnalysisID: analysisID, Provider: "github", Repository: repository, InstallationID: installationID, Number: issue.Number, URL: issue.HTMLURL, State: issue.State, StateReason: issue.StateReason, Title: issue.Title, Locked: issue.Locked, CreatedAt: now, UpdatedAt: now, LastSyncedAt: now}
	if err := s.store.PutObject(r.Context(), p.TenantID, "github_issue", analysisID, link); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "github.issue_created", "analysis", analysisID, map[string]string{"repository": repository, "issue_number": fmt.Sprint(issue.Number)})
	writeJSON(w, http.StatusCreated, map[string]any{"link": link, "issue": issue})
}

func (s *Server) updateAnalysisGitHubIssue(w http.ResponseWriter, r *http.Request) {
	if s.github == nil {
		writeError(w, http.StatusServiceUnavailable, "GitHub App API client is not configured")
		return
	}
	analysisID := strings.TrimSpace(r.PathValue("id"))
	link, found, err := s.loadGitHubIssueLink(r, analysisID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "GitHub issue link not found")
		return
	}
	var body githubIssueUpdateBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	owner, repo, ok := splitRepository(link.Repository)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stored GitHub repository is invalid")
		return
	}
	if body.Title != nil {
		value := truncateRunes(strings.TrimSpace(*body.Title), 256)
		if value == "" {
			writeError(w, http.StatusBadRequest, "GitHub issue title cannot be empty")
			return
		}
		body.Title = &value
	}
	if body.Body != nil {
		value := truncateRunes(*body.Body, 60000)
		body.Body = &value
	}
	if body.Labels != nil {
		value := sanitizeIssueList(*body.Labels, 20, 100)
		body.Labels = &value
	}
	if body.Assignees != nil {
		value := sanitizeIssueList(*body.Assignees, 10, 100)
		body.Assignees = &value
	}
	milestoneSet := len(body.Milestone) > 0
	var milestone *int
	if milestoneSet && string(body.Milestone) != "null" {
		var value int
		if err := json.Unmarshal(body.Milestone, &value); err != nil || value <= 0 {
			writeError(w, http.StatusBadRequest, "milestone must be a positive integer or null")
			return
		}
		milestone = &value
	}
	issue, err := s.github.UpdateIssue(r.Context(), link.InstallationID, owner, repo, link.Number, gh.UpdateIssueRequest{Title: body.Title, Body: body.Body, State: body.State, StateReason: body.StateReason, DuplicateIssueID: body.DuplicateIssueID, Labels: body.Labels, Assignees: body.Assignees, Milestone: milestone, MilestoneSet: milestoneSet, Type: body.Type, IssueFieldValues: body.IssueFieldValues})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if body.Locked != nil {
		if *body.Locked {
			err = s.github.LockIssue(r.Context(), link.InstallationID, owner, repo, link.Number, body.LockReason)
		} else {
			err = s.github.UnlockIssue(r.Context(), link.InstallationID, owner, repo, link.Number)
		}
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		issue.Locked = *body.Locked
	}
	link = githubIssueLinkFromRemote(link, issue)
	if err := s.store.PutObject(r.Context(), principal(r).TenantID, "github_issue", analysisID, link); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "github.issue_updated", "analysis", analysisID, map[string]string{"repository": link.Repository, "issue_number": fmt.Sprint(link.Number), "state": link.State})
	writeJSON(w, http.StatusOK, map[string]any{"link": link, "issue": issue})
}

func (s *Server) commentAnalysisGitHubIssue(w http.ResponseWriter, r *http.Request) {
	if s.github == nil {
		writeError(w, http.StatusServiceUnavailable, "GitHub App API client is not configured")
		return
	}
	analysisID := strings.TrimSpace(r.PathValue("id"))
	link, found, err := s.loadGitHubIssueLink(r, analysisID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "GitHub issue link not found")
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	body.Body = strings.TrimSpace(body.Body)
	if body.Body == "" {
		writeError(w, http.StatusBadRequest, "comment body is required")
		return
	}
	owner, repo, ok := splitRepository(link.Repository)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stored GitHub repository is invalid")
		return
	}
	comment, err := s.github.CreateIssueComment(r.Context(), link.InstallationID, owner, repo, link.Number, truncateRunes(body.Body, 60000))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "github.issue_commented", "analysis", analysisID, map[string]string{"repository": link.Repository, "issue_number": fmt.Sprint(link.Number)})
	writeJSON(w, http.StatusCreated, comment)
}

func (s *Server) loadGitHubIssueLink(r *http.Request, analysisID string) (model.ExternalIssueLink, bool, error) {
	var link model.ExternalIssueLink
	found, err := s.store.GetObject(r.Context(), principal(r).TenantID, "github_issue", analysisID, &link)
	return link, found, err
}

func splitRepository(value string) (string, string, bool) {
	owner, repo, ok := strings.Cut(strings.TrimSpace(value), "/")
	return owner, repo, ok && owner != "" && repo != "" && !strings.Contains(repo, "/")
}

func githubIssueLinkFromRemote(link model.ExternalIssueLink, issue gh.Issue) model.ExternalIssueLink {
	link.Number = issue.Number
	link.URL = issue.HTMLURL
	link.State = issue.State
	link.StateReason = issue.StateReason
	link.Title = issue.Title
	link.Locked = issue.Locked
	link.UpdatedAt = time.Now().UTC()
	link.LastSyncedAt = link.UpdatedAt
	return link
}

func defaultGitHubIssueTitle(analysis model.AnalysisResult) string {
	prefix := "CI failure"
	if analysis.Category != "" {
		prefix = string(analysis.Category)
	}
	return fmt.Sprintf("[%s] %s", prefix, analysis.Summary)
}

func renderGitHubIssueBody(analysis model.AnalysisResult) string {
	var b strings.Builder
	b.WriteString("## CI Radar diagnosis\n\n")
	fmt.Fprintf(&b, "**Summary:** %s\n\n", analysis.Summary)
	fmt.Fprintf(&b, "**Category:** `%s`  \n**Attribution:** `%s`  \n**Confidence:** `%s`  \n**Evidence strength:** `%d/100`  \n**Fingerprint:** `%s`\n\n", analysis.Category, analysis.Attribution, analysis.Confidence, model.EvidenceStrengthOf(analysis), analysis.Fingerprint)
	if analysis.Repository != "" {
		fmt.Fprintf(&b, "**Repository:** `%s`  \n", analysis.Repository)
	}
	if analysis.Workflow != "" || analysis.Job != "" {
		fmt.Fprintf(&b, "**Workflow / job:** `%s` / `%s`  \n", analysis.Workflow, analysis.Job)
	}
	if analysis.CommitSHA != "" {
		fmt.Fprintf(&b, "**Commit:** `%s`  \n", analysis.CommitSHA)
	}
	if analysis.SourceRunURL != "" {
		fmt.Fprintf(&b, "**CI run:** %s  \n", analysis.SourceRunURL)
	}
	if len(analysis.Evidence) > 0 {
		b.WriteString("\n### Evidence\n")
		for i, evidence := range analysis.Evidence {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, "- %s (`%+d`)\n", evidence.Description, evidence.Weight)
		}
	}
	if analysis.Recommendation != "" {
		fmt.Fprintf(&b, "\n### Recommended next action\n%s\n", analysis.Recommendation)
	}
	fmt.Fprintf(&b, "\n<!-- ci-radar-analysis:%s -->\n", analysis.ID)
	return b.String()
}

func sanitizeIssueList(values []string, maximumItems, maximumLength int) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maximumLength || seen[strings.ToLower(value)] {
			continue
		}
		seen[strings.ToLower(value)] = true
		out = append(out, value)
		if len(out) >= maximumItems {
			break
		}
	}
	return out
}

func truncateRunes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}
