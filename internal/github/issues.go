package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Issue struct {
	ID          int64     `json:"id"`
	Number      int       `json:"number"`
	HTMLURL     string    `json:"html_url"`
	State       string    `json:"state"`
	StateReason string    `json:"state_reason,omitempty"`
	Title       string    `json:"title"`
	Body        string    `json:"body,omitempty"`
	Locked      bool      `json:"locked"`
	Comments    int       `json:"comments"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ClosedAt    time.Time `json:"closed_at,omitempty"`
	Labels      []struct {
		Name string `json:"name"`
	} `json:"labels,omitempty"`
	Assignees []struct {
		Login string `json:"login"`
	} `json:"assignees,omitempty"`
}

type IssueFieldValue struct {
	FieldID int64 `json:"field_id"`
	Value   any   `json:"value"`
}

type CreateIssueRequest struct {
	Title            string            `json:"title"`
	Body             string            `json:"body,omitempty"`
	Labels           []string          `json:"labels,omitempty"`
	Assignees        []string          `json:"assignees,omitempty"`
	Milestone        *int              `json:"milestone,omitempty"`
	Type             *string           `json:"type,omitempty"`
	IssueFieldValues []IssueFieldValue `json:"issue_field_values,omitempty"`
}

type UpdateIssueRequest struct {
	Title            *string            `json:"title,omitempty"`
	Body             *string            `json:"body,omitempty"`
	State            *string            `json:"state,omitempty"`
	StateReason      *string            `json:"state_reason,omitempty"`
	DuplicateIssueID *int64             `json:"duplicate_issue_id,omitempty"`
	Labels           *[]string          `json:"labels,omitempty"`
	Assignees        *[]string          `json:"assignees,omitempty"`
	Milestone        *int               `json:"-"`
	MilestoneSet     bool               `json:"-"`
	Type             *string            `json:"type,omitempty"`
	IssueFieldValues *[]IssueFieldValue `json:"issue_field_values,omitempty"`
}

func (request UpdateIssueRequest) MarshalJSON() ([]byte, error) {
	payload := map[string]any{}
	if request.Title != nil {
		payload["title"] = *request.Title
	}
	if request.Body != nil {
		payload["body"] = *request.Body
	}
	if request.State != nil {
		payload["state"] = *request.State
	}
	if request.StateReason != nil {
		payload["state_reason"] = *request.StateReason
	}
	if request.DuplicateIssueID != nil {
		payload["duplicate_issue_id"] = *request.DuplicateIssueID
	}
	if request.Labels != nil {
		payload["labels"] = *request.Labels
	}
	if request.Assignees != nil {
		payload["assignees"] = *request.Assignees
	}
	if request.MilestoneSet {
		if request.Milestone == nil {
			payload["milestone"] = nil
		} else {
			payload["milestone"] = *request.Milestone
		}
	}
	if request.Type != nil {
		payload["type"] = *request.Type
	}
	if request.IssueFieldValues != nil {
		payload["issue_field_values"] = *request.IssueFieldValues
	}
	return json.Marshal(payload)
}

func (c *Client) CreateIssue(ctx context.Context, installationID int64, owner, repo string, request CreateIssueRequest) (Issue, error) {
	request.Title = strings.TrimSpace(request.Title)
	if request.Title == "" {
		return Issue{}, fmt.Errorf("GitHub issue title is required")
	}
	if request.Type != nil {
		issueType := strings.TrimSpace(*request.Type)
		request.Type = &issueType
	}
	if err := validateIssueFieldValues(request.IssueFieldValues); err != nil {
		return Issue{}, err
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return Issue{}, err
	}
	var out Issue
	endpoint := fmt.Sprintf("/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(repo))
	err = c.doJSON(ctx, http.MethodPost, endpoint, token, request, &out)
	return out, err
}

func (c *Client) GetIssue(ctx context.Context, installationID int64, owner, repo string, number int) (Issue, error) {
	if number <= 0 {
		return Issue{}, fmt.Errorf("GitHub issue number must be positive")
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return Issue{}, err
	}
	var out Issue
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), number)
	err = c.doJSON(ctx, http.MethodGet, endpoint, token, nil, &out)
	return out, err
}

func (c *Client) UpdateIssue(ctx context.Context, installationID int64, owner, repo string, number int, request UpdateIssueRequest) (Issue, error) {
	if number <= 0 {
		return Issue{}, fmt.Errorf("GitHub issue number must be positive")
	}
	if request.State != nil {
		state := strings.ToLower(strings.TrimSpace(*request.State))
		if state != "open" && state != "closed" {
			return Issue{}, fmt.Errorf("GitHub issue state must be open or closed")
		}
		request.State = &state
	}
	if request.StateReason != nil {
		reason := strings.ToLower(strings.TrimSpace(*request.StateReason))
		switch reason {
		case "", "completed", "not_planned", "duplicate", "reopened":
		default:
			return Issue{}, fmt.Errorf("unsupported GitHub issue state reason %q", reason)
		}
		if reason == "duplicate" && (request.DuplicateIssueID == nil || *request.DuplicateIssueID <= 0) {
			return Issue{}, fmt.Errorf("duplicate_issue_id is required when state_reason is duplicate")
		}
		request.StateReason = &reason
	}
	if request.Type != nil {
		issueType := strings.TrimSpace(*request.Type)
		request.Type = &issueType
	}
	if request.IssueFieldValues != nil {
		if err := validateIssueFieldValues(*request.IssueFieldValues); err != nil {
			return Issue{}, err
		}
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return Issue{}, err
	}
	var out Issue
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), number)
	err = c.doJSON(ctx, http.MethodPatch, endpoint, token, request, &out)
	return out, err
}

func validateIssueFieldValues(values []IssueFieldValue) error {
	for i, value := range values {
		if value.FieldID <= 0 {
			return fmt.Errorf("issue_field_values[%d].field_id must be positive", i)
		}
		if value.Value == nil {
			return fmt.Errorf("issue_field_values[%d].value is required", i)
		}
	}
	return nil
}

func (c *Client) LockIssue(ctx context.Context, installationID int64, owner, repo string, number int, reason string) error {
	if number <= 0 {
		return fmt.Errorf("GitHub issue number must be positive")
	}
	reason = strings.ToLower(strings.TrimSpace(reason))
	body := map[string]string{}
	if reason != "" {
		switch reason {
		case "off-topic", "too heated", "resolved", "spam":
			body["lock_reason"] = reason
		default:
			return fmt.Errorf("unsupported GitHub lock reason %q", reason)
		}
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d/lock", url.PathEscape(owner), url.PathEscape(repo), number)
	return c.doJSON(ctx, http.MethodPut, endpoint, token, body, nil)
}

func (c *Client) UnlockIssue(ctx context.Context, installationID int64, owner, repo string, number int) error {
	if number <= 0 {
		return fmt.Errorf("GitHub issue number must be positive")
	}
	token, err := c.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d/lock", url.PathEscape(owner), url.PathEscape(repo), number)
	return c.doJSON(ctx, http.MethodDelete, endpoint, token, nil, nil)
}
