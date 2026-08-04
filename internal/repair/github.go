package repair

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	gh "ciradar/internal/github"
	"ciradar/internal/model"
)

func CreateGitHubDraftPR(ctx context.Context, client *gh.Client, source model.RepairSource, analysis model.AnalysisResult, patch, branchPrefix string, maximumFiles, maximumLines int) (model.RepairResult, error) {
	result := model.RepairResult{TenantID: analysis.TenantID, AnalysisID: analysis.ID, Provider: "github", Status: "failed", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if client == nil || source.InstallationID <= 0 {
		return result, errors.New("GitHub App installation is required for draft repair PR")
	}
	owner, repo, ok := strings.Cut(source.Repository, "/")
	if !ok || owner == "" || repo == "" {
		return result, errors.New("repair source repository is invalid")
	}
	if strings.TrimSpace(source.CommitSHA) == "" {
		return result, errors.New("repair source has no commit SHA")
	}
	paths, err := RequiredFiles(patch)
	if err != nil {
		return result, err
	}
	if maximumFiles > 0 && len(paths) > maximumFiles {
		return result, fmt.Errorf("repair changes %d files, maximum is %d", len(paths), maximumFiles)
	}
	contents := map[string]string{}
	shas := map[string]string{}
	for _, path := range paths {
		file, err := client.GetContent(ctx, source.InstallationID, owner, repo, path, source.CommitSHA)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				continue
			}
			return result, err
		}
		contents[path] = file.Content
		shas[path] = file.SHA
	}
	plan, err := BuildPlanFromFiles(analysis.ID, patch, contents)
	if err != nil {
		return result, err
	}
	result.PlanID = plan.ID
	if maximumLines > 0 && plan.ChangedLines > maximumLines {
		return result, fmt.Errorf("repair changes %d lines, maximum is %d", plan.ChangedLines, maximumLines)
	}
	base := strings.TrimSpace(source.BaseBranch)
	if base == "" {
		info, err := client.Repository(ctx, source.InstallationID, owner, repo)
		if err != nil {
			return result, err
		}
		base = info.DefaultBranch
	}
	if base == "" {
		return result, errors.New("repair base branch is unknown")
	}
	branch := sanitizeBranch(firstText(branchPrefix, "ciradar/repair-") + shortID(analysis.ID) + "-" + time.Now().UTC().Format("150405"))
	if err := client.CreateBranch(ctx, source.InstallationID, owner, repo, branch, source.CommitSHA); err != nil {
		return result, err
	}
	result.Branch = branch
	for _, file := range plan.Files {
		message := "CI Radar repair for " + shortID(analysis.ID) + ": " + file.Path
		if err := client.PutContent(ctx, source.InstallationID, owner, repo, file.Path, branch, message, file.NewContent, shas[file.Path]); err != nil {
			return result, err
		}
	}
	title := "CI Radar repair: " + truncateText(analysis.Summary, 72)
	body := renderDraftPRBody(analysis, plan, source)
	pull, err := client.CreateDraftPullRequest(ctx, source.InstallationID, owner, repo, title, body, branch, base)
	if err != nil {
		return result, err
	}
	result.PullRequestNumber = pull.Number
	result.PullRequestURL = pull.HTMLURL
	result.Status = "draft_pr_created"
	result.UpdatedAt = time.Now().UTC()
	return result, nil
}

func renderDraftPRBody(analysis model.AnalysisResult, plan Plan, source model.RepairSource) string {
	var body strings.Builder
	body.WriteString("## CI Radar repair proposal\n\n")
	fmt.Fprintf(&body, "Diagnosis: **%s** · %s confidence · score %d/100\n\n", analysis.Attribution, analysis.Confidence, analysis.Score)
	fmt.Fprintf(&body, "%s\n\n", analysis.Summary)
	body.WriteString("This draft PR was generated from an optional repair proposal. It has not been merged or approved automatically. Review every change and run the complete test suite.\n\n")
	body.WriteString("### Changed files\n")
	for _, file := range plan.Files {
		fmt.Fprintf(&body, "- `%s` (+%d/-%d)\n", file.Path, file.Added, file.Removed)
	}
	if source.RunURL != "" {
		fmt.Fprintf(&body, "\n[Open the failing CI run](%s)\n", source.RunURL)
	}
	fmt.Fprintf(&body, "\nPlan: `%s` · Analysis: `%s`\n", plan.ID, analysis.ID)
	return body.String()
}

func sanitizeBranch(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '/', r == '-', r == '_', r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('-')
		}
	}
	clean := strings.Trim(out.String(), "/.-")
	clean = strings.ReplaceAll(clean, "..", ".")
	clean = strings.ReplaceAll(clean, "//", "/")
	return clean
}

func shortID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func truncateText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
