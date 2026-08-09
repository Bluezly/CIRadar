package sourcecontext

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	gh "github.com/Bluezly/CIRadar/internal/github"
	"github.com/Bluezly/CIRadar/internal/llm"
	"github.com/Bluezly/CIRadar/internal/model"
)

type Result struct {
	ChangedFiles []string
	Files        []llm.SourceFile
	Warnings     []string
}

func FetchGitHub(ctx context.Context, client *gh.Client, source model.RepairSource, changedFiles []string, maxFiles, maxCharacters int, logHints ...string) Result {
	result := Result{ChangedFiles: mergePaths(extractSourcePaths(source.Repository, logHints...), changedFiles)}
	if client == nil || source.InstallationID <= 0 || !strings.EqualFold(source.Provider, "github") {
		result.Warnings = append(result.Warnings, "GitHub source context is unavailable for this analysis")
		return result
	}
	owner, repo, ok := splitRepository(source.Repository)
	if !ok {
		result.Warnings = append(result.Warnings, "analysis source repository is not OWNER/REPO")
		return result
	}
	if len(result.ChangedFiles) == 0 && source.PullRequestNumber > 0 {
		files, err := client.ListPullRequestFiles(ctx, source.InstallationID, owner, repo, source.PullRequestNumber)
		if err != nil {
			result.Warnings = append(result.Warnings, "could not list pull-request files: "+err.Error())
		} else {
			result.ChangedFiles = mergePaths(result.ChangedFiles, files)
		}
	}
	if maxFiles < 1 || maxFiles > 20 {
		maxFiles = 8
	}
	if maxCharacters < 1000 || maxCharacters > 100000 {
		maxCharacters = 32000
	}
	ref := strings.TrimSpace(source.CommitSHA)
	for _, path := range result.ChangedFiles {
		if len(result.Files) >= maxFiles {
			break
		}
		if !eligiblePath(path) {
			continue
		}
		content, err := client.GetContent(ctx, source.InstallationID, owner, repo, path, ref)
		if err != nil {
			result.Warnings = appendLimited(result.Warnings, fmt.Sprintf("could not fetch %s: %v", path, err), 8)
			continue
		}
		if !utf8.ValidString(content.Content) || strings.IndexByte(content.Content, 0) >= 0 {
			result.Warnings = appendLimited(result.Warnings, fmt.Sprintf("skipped non-text source file %s", path), 8)
			continue
		}
		item := llm.SourceFile{Path: filepath.ToSlash(strings.TrimSpace(path)), Content: content.Content}
		if len(item.Content) > maxCharacters {
			item.Content = item.Content[:maxCharacters]
			item.Truncated = true
			result.Warnings = appendLimited(result.Warnings, fmt.Sprintf("source file %s was truncated for LLM context", path), 8)
		}
		result.Files = append(result.Files, item)
	}
	if len(result.ChangedFiles) > 0 && len(result.Files) == 0 {
		result.Warnings = appendLimited(result.Warnings, "no eligible source files could be fetched for exact patch validation", 8)
	}
	return result
}

var sourcePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)File ["']([^"']+\.[A-Za-z0-9]+)["'], line [0-9]+`),
	regexp.MustCompile(`(?m)([A-Za-z0-9_./@+~-]+\.(?:go|py|js|jsx|ts|tsx|java|kt|kts|rb|php|rs|cs|cpp|cc|c|h|hpp|swift|scala|sh|yaml|yml|json|toml)):[0-9]+(?::[0-9]+)?`),
}

func extractSourcePaths(repository string, values ...string) []string {
	_, repo, _ := splitRepository(repository)
	out := []string{}
	for _, value := range values {
		for _, pattern := range sourcePathPatterns {
			matches := pattern.FindAllStringSubmatch(value, 100)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				if candidate := normalizeLogPath(match[1], repo); candidate != "" {
					out = append(out, candidate)
				}
			}
		}
	}
	return uniquePaths(out)
}

func normalizeLogPath(path, repo string) string {
	path = filepath.ToSlash(strings.TrimSpace(strings.Trim(path, `"'()[]`)))
	path = strings.TrimPrefix(path, "file://")
	if path == "" {
		return ""
	}
	for _, marker := range []string{"/github/workspace/", "/workspace/", "/app/", "/src/"} {
		if at := strings.Index(path, marker); at >= 0 {
			path = path[at+len(marker):]
			break
		}
	}
	if repo != "" {
		needle := "/" + repo + "/" + repo + "/"
		if at := strings.Index(path, needle); at >= 0 {
			path = path[at+len(needle):]
		} else if strings.HasPrefix(path, repo+"/") {
			path = strings.TrimPrefix(path, repo+"/")
		}
	}
	path = strings.TrimPrefix(path, "/")
	path = filepath.ToSlash(filepath.Clean(path))
	if path == "." || !eligiblePath(path) {
		return ""
	}
	return path
}

func mergePaths(groups ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, values := range groups {
		for _, value := range values {
			value = filepath.ToSlash(strings.TrimSpace(value))
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func eligiblePath(path string) bool {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "../") || strings.HasSuffix(path, "/") {
		return false
	}
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(lower))
	if strings.Contains(lower, "/vendor/") || strings.Contains(lower, "/node_modules/") || strings.Contains(lower, "/dist/") || strings.Contains(lower, "/build/") || strings.Contains(lower, "/coverage/") {
		return false
	}
	blocked := map[string]bool{
		"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true, "cargo.lock": true,
	}
	if blocked[base] {
		return false
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".jar", ".class", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".mov", ".sqlite", ".db":
		return false
	default:
		return true
	}
}

func splitRepository(repository string) (string, string, bool) {
	parts := strings.Split(strings.TrimSpace(repository), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func uniquePaths(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = filepath.ToSlash(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func appendLimited(values []string, value string, limit int) []string {
	if len(values) >= limit {
		return values
	}
	return append(values, value)
}
