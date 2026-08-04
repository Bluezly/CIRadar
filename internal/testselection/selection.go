package testselection

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ciradar/internal/db"
	"ciradar/internal/model"
)

func Select(ctx context.Context, store db.Backend, tenant string, req model.TestSelectionRequest) (model.TestSelection, error) {
	if req.Limit < 1 || req.Limit > 5000 {
		req.Limit = 500
	}
	if req.MinimumScore <= 0 || req.MinimumScore > 100 {
		req.MinimumScore = 10
	}
	stats, err := store.ListTestCaseStats(ctx, tenant, req.Repository, "", 5000)
	if err != nil {
		return model.TestSelection{}, err
	}
	changed := normalize(req.ChangedFiles)
	graph, graphOK, err := LoadGraph(ctx, store, tenant, req.Repository)
	if err != nil {
		return model.TestSelection{}, err
	}
	coverage := normalizedCoverage(graph.TestCoverage)
	selected := []model.SelectedTest{}
	candidates := 0
	coveredCandidates := 0
	for _, st := range stats {
		if req.Framework != "" && !strings.EqualFold(st.Framework, req.Framework) {
			continue
		}
		candidates++
		covered := coverageFor(st, coverage)
		if len(covered) > 0 {
			coveredCandidates++
		}
		scoreValue, confidence, strategy, reason, path := impactScore(st, changed, graph, graphOK, req.IncludeFlaky, covered)
		if scoreValue < req.MinimumScore {
			continue
		}
		selected = append(selected, model.SelectedTest{TestKey: st.TestKey, Name: st.Name, Suite: st.Suite, ClassName: st.ClassName, File: st.File, Framework: st.Framework, PriorityScore: scoreValue, Confidence: confidence, Strategy: strategy, Reason: reason, ImpactPath: path, Quarantined: st.Quarantined})
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].PriorityScore == selected[j].PriorityScore {
			return selected[i].Confidence > selected[j].Confidence
		}
		return selected[i].PriorityScore > selected[j].PriorityScore
	})
	skipped := 0
	if len(selected) > req.Limit {
		skipped = len(selected) - req.Limit
		selected = selected[:req.Limit]
	}
	diagnostics := selectionDiagnostics(len(stats), candidates, len(changed), graphOK, len(coverage), coveredCandidates, len(selected), req.MinimumScore)
	return model.TestSelection{Repository: req.Repository, ChangedFiles: req.ChangedFiles, Selected: selected, Skipped: skipped, CandidatesEvaluated: candidates, GraphAvailable: graphOK, CoverageIdentities: len(coverage), Diagnostics: diagnostics, GeneratedAt: time.Now().UTC()}, nil
}

func impactScore(st model.TestCaseStats, changed []string, graph model.ImpactGraph, graphOK, includeFlaky bool, covered []string) (float64, float64, string, string, []string) {
	if len(changed) == 0 {
		score := minFloat(100, 20+float64(st.Failures)*3)
		return score, .45, "history", "no changed files supplied; prioritized by recent failure history", nil
	}
	if graphOK {
		for _, changedFile := range changed {
			for _, source := range covered {
				if fileMatches(source, changedFile) {
					return adjustTestSignals(100, .98, "coverage", "per-test coverage directly includes a changed file", coverageImpactPath(source, changedFile), st, includeFlaky)
				}
			}
		}
		testFile := norm(st.File)
		if testFile != "" {
			if path := shortestImpactPath(testFile, changed, graph.Dependencies, 8); len(path) > 1 {
				depth := len(path) - 1
				score := maxFloat(58, 98-float64(depth-1)*8)
				confidence := maxFloat(.62, .96-float64(depth-1)*.07)
				return adjustTestSignals(score, confidence, "dependency_graph", "test reaches a changed file through the indexed dependency graph", path, st, includeFlaky)
			}
		}
	}
	score, reason := heuristicScore(st, changed, includeFlaky)
	confidence := .35
	strategy := "heuristic"
	if graphOK {
		confidence = .42
		strategy = "graph_fallback"
	}
	return score, confidence, strategy, reason, nil
}

func coverageImpactPath(source, changed string) []string {
	source = norm(source)
	changed = norm(changed)
	if source == changed {
		return []string{source}
	}
	return []string{source, changed}
}

func adjustTestSignals(score, confidence float64, strategy, reason string, path []string, st model.TestCaseStats, includeFlaky bool) (float64, float64, string, string, []string) {
	reasons := []string{reason}
	if st.Failures > 0 {
		score += minFloat(8, float64(st.Failures))
		reasons = append(reasons, "recent failure history")
	}
	if includeFlaky && st.Classification == "flaky" {
		score += 4
		reasons = append(reasons, "known flaky coverage")
	}
	if st.Quarantined {
		score -= 12
		reasons = append(reasons, "currently quarantined")
	}
	return minFloat(100, maxFloat(0, score)), minFloat(1, confidence), strategy, strings.Join(reasons, "; "), path
}

func coverageFor(st model.TestCaseStats, coverage map[string][]string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, key := range TestAliases(st) {
		for _, file := range coverage[normalizeTestIdentity(key)] {
			file = norm(file)
			if file != "" && !seen[file] {
				seen[file] = true
				out = append(out, file)
			}
		}
	}
	return out
}

func normalizedCoverage(coverage map[string][]string) map[string][]string {
	out := map[string][]string{}
	for key, files := range coverage {
		normalizedKey := normalizeTestIdentity(key)
		if normalizedKey == "" {
			continue
		}
		out[normalizedKey] = uniqueSorted(append(out[normalizedKey], files...))
	}
	return out
}

func DisplayName(st model.TestCaseStats) string {
	parts := []string{}
	for _, value := range []string{st.Suite, st.ClassName, st.Name} {
		value = strings.TrimSpace(value)
		if value == "" || len(parts) > 0 && strings.EqualFold(parts[len(parts)-1], value) {
			continue
		}
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return st.TestKey
	}
	return strings.Join(parts, "/")
}

func TestAliases(st model.TestCaseStats) []string {
	values := []string{st.TestKey, st.Name, DisplayName(st), st.Suite + "::" + st.Name, st.ClassName + "::" + st.Name, st.Suite + "/" + st.Name, st.ClassName + "/" + st.Name, st.Suite + "/" + st.ClassName + "/" + st.Name, st.Suite + "/" + st.ClassName + "::" + st.Name, norm(st.File), norm(st.File) + "::" + st.Name}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), "/:")
		key := normalizeTestIdentity(value)
		if key != "" && !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func ResolveTest(stats []model.TestCaseStats, selector string) (model.TestCaseStats, error) {
	selector = normalizeTestIdentity(selector)
	if selector == "" {
		return model.TestCaseStats{}, fmt.Errorf("test selector is empty")
	}
	exact := []model.TestCaseStats{}
	partial := []model.TestCaseStats{}
	for _, st := range stats {
		if normalizeTestIdentity(st.TestKey) == selector || len(selector) >= 8 && strings.HasPrefix(normalizeTestIdentity(st.TestKey), selector) {
			exact = append(exact, st)
			continue
		}
		matched := false
		for _, alias := range TestAliases(st) {
			alias = normalizeTestIdentity(alias)
			if alias == selector {
				exact = append(exact, st)
				matched = true
				break
			}
		}
		if !matched && strings.Contains(normalizeTestIdentity(DisplayName(st)), selector) {
			partial = append(partial, st)
		}
	}
	matches := exact
	if len(matches) == 0 {
		matches = partial
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return model.TestCaseStats{}, fmt.Errorf("no test matches %q", selector)
	}
	names := make([]string, 0, len(matches))
	for _, st := range matches {
		names = append(names, fmt.Sprintf("%s (%s)", DisplayName(st), st.TestKey))
	}
	sort.Strings(names)
	if len(names) > 8 {
		names = names[:8]
	}
	return model.TestCaseStats{}, fmt.Errorf("test selector %q is ambiguous: %s", selector, strings.Join(names, ", "))
}

func selectionDiagnostics(total, candidates, changed int, graphOK bool, coverageIdentities, coveredCandidates, selected int, minimumScore float64) []string {
	if selected > 0 {
		return nil
	}
	out := []string{}
	if total == 0 {
		return []string{"no test history exists for this repository; ingest a supported test report first"}
	}
	if candidates == 0 {
		return []string{"test history exists, but no tests match the requested framework filter"}
	}
	if changed == 0 {
		out = append(out, "no changed files were supplied")
	}
	if !graphOK {
		out = append(out, "no impact graph exists; run `ciradar tests index --repo OWNER/REPO --root PATH`")
	} else if coverageIdentities == 0 {
		out = append(out, "the impact graph contains no per-test coverage identities")
	} else if coveredCandidates == 0 {
		out = append(out, "coverage identities did not match any ingested test; use a test key or a readable test identity from `ciradar tests list`")
	}
	out = append(out, fmt.Sprintf("all %d candidate tests scored below the minimum %.0f", candidates, minimumScore))
	return out
}

func shortestImpactPath(start string, targets []string, dependencies map[string][]string, maxDepth int) []string {
	start = norm(start)
	if start == "" {
		return nil
	}
	targetSet := map[string]bool{}
	for _, target := range targets {
		targetSet[norm(target)] = true
	}
	type node struct {
		file string
		path []string
	}
	queue := []node{{file: start, path: []string{start}}}
	seen := map[string]bool{start: true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if len(current.path)-1 >= maxDepth {
			continue
		}
		for _, dep := range dependencies[current.file] {
			dep = norm(dep)
			if seen[dep] {
				continue
			}
			path := append(append([]string(nil), current.path...), dep)
			for target := range targetSet {
				if fileMatches(dep, target) {
					return path
				}
			}
			seen[dep] = true
			queue = append(queue, node{file: dep, path: path})
		}
	}
	return nil
}

func heuristicScore(st model.TestCaseStats, changed []string, includeFlaky bool) (float64, string) {
	score := 0.0
	reasons := []string{}
	file := norm(st.File)
	for _, changedFile := range changed {
		if file != "" && fileMatches(file, changedFile) {
			score += 55
			reasons = append(reasons, "test file matches a changed file")
			break
		}
		dir := filepath.ToSlash(filepath.Dir(file))
		if dir != "." && dir != "" && strings.HasPrefix(changedFile, dir+"/") {
			score += 28
			reasons = append(reasons, "test is near changed files")
			break
		}
	}
	nameText := strings.ToLower(st.Suite + " " + st.ClassName + " " + st.Name)
	for _, changedFile := range changed {
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(changedFile)), filepath.Ext(changedFile))
		if len(base) > 2 && strings.Contains(nameText, base) {
			score += 18
			reasons = append(reasons, "test name matches changed component")
			break
		}
	}
	if st.Failures > 0 {
		score += 10
		reasons = append(reasons, "recent failure history")
	}
	if includeFlaky && st.Classification == "flaky" {
		score += 6
		reasons = append(reasons, "known flaky coverage")
	}
	if st.Quarantined {
		score -= 15
	}
	if len(reasons) == 0 {
		return 0, "no impact evidence"
	}
	return minFloat(100, maxFloat(0, score)), strings.Join(reasons, "; ")
}

func fileMatches(a, b string) bool {
	a, b = norm(a), norm(b)
	return a == b || strings.HasSuffix(a, "/"+b) || strings.HasSuffix(b, "/"+a) || sameStem(a, b)
}

func normalize(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = norm(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func normalizeTestIdentity(value string) string {
	value = strings.ToLower(filepath.ToSlash(strings.TrimSpace(value)))
	value = strings.ReplaceAll(value, " ", "")
	return strings.Trim(value, "/:")
}

func norm(value string) string {
	return strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(value)), "./")
}

func sameStem(a, b string) bool {
	return strings.TrimSuffix(a, filepath.Ext(a)) == strings.TrimSuffix(b, filepath.Ext(b))
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
