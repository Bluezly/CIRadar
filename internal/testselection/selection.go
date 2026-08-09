package testselection

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
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
	allCandidates := []model.SelectedTest{}
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
		base := model.SelectedTest{TestKey: st.TestKey, DisplayName: DisplayName(st), Name: st.Name, Suite: st.Suite, ClassName: st.ClassName, File: st.File, Framework: st.Framework, PriorityScore: 100, Confidence: 1, Strategy: "safety_full_suite", Reason: "included because the impact evidence cannot safely exclude this test", Quarantined: st.Quarantined}
		allCandidates = append(allCandidates, base)
		scoreValue, confidence, strategy, reason, path := impactScore(st, changed, graph, graphOK, req.IncludeFlaky, covered)
		if scoreValue < req.MinimumScore {
			continue
		}
		selected = append(selected, model.SelectedTest{TestKey: st.TestKey, DisplayName: DisplayName(st), Name: st.Name, Suite: st.Suite, ClassName: st.ClassName, File: st.File, Framework: st.Framework, PriorityScore: scoreValue, Confidence: confidence, Strategy: strategy, Reason: reason, ImpactPath: path, Quarantined: st.Quarantined})
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].PriorityScore == selected[j].PriorityScore {
			return selected[i].Confidence > selected[j].Confidence
		}
		return selected[i].PriorityScore > selected[j].PriorityScore
	})
	riskLevel, riskReasons := assessSelectionRisk(changed, graph, graphOK, len(coverage), candidates, coveredCandidates)
	fullSuiteRequired := len(riskReasons) > 0
	unsafeOverride := fullSuiteRequired && req.AllowUnsafePartial
	skipped := 0
	if fullSuiteRequired && !req.AllowUnsafePartial {
		selected = mergeFullSuiteSelection(selected, allCandidates)
	} else if len(selected) > req.Limit {
		skipped = len(selected) - req.Limit
		selected = selected[:req.Limit]
	}
	diagnostics := selectionDiagnostics(len(stats), candidates, len(changed), graphOK, len(coverage), coveredCandidates, len(selected), req.MinimumScore)
	if fullSuiteRequired && !req.AllowUnsafePartial {
		diagnostics = append([]string{"safety fallback activated: run the full test suite; the selected list contains every known test"}, diagnostics...)
	} else if unsafeOverride {
		diagnostics = append([]string{"unsafe partial-selection override applied; a full suite is still recommended before merge"}, diagnostics...)
	}
	recommendation := "run_selected_tests"
	if fullSuiteRequired {
		recommendation = "run_full_suite"
	}
	return model.TestSelection{
		Repository:            req.Repository,
		ChangedFiles:          req.ChangedFiles,
		Selected:              selected,
		Skipped:               skipped,
		CandidatesEvaluated:   candidates,
		GraphAvailable:        graphOK,
		CoverageIdentities:    len(coverage),
		FullSuiteRequired:     fullSuiteRequired,
		SelectionSafe:         !fullSuiteRequired,
		UnsafeOverrideApplied: unsafeOverride,
		RiskLevel:             riskLevel,
		RiskReasons:           riskReasons,
		Recommendation:        recommendation,
		Diagnostics:           diagnostics,
		GeneratedAt:           time.Now().UTC(),
	}, nil
}

func mergeFullSuiteSelection(prioritized, all []model.SelectedTest) []model.SelectedTest {
	out := make([]model.SelectedTest, 0, len(all))
	seen := map[string]bool{}
	for _, selected := range prioritized {
		if selected.TestKey == "" || seen[selected.TestKey] {
			continue
		}
		seen[selected.TestKey] = true
		out = append(out, selected)
	}
	for _, selected := range all {
		if selected.TestKey == "" || seen[selected.TestKey] {
			continue
		}
		seen[selected.TestKey] = true
		out = append(out, selected)
	}
	return out
}

func assessSelectionRisk(changed []string, graph model.ImpactGraph, graphOK bool, coverageIdentities, candidates, coveredCandidates int) (string, []string) {
	reasons := []string{}
	if len(changed) == 0 {
		reasons = append(reasons, "no changed files were supplied, so impact cannot be bounded")
	}
	for _, file := range changed {
		if reason := highRiskChangeReason(file); reason != "" {
			reasons = append(reasons, reason)
		}
	}
	if !graphOK {
		reasons = append(reasons, "no indexed dependency graph is available")
	} else {
		for _, file := range changed {
			if !graphContainsFile(graph, file) {
				reasons = append(reasons, fmt.Sprintf("changed file %q is absent from the indexed dependency graph", file))
			}
		}
	}
	if coverageIdentities == 0 {
		reasons = append(reasons, "no per-test coverage identities are available")
	} else if candidates > 0 && coveredCandidates < candidates {
		reasons = append(reasons, fmt.Sprintf("coverage evidence exists for only %d of %d candidate tests", coveredCandidates, candidates))
	}
	reasons = uniqueStrings(reasons)
	if len(reasons) == 0 {
		return "low", nil
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "migration") || strings.Contains(reason, "schema") || strings.Contains(reason, "dependency manifest") || strings.Contains(reason, "environment/configuration") {
			return "critical", reasons
		}
	}
	return "high", reasons
}

func highRiskChangeReason(file string) string {
	file = strings.ToLower(strings.TrimSpace(filepath.ToSlash(file)))
	base := filepath.Base(file)
	if file == "" {
		return "an empty changed-file identity prevents safe impact analysis"
	}
	if strings.Contains(file, "/migrations/") || strings.HasPrefix(file, "migrations/") || strings.Contains(file, "/migration/") || strings.HasSuffix(base, ".sql") || strings.Contains(base, "schema") {
		return fmt.Sprintf("database migration/schema change %q requires the full suite", file)
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.Contains(file, "/config/") || strings.HasPrefix(file, "config/") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".toml") || strings.HasSuffix(base, ".ini") {
		return fmt.Sprintf("environment/configuration change %q can affect tests indirectly", file)
	}
	dependencyFiles := map[string]bool{
		"go.mod": true, "go.sum": true, "package.json": true, "package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
		"cargo.toml": true, "cargo.lock": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "gradle.properties": true,
		"requirements.txt": true, "pyproject.toml": true, "poetry.lock": true, "gemfile": true, "gemfile.lock": true, "composer.json": true, "composer.lock": true,
	}
	if dependencyFiles[base] {
		return fmt.Sprintf("dependency manifest/lock change %q requires the full suite", file)
	}
	if strings.HasPrefix(file, ".github/workflows/") || strings.HasPrefix(file, ".gitlab-ci") || base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == "makefile" || strings.HasPrefix(base, "tsconfig") || strings.HasPrefix(base, "webpack.") || strings.HasPrefix(base, "vite.config") || strings.HasPrefix(base, "babel.config") || base == "pytest.ini" || base == "tox.ini" {
		return fmt.Sprintf("build/CI/runtime configuration change %q can have repository-wide impact", file)
	}
	return ""
}

func graphContainsFile(graph model.ImpactGraph, file string) bool {
	file = norm(file)
	if file == "" {
		return false
	}
	matches := func(candidate string) bool {
		candidate = norm(candidate)
		return candidate != "" && (candidate == file || fileMatches(candidate, file))
	}
	for source, deps := range graph.Dependencies {
		if matches(source) {
			return true
		}
		for _, dep := range deps {
			if matches(dep) {
				return true
			}
		}
	}
	for _, candidate := range graph.LanguageFiles {
		if matches(candidate) {
			return true
		}
	}
	for candidate := range graph.TestFiles {
		if matches(candidate) {
			return true
		}
	}
	for _, files := range graph.TestCoverage {
		for _, candidate := range files {
			if matches(candidate) {
				return true
			}
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
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
					return adjustTestSignals(100, .98, "coverage", "per-test coverage directly includes a changed file", coverageImpactPath(st.File, source, changedFile), st, includeFlaky)
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

func coverageImpactPath(testFile, source, changedFile string) []string {
	values := []string{norm(testFile), norm(source), norm(changedFile)}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
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
	name := strings.Join(parts, "/")
	if variant := strings.TrimSpace(st.Variant); variant != "" {
		name += " [" + variant + "]"
	}
	return name
}

func TestAliases(st model.TestCaseStats) []string {
	values := []string{st.TestKey, st.Name, DisplayName(st), st.Suite + "::" + st.Name, st.ClassName + "::" + st.Name, st.Suite + "/" + st.Name, st.ClassName + "/" + st.Name, st.Suite + "/" + st.ClassName + "/" + st.Name, st.Suite + "/" + st.ClassName + "::" + st.Name, norm(st.File), norm(st.File) + "::" + st.Name, st.Name + " [" + st.Variant + "]"}
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
