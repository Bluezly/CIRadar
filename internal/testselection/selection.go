package testselection

import (
	"context"
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
	stats, err := store.ListTestCaseStats(ctx, tenant, req.Repository, "", 5000)
	if err != nil {
		return model.TestSelection{}, err
	}
	changed := normalize(req.ChangedFiles)
	selected := []model.SelectedTest{}
	for _, st := range stats {
		if req.Framework != "" && !strings.EqualFold(st.Framework, req.Framework) {
			continue
		}
		score, reason := score(st, changed, req.IncludeFlaky)
		if score <= 0 {
			continue
		}
		selected = append(selected, model.SelectedTest{TestKey: st.TestKey, Name: st.Name, Suite: st.Suite, ClassName: st.ClassName, File: st.File, Framework: st.Framework, PriorityScore: score, Reason: reason, Quarantined: st.Quarantined})
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].PriorityScore > selected[j].PriorityScore })
	skipped := 0
	if len(selected) > req.Limit {
		skipped = len(selected) - req.Limit
		selected = selected[:req.Limit]
	}
	return model.TestSelection{Repository: req.Repository, ChangedFiles: req.ChangedFiles, Selected: selected, Skipped: skipped, GeneratedAt: time.Now().UTC()}, nil
}
func score(st model.TestCaseStats, changed []string, includeFlaky bool) (float64, string) {
	score := 0.0
	reasons := []string{}
	file := norm(st.File)
	for _, c := range changed {
		if file != "" && (c == file || strings.HasSuffix(c, "/"+file) || sameStem(c, file)) {
			score += 75
			reasons = append(reasons, "test file matches a changed file")
			break
		}
		dir := filepath.ToSlash(filepath.Dir(file))
		if dir != "." && dir != "" && strings.HasPrefix(c, dir+"/") {
			score += 35
			reasons = append(reasons, "test is near changed files")
			break
		}
	}
	nameText := strings.ToLower(st.Suite + " " + st.ClassName + " " + st.Name)
	for _, c := range changed {
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(c)), filepath.Ext(c))
		if len(base) > 2 && strings.Contains(nameText, base) {
			score += 20
			reasons = append(reasons, "test name matches changed component")
			break
		}
	}
	if st.Failures > 0 {
		score += 10
		reasons = append(reasons, "recent failure history")
	}
	if includeFlaky && st.Classification == "flaky" {
		score += 8
		reasons = append(reasons, "known flaky coverage")
	}
	if st.Quarantined {
		score -= 15
	}
	if len(changed) == 0 {
		score = 20 + float64(st.Failures)*2
		reasons = []string{"no changed files supplied; prioritized by failure history"}
	}
	if score > 100 {
		score = 100
	}
	return score, strings.Join(reasons, "; ")
}
func normalize(v []string) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		x = norm(x)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
func norm(v string) string { return strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(v)), "./") }
func sameStem(a, b string) bool {
	return strings.TrimSuffix(a, filepath.Ext(a)) == strings.TrimSuffix(b, filepath.Ext(b))
}
