package similarity

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

var ErrAnalysisNotFound = errors.New("analysis not found")

func Find(ctx context.Context, store db.Backend, tenant, analysisID string, limit, dimensions int) ([]model.SimilarAnalysis, error) {
	if limit < 1 || limit > 100 {
		limit = 10
	}
	if dimensions < 64 {
		dimensions = 256
	}
	target, err := store.GetAnalysisForTenant(ctx, tenant, analysisID)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, fmt.Errorf("%w: %s", ErrAnalysisNotFound, analysisID)
	}
	items, err := store.ListAnalysesForTenant(ctx, tenant, 5000)
	if err != nil {
		return nil, err
	}
	tv := vector(text(*target), dimensions)
	out := []model.SimilarAnalysis{}
	for _, x := range items {
		if x.ID == target.ID {
			continue
		}
		score := cosine(tv, vector(text(x), dimensions))
		if score < 0.08 {
			continue
		}
		out = append(out, model.SimilarAnalysis{AnalysisID: x.ID, Repository: x.Repository, Summary: x.Summary, Category: x.Category, Attribution: x.Attribution, Score: score, Engine: "lexical-hash", CreatedAt: x.CreatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func text(r model.AnalysisResult) string {
	parts := []string{r.Summary, string(r.Category), r.Provider, r.Operation, r.ErrorFamily, string(r.Attribution), strings.Join(r.MatchedRules, " ")}
	for _, e := range r.Evidence {
		parts = append(parts, e.Description)
	}
	return strings.Join(parts, " ")
}
func vector(s string, n int) []float64 {
	v := make([]float64, n)
	words := tokenize(s)
	for i, w := range words {
		h := fnv.New64a()
		_, _ = h.Write([]byte(w))
		x := h.Sum64()
		idx := int(x % uint64(n))
		sign := 1.0
		if x&(1<<63) != 0 {
			sign = -1
		}
		weight := 1.0
		if i > 0 {
			weight = .85
		}
		v[idx] += sign * weight
		if i > 0 {
			h.Reset()
			_, _ = h.Write([]byte(words[i-1] + "_" + w))
			x = h.Sum64()
			v[int(x%uint64(n))] += sign * .55
		}
	}
	norm := 0.0
	for _, x := range v {
		norm += x * x
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for i := range v {
			v[i] /= norm
		}
	}
	return v
}
func tokenize(s string) []string {
	f := func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-') }
	raw := strings.FieldsFunc(strings.ToLower(s), f)
	out := raw[:0]
	for _, x := range raw {
		if len(x) > 1 {
			out = append(out, x)
		}
	}
	return out
}
func cosine(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += a[i] * b[i]
	}
	return math.Max(0, math.Min(1, sum))
}
