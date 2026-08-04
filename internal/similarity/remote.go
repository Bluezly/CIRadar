package similarity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

type storedEmbedding struct {
	AnalysisID string    `json:"analysis_id"`
	Model      string    `json:"model"`
	Vector     []float64 `json:"vector"`
	CreatedAt  time.Time `json:"created_at"`
}

func FindConfigured(ctx context.Context, store db.Backend, tenant, analysisID string, limit int, semantic config.SemanticConfig, llm config.LLMConfig) ([]model.SimilarAnalysis, error) {
	if !semantic.Enabled || !semantic.RemoteEmbeddings || strings.TrimSpace(llm.EmbeddingsEndpoint) == "" || strings.TrimSpace(llm.APIKey) == "" {
		return Find(ctx, store, tenant, analysisID, limit, semantic.VectorDimensions)
	}
	target, err := store.GetAnalysisForTenant(ctx, tenant, analysisID)
	if err != nil || target == nil {
		return nil, err
	}
	items, err := store.ListAnalysesForTenant(ctx, tenant, semantic.CandidateLimit)
	if err != nil {
		return nil, err
	}
	candidates := make([]model.AnalysisResult, 0, len(items))
	for _, x := range items {
		if x.ID != analysisID {
			candidates = append(candidates, x)
		}
	}
	all := append([]model.AnalysisResult{*target}, candidates...)
	vectors := make([][]float64, len(all))
	missingIdx := []int{}
	missingText := []string{}
	modelName := llm.EmbeddingModel
	if modelName == "" {
		modelName = "text-embedding-3-small"
	}
	for i, a := range all {
		var cached storedEmbedding
		ok, _ := store.GetObject(ctx, tenant, "analysis_embedding", a.ID+"|"+modelName, &cached)
		if ok && len(cached.Vector) > 0 {
			vectors[i] = cached.Vector
		} else {
			missingIdx = append(missingIdx, i)
			missingText = append(missingText, text(a))
		}
	}
	if len(missingText) > 0 {
		remote, err := embed(ctx, llm, modelName, missingText)
		if err != nil {
			return Find(ctx, store, tenant, analysisID, limit, semantic.VectorDimensions)
		}
		for j, idx := range missingIdx {
			if j < len(remote) {
				vectors[idx] = remote[j]
				_ = store.PutObject(ctx, tenant, "analysis_embedding", all[idx].ID+"|"+modelName, storedEmbedding{AnalysisID: all[idx].ID, Model: modelName, Vector: remote[j], CreatedAt: time.Now().UTC()})
			}
		}
	}
	out := []model.SimilarAnalysis{}
	for i, x := range candidates {
		if i+1 >= len(vectors) {
			break
		}
		score := cosine(vectors[0], vectors[i+1])
		if score < .1 {
			continue
		}
		out = append(out, model.SimilarAnalysis{AnalysisID: x.ID, Repository: x.Repository, Summary: x.Summary, Category: x.Category, Attribution: x.Attribution, Score: score, CreatedAt: x.CreatedAt})
	}
	sortSimilar(out)
	if limit < 1 {
		limit = 10
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func embed(ctx context.Context, cfg config.LLMConfig, modelName string, input []string) ([][]float64, error) {
	payload, _ := json.Marshal(map[string]any{"model": modelName, "input": input, "encoding_format": "float"})
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	c := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EmbeddingsEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("embedding HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	vectors := make([][]float64, len(input))
	for _, d := range out.Data {
		if d.Index >= 0 && d.Index < len(vectors) {
			vectors[d.Index] = d.Embedding
		}
	}
	for _, v := range vectors {
		if len(v) == 0 {
			return nil, fmt.Errorf("embedding response missing vector")
		}
	}
	return vectors, nil
}
func sortSimilar(v []model.SimilarAnalysis) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].Score > v[j-1].Score; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
