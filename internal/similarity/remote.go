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
	semantic.Mode = effectiveSemanticMode(semantic)
	if !semantic.Enabled || semantic.Mode == "lexical" || semantic.Mode == "local-hash" {
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
	for _, item := range items {
		if item.ID != analysisID {
			candidates = append(candidates, item)
		}
	}
	all := append([]model.AnalysisResult{*target}, candidates...)
	vectors := make([][]float64, len(all))
	missingIndexes := []int{}
	missingText := []string{}
	modelName := configuredModelName(semantic, llm)
	for i, analysis := range all {
		var cached storedEmbedding
		ok, _ := store.GetObject(ctx, tenant, "analysis_embedding", analysis.ID+"|"+modelName, &cached)
		if ok && len(cached.Vector) > 0 {
			vectors[i] = cached.Vector
		} else {
			missingIndexes = append(missingIndexes, i)
			missingText = append(missingText, text(analysis))
		}
	}
	if len(missingText) > 0 {
		generated, generationErr := configuredEmbeddings(ctx, semantic, llm, missingText)
		if generationErr != nil {
			return Find(ctx, store, tenant, analysisID, limit, semantic.VectorDimensions)
		}
		for i, index := range missingIndexes {
			if i < len(generated) {
				vectors[index] = generated[i]
				_ = store.PutObject(ctx, tenant, "analysis_embedding", all[index].ID+"|"+modelName, storedEmbedding{AnalysisID: all[index].ID, Model: modelName, Vector: generated[i], CreatedAt: time.Now().UTC()})
			}
		}
	}
	out := []model.SimilarAnalysis{}
	for i, candidate := range candidates {
		if i+1 >= len(vectors) || len(vectors[0]) == 0 || len(vectors[i+1]) == 0 {
			continue
		}
		score := cosine(vectors[0], vectors[i+1])
		if score < .1 {
			continue
		}
		out = append(out, model.SimilarAnalysis{AnalysisID: candidate.ID, Repository: candidate.Repository, Summary: candidate.Summary, Category: candidate.Category, Attribution: candidate.Attribution, Score: score, Engine: modelName, CreatedAt: candidate.CreatedAt})
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

func configuredModelName(semantic config.SemanticConfig, llm config.LLMConfig) string {
	switch semantic.Mode {
	case "local-vectors":
		return "local-vectors:" + semantic.LocalVectorPath
	case "ollama":
		return "ollama:" + semantic.LocalModel
	case "remote":
		if llm.EmbeddingModel != "" {
			return "remote:" + llm.EmbeddingModel
		}
		return "remote:text-embedding-3-small"
	default:
		return "lexical-hash"
	}
}

func configuredEmbeddings(ctx context.Context, semantic config.SemanticConfig, llm config.LLMConfig, input []string) ([][]float64, error) {
	switch semantic.Mode {
	case "local-vectors":
		return localVectorEmbeddings(semantic.LocalVectorPath, input)
	case "ollama":
		return ollamaEmbeddings(ctx, semantic, input)
	case "remote":
		modelName := llm.EmbeddingModel
		if modelName == "" {
			modelName = "text-embedding-3-small"
		}
		if strings.TrimSpace(llm.EmbeddingsEndpoint) == "" || strings.TrimSpace(llm.APIKey) == "" {
			return nil, fmt.Errorf("remote embedding endpoint and api key are required")
		}
		return embedRemote(ctx, llm, modelName, input)
	default:
		return nil, fmt.Errorf("unsupported semantic mode %q", semantic.Mode)
	}
}

func embedRemote(ctx context.Context, cfg config.LLMConfig, modelName string, input []string) ([][]float64, error) {
	payload, _ := json.Marshal(map[string]any{"model": modelName, "input": input, "encoding_format": "float"})
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EmbeddingsEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("embedding HTTP %d", resp.StatusCode)
	}
	var output struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, err
	}
	vectors := make([][]float64, len(input))
	for _, item := range output.Data {
		if item.Index >= 0 && item.Index < len(vectors) {
			vectors[item.Index] = item.Embedding
			normalizeVector(vectors[item.Index])
		}
	}
	for _, vectorValue := range vectors {
		if len(vectorValue) == 0 {
			return nil, fmt.Errorf("embedding response missing vector")
		}
	}
	return vectors, nil
}

func sortSimilar(values []model.SimilarAnalysis) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j].Score > values[j-1].Score; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func effectiveSemanticMode(semantic config.SemanticConfig) string {
	mode := strings.ToLower(strings.TrimSpace(semantic.Mode))
	if mode != "" {
		return mode
	}
	if semantic.RemoteEmbeddings {
		return "remote"
	}
	if semantic.LocalEndpoint != "" {
		return "ollama"
	}
	if semantic.LocalVectorPath != "" {
		return "local-vectors"
	}
	if semantic.Enabled {
		return "ollama"
	}
	return "lexical"
}
