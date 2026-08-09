package similarity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
)

func TestLocalSimilarity(t *testing.T) {
	s, e := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	for i, summary := range []string{"npm registry connection reset while downloading package", "package download failed because npm connection reset", "Go compiler undefined symbol"} {
		in := model.AnalysisInput{TenantID: "default", Repository: "a/b", Log: summary, OccurredAt: time.Now()}
		r := model.AnalysisResult{ID: string(rune('a' + i)), TenantID: "default", Repository: "a/b", Category: model.CategoryDependencyRegistry, Attribution: model.AttributionExternal, Summary: summary, CreatedAt: time.Now()}
		if e := s.RecordAnalysisForTenant(ctx, "default", in, r, false, false); e != nil {
			t.Fatal(e)
		}
	}
	out, e := Find(ctx, s, "default", "a", 10, 128)
	if e != nil {
		t.Fatal(e)
	}
	if len(out) == 0 || out[0].AnalysisID != "b" {
		t.Fatalf("%#v", out)
	}
}

func TestRemoteEmbeddingsAndCache(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for i, summary := range []string{"registry network failure", "registry timeout", "compiler failure"} {
		input := model.AnalysisInput{TenantID: "default", Repository: "a/b", Log: summary, OccurredAt: time.Now()}
		result := model.AnalysisResult{ID: string(rune('a' + i)), TenantID: "default", Repository: "a/b", Summary: summary, Category: model.CategoryUnknown, Attribution: model.AttributionUnknown, CreatedAt: time.Now()}
		if err := store.RecordAnalysisForTenant(ctx, "default", input, result, false, false); err != nil {
			t.Fatal(err)
		}
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			Input []string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		data := make([]map[string]any, len(body.Input))
		for i, text := range body.Input {
			vector := []float64{1, 0, 0}
			if strings.Contains(text, "compiler") {
				vector = []float64{0, 1, 0}
			}
			data[i] = map[string]any{"index": i, "embedding": vector}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer server.Close()
	semantic := config.SemanticConfig{Enabled: true, RemoteEmbeddings: true, VectorDimensions: 128, CandidateLimit: 100}
	llmConfig := config.LLMConfig{EmbeddingsEndpoint: server.URL, AllowPrivateNetwork: true, APIKey: "key", EmbeddingModel: "test", Timeout: time.Second}
	out, err := FindConfigured(ctx, store, "default", "a", 10, semantic, llmConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[0].AnalysisID != "b" || out[0].Score < .99 {
		t.Fatalf("%#v", out)
	}
	if _, err := FindConfigured(ctx, store, "default", "a", 10, semantic, llmConfig); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("embedding requests=%d", requests)
	}
}

func TestConfiguredSimilarityRejectsMissingAnalysis(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	semantic := config.SemanticConfig{Enabled: true, RemoteEmbeddings: true, CandidateLimit: 10}
	llmConfig := config.LLMConfig{EmbeddingsEndpoint: "https://embeddings.example/v1", APIKey: "key", EmbeddingModel: "test"}
	if _, err := FindConfigured(context.Background(), store, "default", "missing", 10, semantic, llmConfig); !errors.Is(err, ErrAnalysisNotFound) {
		t.Fatalf("missing analysis error=%v", err)
	}
}

type failingEmbeddingCacheStore struct {
	db.Backend
	err error
}

func (s failingEmbeddingCacheStore) GetObject(context.Context, string, string, string, any) (bool, error) {
	return false, s.err
}

func TestConfiguredSimilarityPropagatesCacheReadFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	analysis := model.AnalysisResult{ID: "a", TenantID: "default", Repository: "acme/api", Summary: "failure", CreatedAt: time.Now()}
	if err := store.RecordAnalysisForTenant(context.Background(), "default", model.AnalysisInput{TenantID: "default", Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("embedding cache unavailable")
	semantic := config.SemanticConfig{Enabled: true, Mode: "remote", CandidateLimit: 10}
	llmConfig := config.LLMConfig{EmbeddingsEndpoint: "https://embeddings.example/v1", APIKey: "key", EmbeddingModel: "test"}
	_, err = FindConfigured(context.Background(), failingEmbeddingCacheStore{Backend: store, err: sentinel}, "default", "a", 10, semantic, llmConfig)
	if !errors.Is(err, sentinel) {
		t.Fatalf("cache read error=%v", err)
	}
}

type failingEmbeddingCacheWriteStore struct {
	db.Backend
	err error
}

func (s failingEmbeddingCacheWriteStore) PutObject(context.Context, string, string, string, any) error {
	return s.err
}

func TestConfiguredSimilarityPropagatesCacheWriteFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	analysis := model.AnalysisResult{ID: "a", TenantID: "default", Repository: "acme/api", Summary: "failure", CreatedAt: time.Now()}
	if err := store.RecordAnalysisForTenant(context.Background(), "default", model.AnalysisInput{TenantID: "default", Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input []string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		data := make([]map[string]any, len(body.Input))
		for i := range body.Input {
			data[i] = map[string]any{"index": i, "embedding": []float64{1, 0}}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	sentinel := errors.New("embedding cache write failed")
	semantic := config.SemanticConfig{Enabled: true, Mode: "remote", CandidateLimit: 10}
	llmConfig := config.LLMConfig{EmbeddingsEndpoint: server.URL, AllowPrivateNetwork: true, APIKey: "key", EmbeddingModel: "test"}
	_, err = FindConfigured(context.Background(), failingEmbeddingCacheWriteStore{Backend: store, err: sentinel}, "default", "a", 10, semantic, llmConfig)
	if !errors.Is(err, sentinel) {
		t.Fatalf("cache write error=%v", err)
	}
}

func TestReadResponseBodyRejectsOversizedPayload(t *testing.T) {
	if _, err := readResponseBody(strings.NewReader("12345"), 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}
