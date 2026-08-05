package llm

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
	"unicode/utf8"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/model"
)

func TestEnhanceOpenAICompatible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Error("missing auth")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"explanation\":\"The registry reset the connection.\",\"suggested_fix\":\"Retry once.\",\"patch\":\"\",\"warnings\":[\"Review before applying\"]}"}}],"usage":{"prompt_tokens":10,"completion_tokens":8}}`))
	}))
	defer srv.Close()
	store, e := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, APIKey: "key", Model: "test", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200, SendRedactedExcerpt: true}
	x := New(cfg, store)
	r := model.AnalysisResult{ID: "a", TenantID: "default", Repository: "acme/api", Summary: "npm reset", Category: model.CategoryDependencyRegistry, Attribution: model.AttributionExternal, Score: 80, CreatedAt: time.Now(), RedactedExcerpt: "ECONNRESET"}
	out, e := x.Enhance(context.Background(), r, nil)
	if e != nil {
		t.Fatal(e)
	}
	if out.Explanation == "" || out.SuggestedFix == "" {
		t.Fatalf("%#v", out)
	}
	cached, e := x.Enhance(context.Background(), r, nil)
	if e != nil || cached.InputFingerprint != out.InputFingerprint {
		t.Fatal("cache failed")
	}
}

func TestManualEnhancementDoesNotUseAutomaticThreshold(t *testing.T) {
	var requestBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"explanation\":\"The assertion shows a code defect.\",\"suggested_fix\":\"Correct the addition logic.\",\"patch\":\"\",\"warnings\":[]}"}}]}`))
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, APIKey: "key", Model: "qwen", MinimumScore: 99, Timeout: time.Second, MaxInputCharacters: 4000, MaxOutputTokens: 200}
	r := model.AnalysisResult{ID: "code", TenantID: "default", Category: model.CategoryCodeFailure, Attribution: model.AttributionCode, Confidence: model.ConfidenceLikelyCode, Score: -62, ExternalityScore: -62, EvidenceStrength: 62, CodeEvidenceScore: 62, Summary: "Go assertion failed", RedactedExcerpt: "expected 4, got 5"}
	out, err := New(cfg, store).Enhance(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Explanation == "" {
		t.Fatal("missing explanation")
	}
	messages, ok := requestBody["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatalf("messages=%#v", requestBody["messages"])
	}
	user, _ := messages[1].(map[string]any)
	content, _ := user["content"].(string)
	if !strings.Contains(content, `"evidence_strength":62`) || !strings.Contains(content, `"code_evidence_score":62`) || strings.Contains(content, `"score":-62`) {
		t.Fatalf("prompt=%s", content)
	}
}

func TestLocalEnhancementAllowsEmptyAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected authorization header")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"explanation\":\"Local model response.\",\"suggested_fix\":\"Review code.\",\"patch\":\"\",\"warnings\":[]}"}}]}`))
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, Model: "qwen-local", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200}
	if _, err := New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "local", TenantID: "default", Summary: "failure"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestResponseFormatFallback(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if calls == 1 {
			if _, ok := body["response_format"]; !ok {
				t.Fatal("first request should use response_format")
			}
			http.Error(w, `response_format json_object is unsupported`, http.StatusBadRequest)
			return
		}
		if _, ok := body["response_format"]; ok {
			t.Fatal("fallback request must remove response_format")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"explanation\":\"Fallback worked.\",\"suggested_fix\":\"Review.\",\"patch\":\"\",\"warnings\":[]}"}}]}`))
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, Model: "qwen", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200}
	if _, err := New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "fallback", TenantID: "default", Summary: "failure"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestPromptLimitKeepsJSONValid(t *testing.T) {
	e := &Enhancer{cfg: config.LLMConfig{MaxInputCharacters: 900, SendRedactedExcerpt: true, SendChangedFiles: true}}
	r := model.AnalysisResult{ID: "prompt", TenantID: "default", Summary: strings.Repeat("summary ", 20), RedactedExcerpt: strings.Repeat("évidence ", 1000)}
	prompt := e.buildPrompt(r, []string{strings.Repeat("very-long-file-name", 50)})
	if !json.Valid([]byte(prompt)) {
		t.Fatalf("invalid prompt JSON: %s", prompt)
	}
}

func TestCacheSeparatesEndpoints(t *testing.T) {
	response := func(text string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"explanation\":\"` + text + `\",\"suggested_fix\":\"Review.\",\"patch\":\"\",\"warnings\":[]}"}}]}`))
		}))
	}
	first := response("first endpoint")
	defer first.Close()
	second := response("second endpoint")
	defer second.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := model.AnalysisResult{ID: "same-analysis", TenantID: "default", Summary: "failure"}
	base := config.LLMConfig{Enabled: true, AllowPrivateNetwork: true, Model: "same-model", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200}
	base.Endpoint = first.URL
	one, err := New(base, store).Enhance(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.Endpoint = second.URL
	two, err := New(base, store).Enhance(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if one.Explanation == two.Explanation || two.Explanation != "second endpoint" {
		t.Fatalf("one=%q two=%q", one.Explanation, two.Explanation)
	}
}

func TestTrimKeepsUTF8Valid(t *testing.T) {
	out := trim("شرح عربي كامل", 7)
	if !utf8.ValidString(out) {
		t.Fatalf("invalid UTF-8: %q", out)
	}
}

func TestEnhancerBlocksPrivateEndpointByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, Model: "test", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200}
	_, err = New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "private", TenantID: "default", Summary: "failure"}, nil)
	if err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("private LLM endpoint was not blocked: %v", err)
	}
}

type failingLLMObjectStore struct {
	db.Backend
	err error
}

func (s failingLLMObjectStore) GetObject(context.Context, string, string, string, any) (bool, error) {
	return false, s.err
}

func TestEnhancePropagatesCacheReadFailure(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sentinel := errors.New("cache unavailable")
	cfg := config.LLMConfig{Enabled: true, Endpoint: "https://llm.example/v1", APIKey: "key", Model: "test"}
	enhancer := New(cfg, failingLLMObjectStore{Backend: store, err: sentinel})
	_, err = enhancer.Enhance(context.Background(), model.AnalysisResult{ID: "a", TenantID: "default", Summary: "failure"}, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("cache read error=%v", err)
	}
}

func TestReadLLMResponseBodyRejectsOversizedPayload(t *testing.T) {
	if _, err := readLLMResponseBody(strings.NewReader("12345"), 4); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}
