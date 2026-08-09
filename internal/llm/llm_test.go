package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
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

func TestGeneratedPatchMustApplyToFetchedSource(t *testing.T) {
	patch := "--- a/main.go\n+++ b/main.go\n@@ -1,2 +1,2 @@\n package main\n-func value() int { return 1 }\n+func value() int { return 2 }\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]any{"content": `{"explanation":"The function returns the wrong value.","suggested_fix":"Return 2.","patch":` + strconv.Quote(patch) + `,"warnings":[]}`}}}})
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, Model: "local", Timeout: time.Second, MaxInputCharacters: 10000, MaxOutputTokens: 500, SendSourceCode: true, DataPolicy: "local_only"}
	analysis := model.AnalysisResult{ID: "source-patch", TenantID: "default", Summary: "wrong result"}
	out, err := New(cfg, store).EnhanceWithSources(context.Background(), analysis, []string{"main.go"}, []SourceFile{{Path: "main.go", Content: "package main\nfunc value() int { return 1 }\n"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Patch == "" || out.Metadata["patch_validated_against_source"] != "true" {
		t.Fatalf("enhancement=%#v", out)
	}
}

func TestGeneratedPatchRejectedWhenSourceDoesNotMatch(t *testing.T) {
	patch := "--- a/main.go\n+++ b/main.go\n@@ -1,1 +1,1 @@\n-not present\n+replacement\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]any{"content": `{"explanation":"Attempted repair.","suggested_fix":"Review.","patch":` + strconv.Quote(patch) + `,"warnings":[]}`}}}})
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, AllowPrivateNetwork: true, Model: "local", Timeout: time.Second, MaxInputCharacters: 10000, MaxOutputTokens: 500, SendSourceCode: true, DataPolicy: "local_only"}
	out, err := New(cfg, store).EnhanceWithSources(context.Background(), model.AnalysisResult{ID: "bad-patch", TenantID: "default", Summary: "failure"}, nil, []SourceFile{{Path: "main.go", Content: "package main\n"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Patch != "" || len(out.Warnings) == 0 || !strings.Contains(strings.Join(out.Warnings, " "), "rejected") {
		t.Fatalf("enhancement=%#v", out)
	}
}

func TestResponsesEndpointUsesResponsesRequestShape(t *testing.T) {
	var requestBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/responses") {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"output": []map[string]any{{"content": []map[string]any{{"type": "output_text", "text": `{"explanation":"Responses shape worked.","suggested_fix":"Review.","patch":"","warnings":[]}`}}}},
			"usage":  map[string]int{"input_tokens": 10, "output_tokens": 5},
		})
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL + "/v1/responses", AllowPrivateNetwork: true, Model: "test", Timeout: time.Second, MaxInputCharacters: 4000, MaxOutputTokens: 321}
	out, err := New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "responses", TenantID: "default", Summary: "failure"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Explanation == "" {
		t.Fatal("missing response")
	}
	if _, ok := requestBody["messages"]; ok {
		t.Fatalf("chat messages leaked into Responses request: %#v", requestBody)
	}
	if requestBody["input"] == nil || requestBody["instructions"] == nil || requestBody["max_output_tokens"] != float64(321) {
		t.Fatalf("invalid Responses request: %#v", requestBody)
	}
	if _, ok := requestBody["text"]; !ok {
		t.Fatalf("missing Responses JSON format: %#v", requestBody)
	}
}

func TestPromptBudgetPreservesTruncatedSourceContext(t *testing.T) {
	e := &Enhancer{cfg: config.LLMConfig{MaxInputCharacters: 5000, SendRedactedExcerpt: true, SendChangedFiles: true, SendSourceCode: true, MaxSourceFiles: 8, MaxSourceFileCharacters: 32000, DataPolicy: "local_only"}}
	analysis := model.AnalysisResult{ID: "budget", TenantID: "default", Summary: "assertion failed", RedactedExcerpt: strings.Repeat("stack trace line\n", 400)}
	prompt, err := e.buildPromptCheckedWithSources(analysis, []string{"large.go"}, []SourceFile{{Path: "large.go", Content: "package main\n" + strings.Repeat("func generated() {}\n", 2000)}})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(prompt)) {
		t.Fatalf("invalid JSON: %s", prompt)
	}
	if len(prompt) > 5000 {
		t.Fatalf("prompt exceeded budget: %d", len(prompt))
	}
	var payload struct {
		Sources []SourceFile `json:"source_files_untrusted"`
	}
	if err := json.Unmarshal([]byte(prompt), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Sources) != 1 || payload.Sources[0].Content == "" || !payload.Sources[0].Truncated {
		t.Fatalf("source context was discarded instead of trimmed: %#v", payload.Sources)
	}
}

func TestAnthropicProviderUsesNativeMessagesAPI(t *testing.T) {
	var requestBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "anthropic-secret" || r.Header.Get("Anthropic-Version") != "2023-06-01" {
			t.Fatalf("anthropic headers=%v", r.Header)
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected bearer authorization: %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": `{"explanation":"Native Anthropic worked.","suggested_fix":"Review.","patch":"","warnings":[]}`}},
			"usage":   map[string]int{"input_tokens": 12, "output_tokens": 7},
		})
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{Enabled: true, Provider: "anthropic", Endpoint: srv.URL, APIKey: "anthropic-secret", AllowPrivateNetwork: true, Model: "claude-test", Timeout: time.Second, MaxInputCharacters: 4000, MaxOutputTokens: 333, DataPolicy: "local_only"}
	out, err := New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "anthropic", TenantID: "default", Summary: "failure"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Explanation != "Native Anthropic worked." || out.Usage["input_tokens"] != 12 {
		t.Fatalf("output=%#v", out)
	}
	if requestBody["system"] == nil || requestBody["messages"] == nil || requestBody["max_tokens"] != float64(333) {
		t.Fatalf("request=%#v", requestBody)
	}
	if _, ok := requestBody["response_format"]; ok {
		t.Fatalf("OpenAI response_format leaked into Anthropic request: %#v", requestBody)
	}
}

func TestAnthropicMessagesEndpointNormalization(t *testing.T) {
	cases := map[string]string{
		"https://api.anthropic.com":             "https://api.anthropic.com/v1/messages",
		"https://api.anthropic.com/v1":          "https://api.anthropic.com/v1/messages",
		"https://proxy.example/v1/messages":     "https://proxy.example/v1/messages",
		"https://proxy.example/custom/messages": "https://proxy.example/custom/messages",
	}
	for input, want := range cases {
		if got := anthropicMessagesEndpoint(input); got != want {
			t.Fatalf("endpoint %q = %q, want %q", input, got, want)
		}
	}
}

func TestRedactedRemoteSanitizesFilePathsBeforePrompt(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("A", 32)
	e := &Enhancer{cfg: config.LLMConfig{
		MaxInputCharacters:      8000,
		SendChangedFiles:        true,
		SendSourceCode:          true,
		MaxSourceFiles:          4,
		MaxSourceFileCharacters: 4000,
		DataPolicy:              "redacted_remote",
		BlockOnResidualSecret:   true,
	}}
	prompt, err := e.buildPromptCheckedWithSources(
		model.AnalysisResult{ID: "paths", TenantID: "default", Summary: "failure"},
		[]string{"src/token=" + secret + "/main.go"},
		[]SourceFile{{Path: "src/token=" + secret + "/main.go", Content: "package main\n"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, secret) {
		t.Fatalf("remote prompt leaked a secret embedded in a file path: %s", prompt)
	}
	if !strings.Contains(prompt, "REDACTED") {
		t.Fatalf("expected redacted path marker in prompt: %s", prompt)
	}
}

func TestRedactedRemoteSanitizesModelOutputAndDropsSecretPatch(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("A", 32)
	patch := "--- a/main.go\n+++ b/main.go\n@@ -1 +1,2 @@\n package main\n+var token = \"" + secret + "\"\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		content := map[string]any{
			"explanation":   "provider echoed token " + secret,
			"suggested_fix": "rotate " + secret,
			"patch":         patch,
			"warnings":      []string{},
		}
		encoded, _ := json.Marshal(content)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]any{"content": string(encoded)}}}})
	}))
	defer srv.Close()
	store, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.LLMConfig{
		Enabled:               true,
		Endpoint:              srv.URL,
		AllowPrivateNetwork:   true,
		Model:                 "remote-test",
		Timeout:               time.Second,
		MaxInputCharacters:    4000,
		MaxOutputTokens:       300,
		DataPolicy:            "redacted_remote",
		BlockOnResidualSecret: true,
	}
	out, err := New(cfg, store).Enhance(context.Background(), model.AnalysisResult{ID: "remote-output", TenantID: "default", Summary: "failure"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Explanation, secret) || strings.Contains(out.SuggestedFix, secret) {
		t.Fatalf("remote model output retained a secret: %#v", out)
	}
	if out.Patch != "" {
		t.Fatalf("secret-bearing remote patch was retained: %q", out.Patch)
	}
	if !strings.Contains(strings.Join(out.Warnings, " "), "secret-like") {
		t.Fatalf("missing secret-output warning: %#v", out.Warnings)
	}
}
