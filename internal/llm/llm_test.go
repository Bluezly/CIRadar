package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

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
	cfg := config.LLMConfig{Enabled: true, Endpoint: srv.URL, APIKey: "key", Model: "test", Timeout: time.Second, MaxInputCharacters: 2000, MaxOutputTokens: 200, SendRedactedExcerpt: true}
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
