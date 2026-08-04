package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"ciradar/internal/db"
	"ciradar/internal/model"
)

func mcpStore(t *testing.T) *db.Store {
	t.Helper()
	s, err := db.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestReadOnlyToolsAreTenantScoped(t *testing.T) {
	s := mcpStore(t)
	ctx := context.Background()
	_, _ = s.CreateTenant(ctx, "other", "Other")
	a1 := model.AnalysisResult{ID: "a1", TenantID: "default", Repository: "acme/api", Fingerprint: "fp1", Category: model.CategoryNetworkFailure, Attribution: model.AttributionExternal, CreatedAt: time.Now()}
	a2 := model.AnalysisResult{ID: "a2", TenantID: "other", Repository: "secret/repo", Fingerprint: "fp2", Category: model.CategoryCodeFailure, Attribution: model.AttributionCode, CreatedAt: time.Now()}
	_ = s.RecordAnalysisForTenant(ctx, "default", model.AnalysisInput{TenantID: "default", Repository: "acme/api"}, a1, false, false)
	_ = s.RecordAnalysisForTenant(ctx, "other", model.AnalysisInput{TenantID: "other", Repository: "secret/repo"}, a2, false, false)
	srv := &Server{Store: s}
	params, _ := json.Marshal(CallParams{Name: "find_similar_failures", Arguments: map[string]any{"limit": 100}})
	resp := srv.Handle(ctx, "default", Request{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatal(resp.Error)
	}
	b, _ := json.Marshal(resp.Result)
	text := string(b)
	if !contains(text, "a1") || contains(text, "a2") || contains(text, "secret/repo") {
		t.Fatalf("tenant leak: %s", text)
	}
}
func TestInitializeAndReadResource(t *testing.T) {
	srv := &Server{Store: mcpStore(t)}
	r := srv.Handle(context.Background(), "default", Request{JSONRPC: "2.0", ID: "x", Method: "initialize"})
	if r.Error != nil || r.Result == nil {
		t.Fatalf("init=%#v", r)
	}
	p, _ := json.Marshal(ReadParams{URI: "ciradar://incidents/active"})
	r = srv.Handle(context.Background(), "default", Request{JSONRPC: "2.0", ID: 2, Method: "resources/read", Params: p})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
}
func TestUnknownWriteToolIsRejected(t *testing.T) {
	p, _ := json.Marshal(CallParams{Name: "retry_job", Arguments: map[string]any{}})
	r := (&Server{Store: mcpStore(t)}).Handle(context.Background(), "default", Request{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: p})
	if r.Error == nil {
		t.Fatal("write tool unexpectedly allowed")
	}
}
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
