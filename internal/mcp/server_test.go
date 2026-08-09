package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/db"
	"github.com/Bluezly/CIRadar/internal/model"
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

func TestOAuthReadScopeHidesWriteTools(t *testing.T) {
	srv := &Server{Store: mcpStore(t), Runtime: NewRuntime()}
	principal := model.Principal{TenantID: model.DefaultTenantID, Name: "reader", Role: model.RoleOperator, Scopes: []string{"ciradar.read"}}
	resp := srv.HandlePrincipal(context.Background(), principal, Request{JSONRPC: "2.0", ID: 1, Method: "tools/list"})
	if resp.Error != nil {
		t.Fatal(resp.Error)
	}
	b, _ := json.Marshal(resp.Result)
	if contains(string(b), "prepare_action") || contains(string(b), "acknowledge_incident") {
		t.Fatalf("write tools exposed: %s", b)
	}
}

func TestRepairProposalAndConfirmedDraftPR(t *testing.T) {
	store := mcpStore(t)
	ctx := context.Background()
	analysis := model.AnalysisResult{ID: "repair-analysis", TenantID: model.DefaultTenantID, Repository: "acme/api", Attribution: model.AttributionCode, CreatedAt: time.Now().UTC()}
	if err := store.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{TenantID: model.DefaultTenantID, Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	enhancement := model.LLMEnhancement{AnalysisID: analysis.ID, TenantID: model.DefaultTenantID, Patch: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-old\n+new\n", CreatedAt: time.Now().UTC()}
	if err := store.PutObject(ctx, model.DefaultTenantID, "llm_enhancement", analysis.ID, enhancement); err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime()
	srv := &Server{Store: store, Runtime: runtime, Repair: config.RepairConfig{Enabled: true}}
	principal := model.Principal{TenantID: model.DefaultTenantID, Name: "operator", Role: model.RoleOperator}
	proposal, err := srv.callTool(ctx, principal, CallParams{Name: "get_repair_proposal", Arguments: map[string]any{"analysis_id": analysis.ID}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(proposal)
	if !contains(string(encoded), "diff --git") || !contains(string(encoded), "repair-analysis") {
		t.Fatalf("proposal=%s", encoded)
	}
	prepared, err := srv.callTool(ctx, principal, CallParams{Name: "prepare_action", Arguments: map[string]any{"action": "create_draft_repair_pr", "target": analysis.ID}})
	if err != nil {
		t.Fatal(err)
	}
	confirmation := prepared.(map[string]any)["confirmation_token"].(string)
	queued, err := srv.callTool(ctx, principal, CallParams{Name: "create_draft_repair_pr", Arguments: map[string]any{"target": analysis.ID, "confirmation_token": confirmation}})
	if err != nil {
		t.Fatal(err)
	}
	if queued.(map[string]any)["status"] != "queued" {
		t.Fatalf("queued=%#v", queued)
	}
	job, err := store.ClaimJob(ctx, "mcp-test")
	if err != nil || job == nil || job.Type != "repair.draft_pr" || job.TenantID != model.DefaultTenantID {
		t.Fatalf("job=%#v err=%v", job, err)
	}
}

func TestPrepareRejectsUnsupportedWriteAction(t *testing.T) {
	_, _, err := NewRuntime().Prepare(model.Principal{TenantID: model.DefaultTenantID, Name: "operator", Role: model.RoleOperator}, "retry_everything", "target", "")
	if err == nil {
		t.Fatal("unsupported action was accepted")
	}
}

type failingRepositoryHealthStore struct {
	db.Backend
	err error
}

func (s failingRepositoryHealthStore) ListIncidentsForTenant(context.Context, string, int, string) ([]model.Incident, error) {
	return nil, s.err
}

func TestRepositoryHealthPropagatesRelatedStoreFailure(t *testing.T) {
	store := mcpStore(t)
	sentinel := errors.New("incidents unavailable")
	srv := &Server{Store: failingRepositoryHealthStore{Backend: store, err: sentinel}}
	_, err := srv.repositoryHealth(context.Background(), "default", "acme/api")
	if !errors.Is(err, sentinel) {
		t.Fatalf("repository health error=%v", err)
	}
}

type failingMCPAuditStore struct {
	db.Backend
	err error
}

func (s failingMCPAuditStore) RecordAudit(context.Context, model.AuditEvent) error {
	return s.err
}

func TestDraftRepairQueueReportsAuditFailureWithoutReturningRetryableError(t *testing.T) {
	base := mcpStore(t)
	ctx := context.Background()
	analysis := model.AnalysisResult{ID: "repair-audit-failure", TenantID: model.DefaultTenantID, Repository: "acme/api", Attribution: model.AttributionCode, CreatedAt: time.Now().UTC()}
	if err := base.RecordAnalysisForTenant(ctx, model.DefaultTenantID, model.AnalysisInput{TenantID: model.DefaultTenantID, Repository: "acme/api"}, analysis, false, false); err != nil {
		t.Fatal(err)
	}
	if err := base.PutObject(ctx, model.DefaultTenantID, "llm_enhancement", analysis.ID, model.LLMEnhancement{AnalysisID: analysis.ID, TenantID: model.DefaultTenantID, Patch: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-old\n+new\n"}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("audit unavailable")
	runtime := NewRuntime()
	srv := &Server{Store: failingMCPAuditStore{Backend: base, err: sentinel}, Runtime: runtime, Repair: config.RepairConfig{Enabled: true}}
	principal := model.Principal{TenantID: model.DefaultTenantID, Name: "operator", Role: model.RoleOperator}
	prepared, err := srv.callTool(ctx, principal, CallParams{Name: "prepare_action", Arguments: map[string]any{"action": "create_draft_repair_pr", "target": analysis.ID}})
	if err != nil {
		t.Fatal(err)
	}
	confirmation := prepared.(map[string]any)["confirmation_token"].(string)
	queued, err := srv.callTool(ctx, principal, CallParams{Name: "create_draft_repair_pr", Arguments: map[string]any{"target": analysis.ID, "confirmation_token": confirmation}})
	if err != nil {
		t.Fatalf("queued operation should not become retryable after audit failure: %v", err)
	}
	result := queued.(map[string]any)
	if result["status"] != "queued" || result["audit_recorded"] != false || result["warning"] == "" {
		t.Fatalf("result=%#v", result)
	}
	job, err := base.ClaimJob(ctx, "audit-failure-test")
	if err != nil || job == nil || job.Type != "repair.draft_pr" {
		t.Fatalf("job=%#v err=%v", job, err)
	}
}
