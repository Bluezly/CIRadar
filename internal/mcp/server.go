package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ciradar/internal/config"
	"ciradar/internal/db"
	"ciradar/internal/insights"
	"ciradar/internal/model"
	"ciradar/internal/similarity"
	"ciradar/internal/testselection"
	"ciradar/internal/version"
)

type Server struct {
	Store    db.Backend
	Semantic config.SemanticConfig
	LLM      config.LLMConfig
	Repair   config.RepairConfig
	Runtime  *Runtime
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type CallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}
type ReadParams struct {
	URI string `json:"uri"`
}

func (s *Server) Handle(ctx context.Context, tenant string, req Request) Response {
	return s.HandlePrincipal(ctx, model.Principal{TenantID: tenant, Role: model.RoleViewer, Name: "mcp"}, req)
}

func (s *Server) HandlePrincipal(ctx context.Context, principal model.Principal, req Request) Response {
	tenant := principal.TenantID
	out := Response{JSONRPC: "2.0", ID: req.ID}
	if req.JSONRPC != "2.0" {
		out.Error = &RPCError{Code: -32600, Message: "invalid JSON-RPC version"}
		return out
	}
	switch req.Method {
	case "initialize":
		out.Result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}, "resources": map[string]any{"subscribe": false, "listChanged": false}}, "serverInfo": map[string]any{"name": "CI Radar", "version": version.Version}}
	case "notifications/initialized":
		out.Result = map[string]any{}
	case "ping":
		out.Result = map[string]any{}
	case "tools/list":
		out.Result = map[string]any{"tools": toolDefinitions(principal, s.Repair.Enabled)}
	case "tools/call":
		var p CallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			out.Error = &RPCError{Code: -32602, Message: "invalid tool parameters"}
			return out
		}
		result, err := s.callTool(ctx, principal, p)
		if err != nil {
			out.Error = &RPCError{Code: -32000, Message: err.Error()}
			return out
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		out.Result = map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}}, "structuredContent": result, "isError": false}
	case "resources/templates/list":
		out.Result = map[string]any{"resourceTemplates": []any{
			map[string]any{"uriTemplate": "ciradar://incidents/{fingerprint}", "name": "Incident by fingerprint", "mimeType": "application/json"},
			map[string]any{"uriTemplate": "ciradar://analyses/{id}", "name": "Diagnosis by ID", "mimeType": "application/json"},
			map[string]any{"uriTemplate": "ciradar://repositories/{owner}/{repo}/health", "name": "Repository CI health", "mimeType": "application/json"},
		}}
	case "resources/list":
		out.Result = map[string]any{"resources": []any{
			map[string]any{"uri": "ciradar://incidents/active", "name": "Active incidents", "mimeType": "application/json"},
			map[string]any{"uri": "ciradar://analyses/recent", "name": "Recent diagnoses", "mimeType": "application/json"},
			map[string]any{"uri": "ciradar://tests/flaky", "name": "Flaky tests", "mimeType": "application/json"},
		}}
	case "resources/read":
		var p ReadParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			out.Error = &RPCError{Code: -32602, Message: "invalid resource parameters"}
			return out
		}
		v, err := s.readResource(ctx, tenant, p.URI)
		if err != nil {
			out.Error = &RPCError{Code: -32002, Message: err.Error()}
			return out
		}
		b, _ := json.MarshalIndent(v, "", "  ")
		out.Result = map[string]any{"contents": []any{map[string]any{"uri": p.URI, "mimeType": "application/json", "text": string(b)}}}
	default:
		out.Error = &RPCError{Code: -32601, Message: "method not found"}
	}
	return out
}

func toolDefinitions(principal model.Principal, repairEnabled bool) []any {
	items := []any{
		tool("list_active_incidents", "List active CI incidents", map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}}),
		tool("get_incident", "Get one incident by fingerprint", map[string]any{"type": "object", "required": []string{"fingerprint"}, "properties": map[string]any{"fingerprint": map[string]any{"type": "string"}}}),
		tool("get_diagnosis", "Get one diagnosis by ID", map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}}),
		tool("find_similar_failures", "Find recent failures by fingerprint, category, provider or repository", map[string]any{"type": "object", "properties": map[string]any{"fingerprint": map[string]any{"type": "string"}, "category": map[string]any{"type": "string"}, "provider": map[string]any{"type": "string"}, "repository": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}}),
		tool("repository_health", "Summarize CI health for one repository", map[string]any{"type": "object", "required": []string{"repository"}, "properties": map[string]any{"repository": map[string]any{"type": "string"}}}),
		tool("list_flaky_tests", "List flaky tests", map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}, "minimum_score": map[string]any{"type": "number"}, "limit": map[string]any{"type": "integer"}}}),
		tool("semantic_similar_failures", "Find semantically similar failures", map[string]any{"type": "object", "required": []string{"analysis_id"}, "properties": map[string]any{"analysis_id": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}}),
		tool("select_impacted_tests", "Select tests likely impacted by changed files", map[string]any{"type": "object", "required": []string{"repository", "changed_files"}, "properties": map[string]any{"repository": map[string]any{"type": "string"}, "changed_files": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "framework": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}}),
		tool("get_dora_metrics", "Get DORA metrics", map[string]any{"type": "object", "properties": map[string]any{"days": map[string]any{"type": "integer"}, "environment": map[string]any{"type": "string"}}}),
		tool("get_ci_costs", "Get CI duration and estimated cost", map[string]any{"type": "object", "properties": map[string]any{"days": map[string]any{"type": "integer"}}}),
		tool("get_repair_proposal", "Get the reviewable repair proposal and draft PR result for one diagnosis", map[string]any{"type": "object", "required": []string{"analysis_id"}, "properties": map[string]any{"analysis_id": map[string]any{"type": "string"}}}),
	}
	if operatorOrHigher(principal) && allowsScope(principal, "ciradar.write") {
		items = append(items,
			writeTool("prepare_action", "Prepare a human-confirmed write action", map[string]any{"type": "object", "required": []string{"action", "target"}, "properties": map[string]any{"action": map[string]any{"type": "string", "enum": []string{"acknowledge_incident", "resolve_incident", "quarantine_test", "unquarantine_test", "create_draft_repair_pr"}}, "target": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}}}),
			writeTool("acknowledge_incident", "Acknowledge an incident after explicit confirmation", confirmationSchema()),
			writeTool("resolve_incident", "Resolve an incident after explicit confirmation", confirmationSchema()),
			writeTool("quarantine_test", "Quarantine a flaky test for a limited period after explicit confirmation", map[string]any{"type": "object", "required": []string{"target", "confirmation_token", "reason", "owner"}, "properties": map[string]any{"target": map[string]any{"type": "string"}, "confirmation_token": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}, "owner": map[string]any{"type": "string"}, "duration_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": 720}}}),
			writeTool("unquarantine_test", "Restore a quarantined test after explicit confirmation", confirmationSchema()),
			writeTool("create_draft_repair_pr", "Create a reviewable GitHub draft pull request from the stored repair patch after explicit confirmation", confirmationSchema()),
		)
	}
	return items
}
func allowsScope(principal model.Principal, scope string) bool {
	if len(principal.Scopes) == 0 {
		return true
	}
	for _, value := range principal.Scopes {
		if value == scope {
			return true
		}
	}
	return false
}

func tool(name, desc string, input map[string]any) map[string]any {
	return map[string]any{"name": name, "description": desc, "inputSchema": input, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true}}
}
func writeTool(name, desc string, input map[string]any) map[string]any {
	return map[string]any{"name": name, "description": desc, "inputSchema": input, "annotations": map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}}
}
func confirmationSchema() map[string]any {
	return map[string]any{"type": "object", "required": []string{"target", "confirmation_token"}, "properties": map[string]any{"target": map[string]any{"type": "string"}, "confirmation_token": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}}}
}

func (s *Server) callTool(ctx context.Context, principal model.Principal, p CallParams) (any, error) {
	tenant := principal.TenantID
	switch p.Name {
	case "list_active_incidents":
		return s.Store.ListIncidentsForTenant(ctx, tenant, intArg(p.Arguments, "limit", 50), "open")
	case "get_incident":
		fp := stringArg(p.Arguments, "fingerprint")
		if fp == "" {
			return nil, fmt.Errorf("fingerprint is required")
		}
		v, err := s.Store.GetIncidentForTenant(ctx, tenant, fp)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, fmt.Errorf("incident not found")
		}
		return v, nil
	case "get_diagnosis":
		id := stringArg(p.Arguments, "id")
		if id == "" {
			return nil, fmt.Errorf("id is required")
		}
		v, err := s.Store.GetAnalysisForTenant(ctx, tenant, id)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, fmt.Errorf("diagnosis not found")
		}
		return v, nil
	case "find_similar_failures":
		items, err := s.Store.ListAnalysesForTenant(ctx, tenant, min(intArg(p.Arguments, "limit", 50), 500))
		if err != nil {
			return nil, err
		}
		out := items[:0]
		for _, x := range items {
			if matchesAnalysis(x, stringArg(p.Arguments, "fingerprint"), stringArg(p.Arguments, "category"), stringArg(p.Arguments, "provider"), stringArg(p.Arguments, "repository")) {
				out = append(out, x)
			}
		}
		return out, nil
	case "repository_health":
		return s.repositoryHealth(ctx, tenant, stringArg(p.Arguments, "repository"))
	case "list_flaky_tests":
		repo := stringArg(p.Arguments, "repository")
		minScore := floatArg(p.Arguments, "minimum_score", 35)
		items, err := s.Store.ListTestCaseStats(ctx, tenant, repo, "", min(intArg(p.Arguments, "limit", 100), 500))
		if err != nil {
			return nil, err
		}
		out := items[:0]
		for _, x := range items {
			if x.FlakeScore >= minScore {
				out = append(out, x)
			}
		}
		return out, nil
	case "semantic_similar_failures":
		id := stringArg(p.Arguments, "analysis_id")
		if id == "" {
			return nil, fmt.Errorf("analysis_id is required")
		}
		return similarity.FindConfigured(ctx, s.Store, tenant, id, min(intArg(p.Arguments, "limit", 10), 100), s.Semantic, s.LLM)
	case "select_impacted_tests":
		repo := stringArg(p.Arguments, "repository")
		if repo == "" {
			return nil, fmt.Errorf("repository is required")
		}
		files := stringSliceArg(p.Arguments, "changed_files")
		if len(files) == 0 {
			return nil, fmt.Errorf("changed_files is required")
		}
		return testselection.Select(ctx, s.Store, tenant, model.TestSelectionRequest{Repository: repo, ChangedFiles: files, Framework: stringArg(p.Arguments, "framework"), Limit: intArg(p.Arguments, "limit", 100), IncludeFlaky: true})
	case "get_dora_metrics":
		days := intArg(p.Arguments, "days", 30)
		if days > 365 {
			days = 365
		}
		until := time.Now().UTC()
		return insights.DORA(ctx, s.Store, tenant, stringArg(p.Arguments, "environment"), until.Add(-time.Duration(days)*24*time.Hour), until)
	case "get_ci_costs":
		days := intArg(p.Arguments, "days", 30)
		if days > 365 {
			days = 365
		}
		until := time.Now().UTC()
		return insights.Usage(ctx, s.Store, tenant, until.Add(-time.Duration(days)*24*time.Hour), until)
	case "get_repair_proposal":
		id := stringArg(p.Arguments, "analysis_id")
		if id == "" {
			return nil, fmt.Errorf("analysis_id is required")
		}
		analysis, err := s.Store.GetAnalysisForTenant(ctx, tenant, id)
		if err != nil {
			return nil, err
		}
		if analysis == nil {
			return nil, fmt.Errorf("diagnosis not found")
		}
		var enhancement model.LLMEnhancement
		hasEnhancement, err := s.Store.GetObject(ctx, tenant, "llm_enhancement", id, &enhancement)
		if err != nil {
			return nil, err
		}
		var result model.RepairResult
		hasResult, err := s.Store.GetObject(ctx, tenant, "repair_result", id, &result)
		if err != nil {
			return nil, err
		}
		var source model.RepairSource
		hasSource, err := s.Store.GetObject(ctx, tenant, "analysis_source", id, &source)
		if err != nil {
			return nil, err
		}
		return map[string]any{"analysis": analysis, "enhancement": optionalValue(hasEnhancement, enhancement), "repair_result": optionalValue(hasResult, result), "source": optionalValue(hasSource, source), "repair_enabled": s.Repair.Enabled}, nil
	case "prepare_action":
		if s.Runtime == nil {
			return nil, fmt.Errorf("MCP write runtime is not configured")
		}
		action, target, reason := stringArg(p.Arguments, "action"), stringArg(p.Arguments, "target"), stringArg(p.Arguments, "reason")
		token, expires, err := s.Runtime.Prepare(principal, action, target, reason)
		if err != nil {
			return nil, err
		}
		return map[string]any{"confirmation_token": token, "action": action, "target": target, "expires_at": expires, "requires_human_confirmation": true}, nil
	case "acknowledge_incident", "resolve_incident":
		if s.Runtime == nil {
			return nil, fmt.Errorf("MCP write runtime is not configured")
		}
		target, token := stringArg(p.Arguments, "target"), stringArg(p.Arguments, "confirmation_token")
		if _, err := s.Runtime.Consume(principal, token, p.Name, target); err != nil {
			return nil, err
		}
		state := "acknowledged"
		if p.Name == "resolve_incident" {
			state = "resolved"
		}
		value, err := s.Store.UpdateIncidentState(ctx, tenant, target, state, principal.Name, stringArg(p.Arguments, "reason"))
		if err != nil {
			return nil, err
		}
		if value == nil {
			return nil, fmt.Errorf("incident not found")
		}
		return value, nil
	case "quarantine_test":
		if s.Runtime == nil {
			return nil, fmt.Errorf("MCP write runtime is not configured")
		}
		target, token := stringArg(p.Arguments, "target"), stringArg(p.Arguments, "confirmation_token")
		if _, err := s.Runtime.Consume(principal, token, p.Name, target); err != nil {
			return nil, err
		}
		hours := intArg(p.Arguments, "duration_hours", 168)
		if hours < 1 {
			hours = 1
		}
		if hours > 720 {
			hours = 720
		}
		return s.Store.SetTestQuarantine(ctx, model.TestQuarantine{TenantID: tenant, TestKey: target, Reason: stringArg(p.Arguments, "reason"), Owner: stringArg(p.Arguments, "owner"), CreatedBy: principal.Name, ExpiresAt: time.Now().UTC().Add(time.Duration(hours) * time.Hour)})
	case "unquarantine_test":
		if s.Runtime == nil {
			return nil, fmt.Errorf("MCP write runtime is not configured")
		}
		target, token := stringArg(p.Arguments, "target"), stringArg(p.Arguments, "confirmation_token")
		if _, err := s.Runtime.Consume(principal, token, p.Name, target); err != nil {
			return nil, err
		}
		if err := s.Store.RemoveTestQuarantine(ctx, tenant, target); err != nil {
			return nil, err
		}
		return map[string]any{"test_key": target, "quarantined": false}, nil
	case "create_draft_repair_pr":
		if !s.Repair.Enabled {
			return nil, fmt.Errorf("repair is disabled")
		}
		if s.Runtime == nil {
			return nil, fmt.Errorf("MCP write runtime is not configured")
		}
		target, token := stringArg(p.Arguments, "target"), stringArg(p.Arguments, "confirmation_token")
		if _, err := s.Runtime.Consume(principal, token, p.Name, target); err != nil {
			return nil, err
		}
		analysis, err := s.Store.GetAnalysisForTenant(ctx, tenant, target)
		if err != nil {
			return nil, err
		}
		if analysis == nil {
			return nil, fmt.Errorf("diagnosis not found")
		}
		var enhancement model.LLMEnhancement
		found, err := s.Store.GetObject(ctx, tenant, "llm_enhancement", target, &enhancement)
		if err != nil {
			return nil, err
		}
		if !found || strings.TrimSpace(enhancement.Patch) == "" {
			return nil, fmt.Errorf("diagnosis has no repair patch")
		}
		if err := s.Store.EnqueueForTenant(ctx, tenant, "repair.draft_pr", map[string]any{"tenant_id": tenant, "analysis_id": target}, time.Now().UTC()); err != nil {
			return nil, err
		}
		auditErr := s.Store.RecordAudit(ctx, model.AuditEvent{TenantID: tenant, Actor: principal.Name, Role: principal.Role, Action: "repair.draft_pr_requested", Resource: "analysis", ResourceID: target, CreatedAt: time.Now().UTC()})
		result := map[string]any{"status": "queued", "analysis_id": target, "review_required": true, "audit_recorded": auditErr == nil}
		if auditErr != nil {
			result["warning"] = "repair was queued, but its audit event could not be recorded"
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", p.Name)
	}
}

func (s *Server) readResource(ctx context.Context, tenant, uri string) (any, error) {
	switch {
	case uri == "ciradar://incidents/active":
		return s.Store.ListIncidentsForTenant(ctx, tenant, 100, "open")
	case uri == "ciradar://analyses/recent":
		return s.Store.ListAnalysesForTenant(ctx, tenant, 100)
	case uri == "ciradar://tests/flaky":
		return s.Store.ListTestCaseStats(ctx, tenant, "", "flaky", 200)
	case strings.HasPrefix(uri, "ciradar://incidents/"):
		return s.callTool(ctx, model.Principal{TenantID: tenant, Role: model.RoleViewer, Name: "resource"}, CallParams{Name: "get_incident", Arguments: map[string]any{"fingerprint": strings.TrimPrefix(uri, "ciradar://incidents/")}})
	case strings.HasPrefix(uri, "ciradar://analyses/"):
		return s.callTool(ctx, model.Principal{TenantID: tenant, Role: model.RoleViewer, Name: "resource"}, CallParams{Name: "get_diagnosis", Arguments: map[string]any{"id": strings.TrimPrefix(uri, "ciradar://analyses/")}})
	case strings.HasPrefix(uri, "ciradar://repositories/") && strings.HasSuffix(uri, "/health"):
		repo := strings.TrimSuffix(strings.TrimPrefix(uri, "ciradar://repositories/"), "/health")
		return s.repositoryHealth(ctx, tenant, repo)
	default:
		return nil, fmt.Errorf("resource not found")
	}
}

func (s *Server) repositoryHealth(ctx context.Context, tenant, repo string) (any, error) {
	if strings.TrimSpace(repo) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	analyses, err := s.Store.ListAnalysesForTenant(ctx, tenant, 500)
	if err != nil {
		return nil, err
	}
	filtered := analyses[:0]
	external, code := 0, 0
	for _, a := range analyses {
		if strings.EqualFold(a.Repository, repo) {
			filtered = append(filtered, a)
			if a.Attribution == "EXTERNAL" {
				external++
			}
			if a.Attribution == "CODE" {
				code++
			}
		}
	}
	incidents, err := s.Store.ListIncidentsForTenant(ctx, tenant, 100, "open")
	if err != nil {
		return nil, err
	}
	fingerprints := map[string]bool{}
	for _, a := range filtered {
		fingerprints[a.Fingerprint] = true
	}
	active := incidents[:0]
	for _, i := range incidents {
		if fingerprints[i.Fingerprint] {
			active = append(active, i)
		}
	}
	tests, err := s.Store.ListTestCaseStats(ctx, tenant, repo, "", 100)
	if err != nil {
		return nil, err
	}
	profile, err := s.Store.GetRepositoryProfile(ctx, tenant, repo)
	if err != nil {
		return nil, err
	}
	return map[string]any{"repository": repo, "diagnoses": len(filtered), "external": external, "code": code, "active_incidents": active, "recent_analyses": limitAnalyses(filtered, 20), "test_cases": tests, "profile": profile}, nil
}

func optionalValue[T any](ok bool, value T) any {
	if !ok {
		return nil
	}
	return value
}

func matchesAnalysis(a model.AnalysisResult, fp, cat, provider, repo string) bool {
	if fp != "" && !strings.EqualFold(a.Fingerprint, fp) {
		return false
	}
	if cat != "" && !strings.EqualFold(string(a.Category), cat) {
		return false
	}
	if provider != "" && !strings.Contains(strings.ToLower(a.Provider), strings.ToLower(provider)) {
		return false
	}
	if repo != "" && !strings.EqualFold(a.Repository, repo) {
		return false
	}
	return true
}
func stringArg(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
func intArg(m map[string]any, key string, fallback int) int {
	switch v := m[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	case json.Number:
		if n, e := v.Int64(); e == nil && n > 0 {
			return int(n)
		}
	}
	return fallback
}
func stringSliceArg(m map[string]any, key string) []string {
	v, ok := m[key].([]any)
	if !ok {
		if x, ok := m[key].([]string); ok {
			return x
		}
		return nil
	}
	out := []string{}
	for _, x := range v {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
func floatArg(m map[string]any, key string, fallback float64) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case json.Number:
		if n, e := v.Float64(); e == nil {
			return n
		}
	}
	return fallback
}

func limitAnalyses(v []model.AnalysisResult, n int) []model.AnalysisResult {
	if len(v) > n {
		return v[:n]
	}
	return v
}
