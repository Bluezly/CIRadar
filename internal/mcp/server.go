package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"ciradar/internal/db"
	"ciradar/internal/model"
	"ciradar/internal/version"
)

type Server struct{ Store db.Backend }

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
		out.Result = map[string]any{"tools": toolDefinitions()}
	case "tools/call":
		var p CallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			out.Error = &RPCError{Code: -32602, Message: "invalid tool parameters"}
			return out
		}
		result, err := s.callTool(ctx, tenant, p)
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

func toolDefinitions() []any {
	return []any{
		tool("list_active_incidents", "List active CI incidents", map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100}}}),
		tool("get_incident", "Get one incident by fingerprint", map[string]any{"type": "object", "required": []string{"fingerprint"}, "properties": map[string]any{"fingerprint": map[string]any{"type": "string"}}}),
		tool("get_diagnosis", "Get one diagnosis by ID", map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}}),
		tool("find_similar_failures", "Find recent failures by fingerprint, category, provider or repository", map[string]any{"type": "object", "properties": map[string]any{"fingerprint": map[string]any{"type": "string"}, "category": map[string]any{"type": "string"}, "provider": map[string]any{"type": "string"}, "repository": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}}),
		tool("repository_health", "Summarize CI health for one repository", map[string]any{"type": "object", "required": []string{"repository"}, "properties": map[string]any{"repository": map[string]any{"type": "string"}}}),
		tool("list_flaky_tests", "List flaky tests", map[string]any{"type": "object", "properties": map[string]any{"repository": map[string]any{"type": "string"}, "minimum_score": map[string]any{"type": "number"}, "limit": map[string]any{"type": "integer"}}}),
	}
}
func tool(name, desc string, input map[string]any) map[string]any {
	return map[string]any{"name": name, "description": desc, "inputSchema": input, "annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true}}
}

func (s *Server) callTool(ctx context.Context, tenant string, p CallParams) (any, error) {
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
	default:
		return nil, fmt.Errorf("unknown read-only tool %q", p.Name)
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
		return s.callTool(ctx, tenant, CallParams{Name: "get_incident", Arguments: map[string]any{"fingerprint": strings.TrimPrefix(uri, "ciradar://incidents/")}})
	case strings.HasPrefix(uri, "ciradar://analyses/"):
		return s.callTool(ctx, tenant, CallParams{Name: "get_diagnosis", Arguments: map[string]any{"id": strings.TrimPrefix(uri, "ciradar://analyses/")}})
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
	incidents, _ := s.Store.ListIncidentsForTenant(ctx, tenant, 100, "open")
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
	tests, _ := s.Store.ListTestCaseStats(ctx, tenant, repo, "", 100)
	profile, _ := s.Store.GetRepositoryProfile(ctx, tenant, repo)
	return map[string]any{"repository": repo, "diagnoses": len(filtered), "external": external, "code": code, "active_incidents": active, "recent_analyses": limitAnalyses(filtered, 20), "test_cases": tests, "profile": profile}, nil
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
