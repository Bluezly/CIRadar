# CI Radar MCP

CI Radar exposes tenant-scoped read-only MCP tools. It deliberately excludes retry, resolve, quarantine and policy-changing operations.

## Tools

- `list_active_incidents`
- `get_incident`
- `get_diagnosis`
- `find_similar_failures`
- `semantic_similar_failures`
- `repository_health`
- `list_flaky_tests`
- `select_impacted_tests`
- `get_dora_metrics`
- `get_ci_costs`

## Resources

- `ciradar://incidents/active`
- `ciradar://analyses/recent`
- `ciradar://tests/flaky`
- dynamic incident, analysis and repository-health templates

## stdio

```bash
ciradar mcp --config ciradar.json --tenant acme
```

stdout is reserved for JSON-RPC messages.

## HTTP

Use `POST /mcp` with a tenant-scoped Viewer API key.

The HTTP transport validates `Origin` when present, validates supported MCP protocol versions and returns JSON-RPC responses as `application/json`. It does not implement OAuth discovery, sessions, SSE or server-initiated notifications. Authentication remains CI Radar SSO or API keys.
