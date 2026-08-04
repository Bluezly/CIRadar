# CI Radar MCP

## Design

CI Radar exposes only read-only tools/resources. This is intentional: an LLM cannot retry builds, resolve incidents, change policies or quarantine tests through MCP.

## Tools

- `list_active_incidents`
- `get_incident`
- `get_diagnosis`
- `find_similar_failures`
- `repository_health`
- `list_flaky_tests`

## Resources

- `ciradar://incidents/active`
- `ciradar://analyses/recent`
- `ciradar://tests/flaky`
- templates for incidents, analyses and repository health

## stdio

```bash
ciradar mcp --config ciradar.json --tenant acme
```

stdout is reserved for newline-delimited JSON-RPC. Logs must not be printed to stdout.

## HTTP

Endpoint: `POST /mcp`.

- Bearer Viewer API key required.
- Origin is validated when present.
- protocol versions 2025-03-26, 2025-06-18 and 2025-11-25 accepted.
- notifications return HTTP 202 with no body.
- JSON-RPC requests return `application/json`.
- `GET /mcp` returns 405 because server-initiated SSE is not offered.

This is a basic Streamable HTTP implementation without sessions or server-to-client notifications. It does not implement OAuth discovery; authentication is the product's tenant-scoped API key system.
