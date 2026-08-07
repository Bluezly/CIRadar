# CI Radar MCP

CI Radar exposes tenant-scoped MCP through stdio and Streamable HTTP. Read tools work with Viewer access. State-changing tools require Operator access, an active MCP session, and a short-lived confirmation token produced by `prepare_action`.

## Transports

### stdio

```bash
ciradar mcp --config ciradar.json --tenant acme
```

stdout is reserved for JSON-RPC messages.

### HTTP

- `POST /mcp` sends JSON-RPC requests
- `GET /mcp` opens a server-sent event stream for an authenticated session
- `DELETE /mcp` closes a session
- `MCP-Session-Id` identifies the session
- `Origin` is validated when present
- protocol versions are validated
- server notifications are emitted to active sessions

CI Radar publishes OAuth protected-resource and authorization-server metadata, dynamic client registration, Authorization Code with PKCE, explicit user consent, token issuance, and token revocation for MCP clients. The authorization endpoint displays the client name, redirect destination, tenant, and requested scopes; a same-origin POST approval is required before a code is issued.

## Read tools

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
- `get_repair_proposal`

## Confirmed write tools

- `acknowledge_incident`
- `resolve_incident`
- `quarantine_test`
- `unquarantine_test`
- `create_draft_repair_pr`

The client first calls:

```json
{
  "name": "prepare_action",
  "arguments": {
    "action": "resolve_incident",
    "target": "incident-fingerprint"
  }
}
```

The returned confirmation token is short-lived and bound to the tenant, actor, action, and target. The client then passes it to the selected write tool. CI Radar records an audit event for every accepted mutation.

MCP cannot run arbitrary commands, alter CI Radar configuration, apply a patch locally, or merge a repair pull request.

## Long-lived HTTP streams

Streamable HTTP SSE responses refresh a bounded write deadline before endpoint messages, server events, and heartbeats. This prevents the general HTTP `WriteTimeout` from terminating a healthy long-lived MCP stream while still bounding writes to a stalled client.
