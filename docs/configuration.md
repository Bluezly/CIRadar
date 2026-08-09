# Configuration

`ciradar init` creates a working local configuration with fresh bootstrap secrets. `ciradar.example.json` is the complete checked-in example for review and automation.

## Configuration sources

CI Radar loads the JSON configuration file first and then applies supported `CIRADAR_*` environment overrides. Secret fields may use environment references such as:

```json
{
  "dashboard_session_secret": "env:CIRADAR_DASHBOARD_SESSION_SECRET"
}
```

Use environment variables or a secret manager for production secrets. Do not commit generated `ciradar.json`, private keys, tokens, or database credentials.

## Core settings

| Setting | Purpose |
| --- | --- |
| `listen_address` | HTTP listen address |
| `public_base_url` | Externally reachable HTTPS origin used by browser/auth flows |
| `database_driver` | `embedded` or `postgres` |
| `database_path` | Embedded-state path |
| `database_url` | PostgreSQL DSN when PostgreSQL mode is enabled |
| `rules_directory` | Organization-defined deterministic rules |
| `retention_days` | Retention window for eligible historical data |
| `max_log_bytes` | Maximum decoded log size accepted for analysis; capped at 256 MiB |
| `store_raw_logs` | Raw-log persistence; disabled by default |
| `cross_tenant_correlation` | Cross-tenant correlation; disabled by default |

## Security-sensitive groups

- `sso` configures OIDC, SAML, or trusted proxy identity.
- `chatops` configures Slack and Teams request verification and allowlists.
- `notifications` configures outbound channels and event routing.
- `connectors` configures external CI providers and their webhook credentials.
- `llm` controls the optional model-assisted path and its data policy.
- `semantic` controls lexical, local vector, Ollama, or remote embedding modes.

Every outbound integration has an explicit private-network policy. Leave private-network access disabled unless the destination is intentionally internal and trusted.

## Validate before serving

```bash
ciradar doctor --config ciradar.json
ciradar database check --config ciradar.json
ciradar serve --config ciradar.json
```

For deployment guidance, continue with [Deployment](self-hosting.md).
