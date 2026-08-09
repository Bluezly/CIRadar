# Architecture

CI Radar is a self-hosted Go service with a deterministic diagnosis core, tenant-scoped storage, provider adapters, background workers, and optional assistance layers.

```text
CI providers / uploaded test reports / API
                 |
          authenticated ingestion
                 |
          normalized CIEvent
                 |
       redaction + rule engine
                 |
     attribution + fingerprinting
                 |
 incidents / test history / metrics
                 |
 embedded store or PostgreSQL
                 |
 dashboard / API / alerts / ChatOps / MCP
```

## Main packages

- `internal/connectors` normalizes CI provider events, retrieves logs, and handles safe provider-specific actions.
- `internal/analyzer` performs redaction, deterministic matching, evidence weighting, attribution, and fingerprints.
- `internal/db` implements the embedded store, PostgreSQL-backed state, jobs, migrations, rate limits, replay state, and tenant-scoped persistence.
- `internal/pgwire` is the project-maintained PostgreSQL protocol client used by the PostgreSQL backend.
- `internal/testintelligence` tracks observations, test state, quarantine, critical-test policy, and reliability statistics.
- `internal/testselection` builds source-impact indexes and combines them with optional per-test coverage maps.
- `internal/notifications` handles event routing, retries, deduplication, and outbound channels.
- `internal/server` exposes the HTTP API, dashboard, webhooks, browser sessions, ChatOps endpoints, and service lifecycle.
- `internal/worker` processes queued analysis, notification, enrichment, and repair work.
- `internal/sso` implements OIDC, strict-profile SAML orchestration, and trusted-proxy identity.
- `internal/mcp` exposes stdio and HTTP MCP with OAuth/PKCE, sessions, SSE, and confirmation-gated writes.
- `internal/repair` validates bounded patch plans and local repair application.
- `internal/github` implements GitHub App authentication and GitHub-specific workflow actions.
- `internal/similarity` provides lexical, local-vector, Ollama, and remote embedding modes.
- `internal/llm` implements the optional model-assisted explanation and repair proposal path.

## Data boundaries

Tenant identity comes from authenticated context, not ordinary request payloads. Stored entities and PostgreSQL operations are tenant-scoped. Slack ChatOps additionally binds a verified workspace Team ID to the target tenant before a state-changing action can execute.

Raw logs are not stored by default. Redaction is applied before stored excerpts and before optional remote model or similarity requests. Cross-tenant correlation is disabled by default.

## Automation boundaries

Automatic rerun is restricted to qualifying external failures and is disabled by default. Automatic quarantine is opt-in and does not apply to critical tests. MCP mutations require both authorization and a short-lived confirmation token. Repair proposals never auto-merge.

## Storage choices

The embedded store is intended for evaluation and small single-process deployments. PostgreSQL provides shared tenant-scoped state, distributed request/auth rate limits, and job coordination for multi-instance deployments.

The custom PostgreSQL wire layer and project-maintained SAML parser/orchestration are explicit security and interoperability review boundaries. See [Security](../SECURITY.md) and [Limitations](limitations.md).
