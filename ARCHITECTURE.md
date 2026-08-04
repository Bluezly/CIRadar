# CI Radar architecture — 1.2.0 OSS RC.3

CI Radar is a free self-hosted CI failure intelligence service. The deterministic analyzer remains the decision core. Optional systems such as LLM enhancement and remote embeddings operate above the stored deterministic result and never replace it.

## Processing path

```text
CI provider webhook or manual upload
             |
             v
signature validation and tenant resolution
             |
             v
normalized CIEvent and persistent queue
             |
             v
bounded log retrieval and secret redaction
             |
             v
rules, contradictory evidence, history, provider state and correlation
             |
             v
AnalysisResult, suggested actions and protected fingerprint
             |
             +--> GitHub Check and sticky PR comment
             +--> GitLab sticky MR note
             +--> incident lifecycle and ChatOps
             +--> notifications and on-call systems
             +--> dashboard, DORA, cost and historical trends
             +--> read-only MCP and optional BYOK LLM
```

## Packages

- `internal/analyzer` contains deterministic rules, scoring, attribution, environment drift, fingerprints and suggested actions.
- `internal/connectors` validates and normalizes GitLab, Buildkite, CircleCI, Jenkins, Azure DevOps, Bitrise, TeamCity, Travis CI and AWS CodeBuild events.
- `internal/github` handles GitHub App authentication, Actions logs, Check Runs and sticky PR comments.
- `internal/marketplace` records optional GitHub Marketplace installation metadata without product feature gates.
- `internal/db` defines the storage contract and implements embedded and PostgreSQL backends.
- `internal/pgwire` is the bundled PostgreSQL wire client with TLS and SCRAM-SHA-256.
- `internal/testintelligence` parses JUnit, Playwright, Jest, pytest, Cypress and Mocha reports and infers probable flaky causes.
- `internal/testselection` ranks tests against changed files and historical failures.
- `internal/insights` calculates DORA metrics, CI usage, cost estimates and daily trends.
- `internal/similarity` offers local vector similarity and optional remote embeddings.
- `internal/llm` provides optional OpenAI-compatible explanation and patch generation.
- `internal/sso` implements native OIDC and trusted authentication-proxy identity for SAML deployments.
- `internal/notifications` provides policy routing, retries, deduplication and enterprise channels.
- `internal/mcp` exposes tenant-scoped read-only tools and resources.
- `internal/server` provides HTTP, dashboard, SSO, REST, webhooks, ChatOps, metrics and MCP.
- `internal/worker` executes queued work, correlation, comments, drift events and safe retry decisions.

## Storage

Every caller depends on `db.Backend`.

### Embedded backend

The embedded backend uses atomic replacement, fsync and backup recovery. It is suitable for evaluation and small single-process installations.

### PostgreSQL backend

The PostgreSQL backend supports verified TLS, SCRAM-SHA-256, migrations, transactions, row locks, and advisory locks. RC.3 stores one row per tenant entity in `ciradar_objects`, jobs in a queue table, and webhook idempotency records in a delivery table. Locks are scoped to the affected tenant and entity kind. This removes the global JSONB bottleneck while preserving the existing backend contract. It is a scalable self-hosted entity store, not a distributed hyperscale analytics claim.

## Isolation and authorization

All analyses, incidents, test history, quarantines, deployments, usage, notifications, API keys, installation bindings and audit records are tenant-scoped. Roles are Viewer, Operator, Admin and Root. SSO identities map to the same principal model as API keys.

## Security boundaries

- Raw logs are disabled by default.
- Redaction runs before persistence and fingerprinting.
- Cross-tenant correlation is disabled by default and requires an HMAC key.
- LLM and remote embeddings are disabled by default.
- ChatOps write actions are disabled until explicitly enabled.
- MCP is read-only.
- Auto-retry and auto-quarantine are disabled by default.
