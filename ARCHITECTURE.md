# CI Radar architecture — 1.0.0 RC.1

## Data flow

```text
GitHub / GitLab / Buildkite / CircleCI / Jenkins / manual API
                         ↓
                  verified CIEvent
                         ↓
                tenant-scoped job queue
                         ↓
        log fetch → redaction → environment extraction
                         ↓
 rules + evidence + history + correlation + provider status
                         ↓
 AnalysisResult + SuggestedActions + fingerprint
                         ↓
 Checks/comments · incidents · notifications · dashboard · MCP
```

## Packages

- `internal/connectors`: webhook verification, payload normalization, provider log fetch, GitLab MR notes.
- `internal/github`: GitHub App JWT/tokens, Actions API, job logs, Check Runs, sticky PR comments.
- `internal/analyzer`: deterministic classification, evidence scoring, fingerprints, environment drift, actions.
- `internal/testintelligence`: JUnit parsing and test identity.
- `internal/db`: `Backend` contract, embedded atomic store, PostgreSQL compatibility backend.
- `internal/pgwire`: pure-Go PostgreSQL protocol subset with TLS, MD5 and SCRAM-SHA-256.
- `internal/notifications`: channel policy, dedup, quiet hours, retries and delivery tracking.
- `internal/mcp`: read-only JSON-RPC tools/resources.
- `internal/server`: REST, dashboard, webhooks, MCP HTTP, metrics, auth and RBAC.
- `internal/worker`: background execution, correlation, comments, retry policy and environment baselines.

## Storage

`db.Backend` isolates all callers from storage details.

### Embedded

- atomic temp-file replacement
- fsync and backup recovery
- single process only
- portable local/private beta

### PostgreSQL RC backend

- TLS and SCRAM-SHA-256 capable
- automatic migration
- `SELECT ... FOR UPDATE` transaction around state mutation
- multiple API/worker processes cannot overwrite one another
- compatible with every feature

Current tradeoff: one canonical JSONB state row serializes mutations. It provides durability and correctness, but not high-write horizontal scaling. A normalized backend can replace it behind the same interface without rewriting the analyzer or integrations.

## Tenant isolation

Every analysis, incident, queue job, baseline, notification, feedback entry, test, quarantine, API key, profile and audit event has a tenant boundary. GitHub installations and external connectors resolve a tenant before enqueueing work. Disabled tenants are not processed.

## Decision model

The analyzer separates:

- rule evidence
- contextual evidence
- contradictory evidence
- external and code scores
- final attribution and confidence

Automatic retry is only eligible when attribution is external, score passes threshold, and no unsafe contradiction applies.

## Test reliability

JUnit observations normalize to a deterministic test key. State tracks total runs, failures, transitions, flake score, classification and quarantine. `tests gate` makes quarantine enforceable from any CI provider.

## MCP

Read-only by design. HTTP shares tenant-scoped Viewer authentication with REST. stdio reads credentials/config from the process environment. No model-controlled write actions are exposed.
