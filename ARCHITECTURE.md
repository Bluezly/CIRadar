# CI Radar architecture — 1.3.2 OSS RC.14

CI Radar is a self-hosted Go service with a deterministic diagnosis core and optional local or BYOK intelligence layers.

```text
CI providers and uploaded reports
              |
       authenticated adapters
              |
         normalized CIEvent
              |
  redaction -> rules -> attribution
              |
 incidents, baselines, tests, DORA, cost
              |
 PostgreSQL or embedded storage
              |
 Dashboard, Checks, PR/MR comments, alerts, ChatOps, API, MCP
```

## Main components

- `internal/connectors` normalizes fifteen CI providers and performs provider-scoped log retrieval and safe rerun.
- `internal/analyzer` redacts secrets, applies deterministic rules, weighs contradictory evidence, and produces explainable attribution.
- `internal/incident` correlates fingerprints across repositories and organizations.
- `internal/testselection` stores coverage maps and static import impact graphs for test selection.
- `internal/testintel` tracks test observations, flake state, likely causes, quarantine, and CI gates.
- `internal/similarity` separates lexical hashing from Ollama, local vector-file, and remote embedding engines.
- `internal/sso` implements OIDC, native strict-profile SAML with a SHA-256-pinned `xmlsec1` executable, and trusted proxy identity.
- `internal/mcp` provides stdio and HTTP MCP, OAuth metadata, PKCE, sessions, SSE notifications, and confirmed Operator actions.
- `internal/repair` creates bounded patch plans and optional GitHub draft repair pull requests. It never auto-merges.
- `internal/db` provides the embedded backend and relational PostgreSQL object, queue, delivery, migration, and indexing layers.

## Storage

The embedded backend targets evaluation and small single-process installations. PostgreSQL stores independent tenant-scoped entity rows and a separate `SKIP LOCKED` queue. It is suitable for replicated self-hosting, but CI Radar does not claim a globally distributed hyperscale event store.

## Automation boundary

Safe rerun is allowed only for high-confidence external failures and is disabled by default. Repair proposals require explicit enablement. MCP mutations require Operator authorization plus a short-lived action confirmation. Source changes are never auto-merged.

## Data boundary

Raw logs are off by default. Redaction occurs before excerpts, fingerprints, persistence, LLM requests, and similarity text. Cross-tenant correlation uses HMAC fingerprints when enabled.
