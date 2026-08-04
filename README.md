# CI Radar

CI Radar is a free, self-hosted, open-source CI intelligence platform. It classifies failures with deterministic evidence, correlates incidents, tracks test reliability, measures CI cost and DORA signals, and can add optional local or BYOK AI without replacing the deterministic decision core.

License: AGPL-3.0-or-later.

## What RC.5 includes

- 15 CI providers: GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins, Azure DevOps Pipelines, Bitrise, TeamCity, Travis CI, AWS CodeBuild, Bitbucket Pipelines, Drone, Semaphore, AppVeyor, and Google Cloud Build
- GitHub Checks, sticky GitHub Pull Request comments, and sticky GitLab Merge Request comments
- relational tenant-scoped PostgreSQL storage or portable embedded storage
- tenant isolation, RBAC, API keys, encrypted secrets, retention, audit events, trusted proxies, CSP, OIDC, and native SAML SP flow
- Slack, Teams, Discord, Telegram, email, PagerDuty, Opsgenie, and signed generic webhooks
- ChatOps for acknowledge, resolve, quarantine, and restore
- JUnit, Playwright, Jest, pytest, Cypress, and Mocha result ingestion
- test history, likely flake cause, quarantine, CI gates, source impact indexing, and per-test coverage maps
- DORA metrics, runner duration, estimated cost, and historical trends
- lexical similarity fallback, local static vectors, local neural embeddings through Ollama, or BYOK remote embeddings
- MCP over stdio and Streamable HTTP with OAuth discovery, PKCE, sessions, SSE, server notifications, and confirmation-gated write tools
- safe automatic rerun for external failures, disabled by default
- repair plan and confirmation-gated local patch application, plus optional GitHub draft repair Pull Requests
- Windows, Linux, and macOS builds for amd64 and arm64
- field-test fixes: stable local analysis scores by default, opt-in `--correlate`, readable test quarantine selectors, coverage identity aliases, selection diagnostics, built-in CLI samples, and standard Go test failure classification

## Quick start

```bash
ciradar init
ciradar analyze --sample npm-econnreset
ciradar analyze --sample go-test-failure
ciradar serve
```

Open `http://127.0.0.1:8787/` and exchange the generated root token through the secure login field. `ciradar.json` contains generated administrative and cryptographic secrets, is created with mode `0600` on Unix, and must not be committed or shared.

## Local analysis behavior

Local CLI analyses are deterministic by default and do not change score because the same file was analyzed earlier. Add `--correlate` only when you intentionally want stored cross-run correlation included.

## PostgreSQL

```json
{
  "database_driver": "postgres",
  "database_url": "env:CIRADAR_DATABASE_URL"
}
```

```bash
ciradar database check
ciradar serve
```

## Test impact selection

Build the repository import graph:

```bash
ciradar tests index --repo acme/api --root .
```

Optionally add exact per-test coverage links:

```bash
ciradar tests coverage --repo acme/api coverage-map.json
```

Select impacted tests:

```bash
ciradar tests select --repo acme/api --changed src/payments.go,src/ledger.go
```

The selector reports its strategy, confidence, reasons, and impact path. Coverage matches outrank import-graph paths; history and flake signals are secondary. The built-in source index currently parses Go, JavaScript, TypeScript, and Python. Coverage maps work for any language.

## Similarity modes

```json
{
  "semantic": {
    "enabled": true,
    "mode": "ollama",
    "local_endpoint": "http://127.0.0.1:11434/api/embed",
    "local_model": "embeddinggemma"
  }
}
```

Modes:

- `lexical`: transparent FNV bag-of-words fallback, not marketed as embeddings
- `local-vectors`: local word-vector file
- `ollama`: local neural embeddings
- `remote`: BYOK remote embeddings

Every result includes the engine used.

## SSO

OIDC is native. SAML is also handled directly by CI Radar as an SP. SAML XML signatures are verified with a pinned IdP certificate through `xmlsec1`; no SAML auth proxy is required. Metadata is available at `/auth/saml/metadata`.

See `SSO.md`.

## MCP

MCP supports:

- stdio
- Streamable HTTP
- protected-resource and authorization-server metadata
- dynamic client registration
- Authorization Code with PKCE
- session IDs
- SSE event streams
- server notifications
- Viewer read tools
- Operator write tools requiring a short-lived human confirmation token

See `MCP.md`.

## Safe rerun and repair

Automatic rerun is off by default. It is considered only when attribution is `EXTERNAL`, confidence exceeds the configured threshold, the category is retry-safe, no provider-wide incident is active, and the run has not already been retried.

Native rerun requests are available for GitHub, GitLab, CircleCI, Buildkite, Travis, Google Cloud Build, Azure DevOps, Bitbucket, Drone, Semaphore, AppVeyor, Bitrise, and TeamCity. Jenkins and AWS CodeBuild can use a same-origin configured retry endpoint.

Repair is separate from rerun. A patch must pass path, size, binary-file, symlink, and confirmation checks. Automatic merge is not implemented.

## Security defaults

- raw log storage disabled
- redaction before persistence, fingerprints, and optional AI
- LLM and embeddings optional
- auto-rerun, auto-quarantine, and auto-repair disabled
- tenant-scoped API, storage, dashboard, and MCP
- strict CSP and HttpOnly encrypted dashboard sessions
- PostgreSQL TLS verification enabled by default

Read `SECURITY.md`, `POSTGRESQL.md`, `CONNECTORS.md`, `TEST-INTELLIGENCE.md`, `MCP.md`, `SELF-HOSTING.md`, `COMPARISONS.md`, and `PROJECT-STATUS.md` before production use.
