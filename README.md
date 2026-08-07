# CI Radar

CI Radar is a free, self-hosted, open-source CI intelligence platform. It classifies failures with deterministic evidence, correlates incidents, tracks test reliability, measures CI cost and DORA signals, and can add optional local or BYOK AI without replacing the deterministic decision core.

License: AGPL-3.0-or-later.

Current release notes: `RELEASE-NOTES-OSS-RC14.md`.

## What RC.14 includes

- 630 built-in deterministic diagnosis rules spanning CI providers, language/toolchain failures, registries, cloud/infrastructure, data systems, and enterprise/mainframe signatures
- Tenant-isolated 24-hour diagnostic memory for repeated fingerprints in server/worker flows; benchmark analysis remains stateless
- 15 CI providers: GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins, Azure DevOps Pipelines, Bitrise, TeamCity, Travis CI, AWS CodeBuild, Bitbucket Pipelines, Drone, Semaphore, AppVeyor, and Google Cloud Build
- GitHub Checks, sticky GitHub Pull Request comments, full linked GitHub Issue lifecycle (create/read/update/assign/label/close/reopen/lock/comment), and sticky GitLab Merge Request comments
- relational tenant-scoped PostgreSQL storage or portable embedded storage
- tenant isolation, RBAC, API keys, encrypted secrets, retention, audit events, trusted proxies, CSP, OIDC, and native SAML SP flow
- Slack, Teams, Discord, Telegram, email, PagerDuty, Opsgenie, and signed generic webhooks
- ChatOps for acknowledge, resolve, quarantine, and restore
- Slack ChatOps workspace-to-tenant binding so a signed action cannot cross tenant boundaries through an embedded button value
- dedicated `test_quarantined` notifications emitted when automatic quarantine actually succeeds
- JUnit, Playwright, Jest, pytest, Cypress, and Mocha result ingestion
- triage-first test history with variants, grouped failures, unique PR impact, critical-test policy, quarantine, CI gates, source impact indexing, and per-test coverage maps
- a plain table-first dashboard prioritized by unresolved work, affected Pull Requests, and conservative engineering-time loss
- DORA metrics, runner duration, estimated cost, and historical trends
- lexical similarity fallback, local static vectors, local neural embeddings through Ollama, or BYOK remote embeddings
- MCP over stdio and Streamable HTTP with OAuth discovery, PKCE, sessions, SSE, server notifications, and confirmation-gated write tools
- safe automatic rerun for external failures, disabled by default
- source-grounded LLM repair suggestions with exact patch validation, confirmation-gated local patch application, optional idempotent GitHub draft repair Pull Requests, and repair-PR notifications
- Windows, Linux, and macOS builds for amd64 and arm64

## Quick start

```bash
ciradar init
ciradar demo npm-econnreset
ciradar demo go-test-failure
ciradar serve
```

`demo` is built into the binary, so the quick start does not depend on files from the source archive. `ciradar init` creates a configuration containing bootstrap secrets with owner-only permissions on POSIX systems. Restrict the file ACL on Windows and move production secrets to environment variables or a secret manager.

Open `http://127.0.0.1:8787/`, choose Session, and sign in with the generated root token.

## API routing and authentication hardening

The dashboard is served only at `/`. Unknown non-API paths return HTTP 404, and every unmatched path under `/api` returns a JSON 404 response. This prevents a misspelled integration endpoint from receiving dashboard HTML with HTTP 200.

Bearer-token and `/auth/token` failures are tracked separately from the general request limit. After 10 failed authentication attempts from one resolved client IP within five minutes, CI Radar applies an exponential delay starting at five seconds and capped at 15 minutes. Trusted-proxy configuration still controls which client IP is used.

## Build integrity and diagnostics

Release builds produce `SHA256SUMS`. Verify a downloaded binary before execution with `sha256sum -c SHA256SUMS` or the equivalent platform tool. A checksum detects corruption or substitution only when the checksum file itself comes from a trusted release channel.

The build scripts strip release binaries by default. Set `STRIP=0` when building an internal diagnostic binary with DWARF data retained. Go panic stacks normally retain function and source-location information even in stripped release builds, but an unstripped build is still more useful for debuggers and post-mortem tooling.

## Dependency and protocol ownership

The Go module intentionally has no third-party Go module dependencies. That reduces supply-chain surface but makes this project responsible for maintaining its custom PostgreSQL wire client and strict SAML parsing/orchestration. PostgreSQL values are sent through the Extended Query Protocol as separate bound parameters rather than interpolated into SQL text, but the wire implementation itself remains project-maintained. SAML XML-signature verification is delegated to the operator-configured `xmlsec1` executable, whose resolved executable is SHA-256 pinned and rechecked before verification; optional integrations such as PostgreSQL, Ollama, and external CI providers remain runtime dependencies when enabled. The custom protocol surfaces should receive independent security review before high-risk production deployment, and a mature PostgreSQL driver remains the preferred long-term replacement if the dependency policy changes.

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

## Accuracy measurement

Unit tests prove implementation behavior; they do not prove real-world diagnosis accuracy. `ciradar benchmark` evaluates the deterministic analyzer on an external labeled corpus and reports category accuracy, macro precision/recall/F1, UNKNOWN coverage, Wilson confidence intervals, confusion matrices, per-category errors, rule utilization, a dataset SHA-256, and an analyzer-configuration SHA-256. The configuration digest changes when rules or redaction behavior changes, while the private fingerprint key is deliberately excluded because it does not affect classification.

```bash
ciradar benchmark --dataset /path/to/dataset.json --split test --output benchmark-report.json
```

`benchmarks/example` is synthetic smoke-test data and must not be published as a product-accuracy score. `BENCHMARKING.md` defines the held-out labeling and publication policy. CI now runs the synthetic benchmark only as a regression test of the measurement harness.

User feedback metrics are kept separate from benchmark precision. `agreement_percent` summarizes correct/partial/incorrect reviewer feedback. Optional `actual_category`, `actual_cause`, `actual_provider`, and `actual_error_family` labels produce labeled accuracy metrics. The older `precision_percent` and `external_precision_percent` response fields remain compatibility aliases for agreement in this release and should not be interpreted as statistical precision.

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

A repeated local `analyze` command is score-stable by default. Add `--correlate` only when you explicitly want stored cross-run correlation to affect the score.

The signed `externality_score` is directional: negative means code evidence and positive means external evidence. Automation that should work for either direction uses `evidence_strength`; automatic repair uses `code_evidence_score`. A negative score is not low confidence.

The selector reports its strategy, confidence, reasons, impact path, candidates evaluated, graph availability, coverage identity count, and diagnostics when no test is selected. Coverage matches outrank import-graph paths; history and flake signals are secondary. The built-in source index currently parses Go, JavaScript, TypeScript, and Python. Coverage maps work for any language.

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

OIDC is native. SAML is also handled directly by CI Radar as an SP. SAML XML signatures are verified with a pinned IdP certificate through `xmlsec1`; strict response-shape, binding, algorithm, and replay checks are enabled by default. The parser/orchestration code remains project-maintained and should receive independent review before high-risk deployment. Metadata is available at `/auth/saml/metadata`.

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

Read `SECURITY.md`, `POSTGRESQL.md`, `CONNECTORS.md`, `TEST-INTELLIGENCE.md`, `MCP.md`, `SELF-HOSTING.md`, `COMPARISONS.md`, `COMPETITOR-BENCHMARK.md`, and `PROJECT-STATUS.md` before production use.
