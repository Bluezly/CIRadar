# CI Radar

CI Radar is a free, self-hosted, open-source CI failure intelligence platform. It keeps a deterministic, explainable diagnosis core and adds optional SSO, LLM explanations, multi-CI ingestion, test intelligence, ChatOps, DORA metrics, cost tracking, semantic similarity, and predictive test selection.

License: AGPL-3.0-or-later.

## Core capabilities

- GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins, Azure DevOps Pipelines, Bitrise, TeamCity, Travis CI, and AWS CodeBuild
- GitHub Checks and sticky GitHub PR comments
- Sticky GitLab merge request comments
- deterministic diagnosis rules, evidence weights, suggested actions, and feedback metrics
- PostgreSQL or portable embedded storage
- tenant isolation, API keys, RBAC, audit events, retention, encrypted secrets, OIDC, and SAML through a trusted auth proxy
- Slack, Teams, Discord, Telegram, email, PagerDuty, Opsgenie, and signed generic webhooks
- Slack buttons and Teams commands for acknowledge, resolve, and test quarantine
- JUnit, Playwright JSON, Jest JSON, pytest-json-report, Cypress JSON, and Mocha JSON
- flaky-test history, likely-cause classification, quarantine, and CI test gates
- DORA metrics, runner duration, estimated cost, and historical trends
- local vector similarity or optional BYOK remote embeddings
- predictive test selection from changed files and test history
- read-only MCP over stdio and Streamable HTTP
- optional BYOK OpenAI-compatible LLM enhancement over the deterministic result

## Quick start

```bash
ciradar init
ciradar analyze samples/npm-econnreset.log
ciradar serve
```

Open `http://127.0.0.1:8787/` and use the generated root token from `ciradar.json`.

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

## Native test reports

```bash
ciradar tests ingest --repo acme/api --format playwright playwright-report.json
ciradar tests ingest --repo acme/api --format jest jest-results.json
ciradar tests ingest --repo acme/api --format pytest report.json
ciradar tests ingest --repo acme/api --format cypress cypress-results.json
ciradar tests gate --repo acme/api --format junit junit.xml
```

## Predictive test selection

```bash
ciradar tests select --repo acme/api --changed src/payments.go,src/ledger.go
```

## DORA and cost

```bash
ciradar deployment record --repo acme/api --environment production --sha "$GIT_SHA"
ciradar metrics dora --days 30 --environment production
ciradar metrics usage --days 30
```

## Optional LLM

The LLM receives deterministic output, optional redacted excerpts, and optional changed file names. Raw logs and secrets are not sent by default.

```json
{
  "llm": {
    "enabled": true,
    "endpoint": "https://provider.example/v1/chat/completions",
    "api_key": "env:CIRADAR_LLM_API_KEY",
    "model": "your-model",
    "auto_enhance": false,
    "send_redacted_excerpt": true
  }
}
```

## SSO

Native OIDC uses Authorization Code with PKCE. SAML deployments use a trusted SAML-aware reverse proxy and signed identity headers. See `SSO.md`.

## Security defaults

- raw log storage disabled
- redaction before persistence and fingerprints
- tenant-scoped API and MCP access
- write-capable ChatOps disabled until explicitly enabled
- LLM and remote embeddings disabled by default
- test auto-quarantine disabled by default
- automatic CI retry disabled by default

Read `SECURITY.md`, `POSTGRESQL.md`, `CONNECTORS.md`, `TEST-INTELLIGENCE.md`, `MCP.md`, and `SELF-HOSTING.md` before production deployment.
