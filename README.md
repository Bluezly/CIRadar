# CI Radar 1.0.0 RC.1

A single-binary Go platform for multi-CI failure diagnosis, cross-repository incident correlation, CI environment drift, test reliability, developer comments, enterprise notifications, and read-only MCP access.

## Included

- GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins adapter, and manual log ingestion.
- Explainable attribution: external, code, mixed, toolchain, unknown.
- GitHub Checks plus sticky GitHub PR and GitLab MR comments.
- Deterministic recommended actions and diagnosis feedback metrics.
- JUnit ingestion, per-test history, flake scoring, expiring quarantine, manifest, and `tests gate`.
- Slack, Discord, Telegram, signed webhook, SMTP email, Teams, PagerDuty, Opsgenie.
- Embedded store or transactional PostgreSQL 18 backend.
- Tenant isolation, RBAC API keys, audit log, encrypted/config-referenced secrets.
- Dashboard, REST API, Prometheus metrics, stdio and basic Streamable HTTP MCP.

Start with [README-AR.md](README-AR.md), [ARCHITECTURE.md](ARCHITECTURE.md), [CONNECTORS.md](CONNECTORS.md), [POSTGRESQL.md](POSTGRESQL.md), [TEST-INTELLIGENCE.md](TEST-INTELLIGENCE.md), and [MCP.md](MCP.md).

## Build

```bash
go test ./...
go test -race ./...
go vet ./...
make build VERSION=1.0.0-rc.1
```

No third-party Go modules and no CGO dependency.

## Release status

This is a serious private-beta release candidate, not a claim of finished hyperscale enterprise SaaS. The PostgreSQL compatibility backend is durable and multi-process safe, but still serializes state through one JSONB row. External providers and notifications were mock-tested because live credentials were unavailable during the build.
