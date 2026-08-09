# CI Radar

[![CI](https://github.com/Bluezly/CIRadar/actions/workflows/ci.yml/badge.svg)](https://github.com/Bluezly/CIRadar/actions/workflows/ci.yml) [![CodeQL](https://github.com/Bluezly/CIRadar/actions/workflows/codeql.yml/badge.svg)](https://github.com/Bluezly/CIRadar/actions/workflows/codeql.yml)

CI Radar is a self-hosted service for diagnosing CI failures and tracking flaky tests across multiple CI systems.

It accepts build logs, webhooks, and JUnit-style reports, turns them into structured failure records, and keeps the results in an embedded store or PostgreSQL. The core diagnosis path is rule-based. Model-assisted explanations and repair suggestions are optional.

[Docs](docs/README.md) · [Arabic](README.ar.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Quick start

Clone and build:

```bash
git clone https://github.com/Bluezly/CIRadar.git
cd CIRadar
go build -o ciradar ./cmd/ciradar
```

Or install the CLI directly:

```bash
go install github.com/Bluezly/CIRadar/cmd/ciradar@latest
```

Try the analyzer without creating a config file:

```bash
./ciradar demo npm-econnreset
./ciradar rules
```

A demo result looks like this:

```text
Category         : DEPENDENCY_REGISTRY
Provider         : npm
Operation        : package-download
Summary          : npm package download connection was reset
Recommendation   : Avoid changing dependencies speculatively; verify npm/network health and retry after recovery.
```

Create a local instance:

```bash
./ciradar init
./ciradar serve
```

The dashboard listens on `http://127.0.0.1:8787/` by default. `ciradar init` prints the root token used for the first sign-in.

## What it does

- Classifies common CI failures with a built-in rule catalog and explicit `UNKNOWN` fallback.
- Correlates repeated failures across jobs and repositories.
- Ingests JUnit-family reports and keeps test history, flake state, quarantine state, and critical-test policy.
- Sends notifications and supports Slack/Teams actions.
- Integrates with GitHub and GitLab review workflows.
- Exposes a CLI, HTTP API, dashboard, and MCP server.
- Runs with an embedded state file or PostgreSQL.

The built-in catalog currently contains 630 rules. Custom rules can be loaded from configuration without rebuilding the binary.

## CI providers

GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins, Azure DevOps Pipelines, Bitrise, TeamCity, Travis CI, AWS CodeBuild, Bitbucket Pipelines, Drone, Semaphore, AppVeyor, and Google Cloud Build.

Provider support means CI Radar can normalize and analyze events from that provider. It does not imply that every provider-specific failure has a dedicated rule.

## Common commands

```bash
ciradar analyze build.log
ciradar baseline --repo owner/repo successful.log
ciradar incidents --json
ciradar status --json
ciradar tests ingest --repo owner/repo --format junit results.xml
ciradar tests list --repo owner/repo
ciradar tests select --repo owner/repo --changed src/a.go,src/b.go
ciradar database check
ciradar doctor
```

Run `ciradar help` for the full command list.

## Storage

| Mode | Use it for |
| --- | --- |
| Embedded | Local evaluation and small single-process installs |
| PostgreSQL | Shared state and multi-instance deployments |

PostgreSQL values are sent as bound parameters. CI Radar maintains its own PostgreSQL wire client, so deployments with strict security or interoperability requirements should review that boundary before production use. See [PostgreSQL](docs/postgresql.md).

## Docker

Initialize a configuration and copy the environment template:

```bash
ciradar init --config ciradar.json
cp .env.example .env
ciradar secret key
```

Set independent values for `CIRADAR_MASTER_KEY`, `POSTGRES_PASSWORD`, and `CIRADAR_DASHBOARD_SESSION_SECRET`, then start the stack:

```bash
docker compose up --build
```

For an internet-facing deployment, put CI Radar behind HTTPS and read [Self-hosting](docs/self-hosting.md) first.

## Optional model assistance

CI Radar can call a local or operator-configured model endpoint for explanations and repair proposals. It is disabled by default and is not required for classification. Data-handling options are documented in [Model integration](docs/llm.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Self-hosting](docs/self-hosting.md)
- [Connectors](docs/connectors.md)
- [Test intelligence](docs/test-intelligence.md)
- [ChatOps](docs/chatops.md)
- [PostgreSQL](docs/postgresql.md)
- [SSO](docs/sso.md)
- [MCP](docs/mcp.md)
- [Benchmarking](docs/benchmarking.md)
- [Known limits](docs/known-limits.md)

## Development

```bash
make check
make test
make race
make vet
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Status

CI Radar is a release candidate. The automated test suite covers the supported code paths, but it is not a substitute for load, failover, backup/restore, or identity-provider testing in your own environment. See [Known limits](docs/known-limits.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
