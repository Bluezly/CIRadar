# CI Radar

[![CI](https://github.com/Bluezly/CIRadar/actions/workflows/ci.yml/badge.svg)](https://github.com/Bluezly/CIRadar/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Bluezly/CIRadar/actions/workflows/codeql.yml/badge.svg)](https://github.com/Bluezly/CIRadar/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

CI Radar is a self-hosted service for turning CI failures into structured diagnoses. It ingests build events and test reports, groups recurring failures, tracks flaky tests, and exposes the result through a CLI, API, dashboard, alerts, and ChatOps.

The diagnosis engine is deterministic by default. Optional model-backed explanations and repair proposals can be enabled separately.

## Quick start

```bash
git clone https://github.com/Bluezly/CIRadar.git
cd CIRadar
go build -o ciradar ./cmd/ciradar
./ciradar demo npm-econnreset
```

Create a local configuration and start the server:

```bash
./ciradar init
./ciradar serve
```

The dashboard listens on `127.0.0.1:8787` by default. `ciradar init` prints the bootstrap token used for the first sign-in.

You can also install the CLI directly:

```bash
go install github.com/Bluezly/CIRadar/cmd/ciradar@latest
```

## What it handles

- CI failure classification with an explicit `UNKNOWN` fallback
- recurring incident correlation across jobs and repositories
- JUnit, Playwright, Jest, pytest, Cypress, and Mocha test-result ingestion
- flaky-test history, quarantine, critical-test policy, and impact-aware test selection
- GitHub and GitLab workflow actions
- Slack and Microsoft Teams ChatOps
- notifications, DORA metrics, and CI cost tracking
- embedded storage for local use or PostgreSQL for shared deployments
- optional OIDC, SAML, MCP, embeddings, and model-assisted explanations

CI events can be normalized from GitHub Actions, GitLab CI, Buildkite, CircleCI, Jenkins, Azure DevOps, Bitrise, TeamCity, Travis CI, AWS CodeBuild, Bitbucket Pipelines, Drone, Semaphore, AppVeyor, and Google Cloud Build.

## CLI

```bash
ciradar analyze build.log
ciradar baseline --repo owner/repo successful.log
ciradar incidents --json
ciradar tests ingest --repo owner/repo --format junit results.xml
ciradar tests list --repo owner/repo
ciradar tests select --repo owner/repo --changed src/a.go,src/b.go
ciradar database check
ciradar doctor
```

Run `ciradar help` for the complete command list.

## Docker

Copy the environment template, generate the required secrets, and create a config:

```bash
cp .env.example .env
./ciradar secret key
./ciradar init --config ciradar.json
```

Set the values in `.env`, then start the stack:

```bash
docker compose up --build
```

For an internet-facing deployment, put CI Radar behind HTTPS and use PostgreSQL. See [Deployment](docs/self-hosting.md) and [PostgreSQL](docs/postgresql.md).

## Documentation

- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Connectors](docs/connectors.md)
- [Test intelligence](docs/test-intelligence.md)
- [ChatOps](docs/chatops.md)
- [PostgreSQL](docs/postgresql.md)
- [SSO](docs/sso.md)
- [MCP](docs/mcp.md)
- [Model assistance](docs/model-assistance.md)
- [Benchmarking](docs/benchmarking.md)
- [Testing](docs/testing.md)
- [Limitations](docs/limitations.md)
- [Development history](docs/history.md)

## Development

```bash
make check
make test
make race
make vet
```

Pull requests run the same core checks in GitHub Actions, plus PostgreSQL integration, static analysis, vulnerability scanning, and cross-platform builds. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

CI Radar is licensed under AGPL-3.0-or-later. See [LICENSE](LICENSE).
