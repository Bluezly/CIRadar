# CI Radar documentation

The root [README](../README.md) is the shortest path to a working local instance. This directory contains operational and implementation detail that would otherwise make the repository landing page hard to scan.

## Run and operate

- [Self-hosting](self-hosting.md) — deployment layout, secrets, reverse proxies, upgrades, and runtime expectations.
- [Configuration](configuration.md) — important configuration groups and environment-variable behavior.
- [PostgreSQL](postgresql.md) — database mode, migrations, pooling, timeouts, and known protocol boundary.
- [SSO](sso.md) — OIDC, native SAML, trusted proxy identity, and recovery considerations.
- [Connectors](connectors.md) — CI provider ingestion and provider-specific behavior.
- [ChatOps](chatops.md) — Slack and Teams actions, authorization, replay handling, and tenant binding.
- [Production acceptance](production-acceptance.md) — checks that must be completed in the operator's own environment.

## Reliability and analysis

- [Architecture](architecture.md) — major packages and data flow.
- [Test intelligence](test-intelligence.md) — flaky-state tracking, quarantine, critical tests, and impact selection.
- [Benchmarking](benchmarking.md) — dataset format, metrics, reproducibility, and publication rules.
- [Testing](testing.md) — what the automated suite covers and what it does not prove.
- [DORA and CI cost](dora-and-costs.md) — deployment and CI usage metrics.

## Integrations and automation

- [MCP](mcp.md) — stdio/HTTP transport, OAuth, sessions, and confirmation-gated writes.
- [LLM integration](llm.md) — optional model-assisted explanation/repair paths and data policies.
- [GitHub Marketplace](github-marketplace.md) — optional installation/subscription metadata handling.

## Project

- [Governance](governance.md) — technical decision priorities and compatibility expectations.
- [Project status](project-status.md) — verified behavior and explicitly unproven production boundaries.
- [Changelog](../CHANGELOG.md) — release history.
- [Security policy](../SECURITY.md) — threat model and vulnerability reporting.
