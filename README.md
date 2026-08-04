# CI Radar 0.3.0 Beta 5

A portable, explainable CI failure-intelligence service for GitHub Actions, written entirely in Go.

Beta 5 adds real tenant isolation, RBAC API keys, audit history, repository ownership/routing, incident workflows, proactive environment-drift alerts, an embedded dashboard, and a storage backend contract for a future PostgreSQL implementation.

## Quick start

```bash
./ciradar init --config ciradar.json
./ciradar analyze --config ciradar.json samples/npm-econnreset.log
./ciradar serve --config ciradar.json
```

Open `http://127.0.0.1:8787/` and use the generated `admin_token`.

## Core capabilities

- GitHub App webhook ingestion and Check Runs
- secret redaction before storage/fingerprinting
- EXTERNAL / CODE / MIXED / TOOLCHAIN / UNKNOWN attribution
- positive and negative evidence scoring
- tenant-scoped cross-repository incidents
- successful-run environment baselines and drift alerts
- Slack, Discord, Telegram, signed generic webhooks
- notification filtering, cooldown, quiet hours, retry safety
- tenants, viewer/operator/admin API keys, audit log
- repository criticality and notification routing
- embedded dashboard and Prometheus-format metrics

Read [README-AR.md](README-AR.md) for complete setup instructions.

## Honest scope

The bundled JSON backend is a durable portable single-node implementation, not a multi-replica SaaS database. `db.Backend` now separates persistence from analysis, delivery, and HTTP layers so PostgreSQL can be added without rewriting the product core.
