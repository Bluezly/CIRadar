# CI Radar Beta 5 Architecture

## Runtime flow

```text
GitHub workflow_run webhook
  -> HMAC validation + delivery deduplication
  -> installation-to-tenant resolution
  -> durable tenant job queue
  -> GitHub installation token
  -> job/log retrieval
  -> redaction
  -> rules + change/history/provider/environment evidence
  -> attribution + fingerprint
  -> tenant-scoped persistence
  -> incident correlation
  -> GitHub Check
  -> routed notifications
```

Successful runs follow a second path:

```text
successful job log
  -> environment extraction
  -> compare with prior successful baseline
  -> store new baseline
  -> environment_changed notification when runner/tool/action/container drift is detected
```

## Packages

- `internal/analyzer`: redaction, rule matching, evidence scoring, attribution, fingerprints, environment extraction.
- `internal/github`: GitHub App JWT, installation tokens, logs, run history, PR files, Checks, reruns.
- `internal/db`: portable atomic JSON backend and the `Backend` persistence contract.
- `internal/worker`: tenant-aware durable job processing.
- `internal/notifications`: routing, filtering, quiet hours, cooldown, retries, HMAC webhook signing.
- `internal/server`: authenticated API, dashboard, webhook endpoint, RBAC, audit actions, rate limits.
- `internal/providers`: provider status polling.

## Isolation model

Every analysis, environment baseline, job, incident, notification delivery, API key, repository profile, and audit event carries a tenant ID. GitHub installation IDs are explicitly bound to one tenant. API keys cannot select another tenant. Only the root bootstrap token can select an enabled tenant with `X-CI-Radar-Tenant`.

Cross-tenant fingerprint correlation is disabled by default and requires a configured HMAC key. Cross-repository correlation inside one tenant is always enabled because it is the core incident-detection feature.

## Persistence

The bundled backend writes an atomic snapshot, fsyncs it, and keeps a backup for recovery. It is designed for portable single-node testing and smaller installations.

The runtime layers depend on `db.Backend`, not the concrete JSON store. A future PostgreSQL backend should implement the same contract and provide transactional job claims, indexes, row-level tenant constraints, connection pooling, and HA deployment.

## Safety decisions

- Raw logs are not persisted by default.
- Auto-retry is off by default and only eligible for external attribution, supported transient categories, no active provider incident, a score threshold, and the first run attempt.
- Deterministic code/dependency/workflow changes subtract evidence rather than merely failing to add positive evidence.
- Toolchain internal crashes are not labeled as source-code failures.
- Unknown evidence produces UNKNOWN rather than a fabricated diagnosis.
