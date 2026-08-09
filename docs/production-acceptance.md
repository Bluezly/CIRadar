# Production acceptance evidence

CI Radar release verification proves repository behavior in the environments that were actually exercised. It is not a substitute for deployment-specific production evidence.

## Automated preflight

Run against a disposable PostgreSQL database that matches the production major version and TLS policy:

```bash
export CIRADAR_TEST_POSTGRES_DSN='postgres://...'
./scripts/production-preflight.sh
```

The script runs the live PostgreSQL integration suite, PostgreSQL protocol/SAML security regressions, ChatOps/notification regressions, and an uncached full test suite. A pass is necessary evidence, not production certification.

## Evidence that must be recorded per deployment

| Exercise | Minimum evidence | Pass criterion |
| --- | --- | --- |
| Representative load | workload shape, concurrency, duration, row counts, p50/p95/p99 latency, queue age, CPU/RAM, DB I/O | agreed SLOs met without unbounded queue or memory growth |
| Backup and restore | backup command/version, artifact checksum, isolated restore log, integrity check | restored service reaches ready state and sampled records match |
| Replication/failover | topology, injected failure time, client errors, reconnect time, RPO/RTO | observed RPO/RTO within deployment targets |
| Migration rehearsal | source schema/version, copied dataset size, migration duration, rollback point | forward migration and documented rollback both succeed |
| Native SAML | IdP/vendor/version, pinned `xmlsec1` digest, login/logout/replay/expiry results | real IdP flow succeeds and negative cases fail closed |
| Platform binaries | OS/architecture/version and smoke-test log | native startup, `doctor`, analysis, serve, and clean shutdown succeed |

## PostgreSQL tenant-state hydration

Some PostgreSQL operations intentionally hydrate selected entity rows into the shared in-memory `Store` implementation so embedded and PostgreSQL behavior use the same validation and calculation logic. RC.16 narrows quarantine set/remove operations to the single target test-statistics row and single target quarantine row instead of loading every test/quarantine row for the tenant.

Other tenant-scoped operations may still hydrate bounded sets. Large installations should measure these paths with production-like row counts and retention settings rather than inferring capacity from unit tests.

## What a release may claim

A release may state only the evidence actually run and recorded. Do not convert synthetic benchmark results, local tests, or a single-node PostgreSQL run into claims of production-scale reliability, failover readiness, or real-world diagnosis accuracy.
