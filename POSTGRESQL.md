# PostgreSQL deployment

CI Radar includes a pure-Go PostgreSQL wire client and requires no CGO or external driver file.

## Configuration

```json
{
  "database_driver": "postgres",
  "database_url": "env:CIRADAR_DATABASE_URL"
}
```

```bash
ciradar database check --config ciradar.json
ciradar database migrate --config ciradar.json
ciradar serve --config ciradar.json
```

## TLS

The default mode is `verify-full`. It verifies the certificate chain and the database hostname.

Recommended production DSN:

```text
postgres://ciradar:password@db.internal:5432/ciradar?sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem
```

Supported modes:

- `verify-full`: encryption, CA verification, and hostname verification
- `verify-ca`: encryption and CA verification without hostname verification
- `require`, `prefer`, and `allow`: when TLS is negotiated, the certificate and hostname are verified
- `insecure-require`: encryption without certificate verification; intended only for controlled local testing
- `disable`: plaintext; intended only for isolated local testing

Authentication supports password, MD5, and SCRAM-SHA-256.

## Current relational storage model

CI Radar no longer stores the installation in one global JSONB row.

It uses:

- `ciradar_objects`: one row per tenant entity, with indexed tenant, kind, event time, repository, fingerprint, state, status, and deduplication metadata
- `ciradar_jobs`: an independent queue using row locks and `SKIP LOCKED`
- `ciradar_webhook_deliveries`: independent webhook idempotency records
- `ciradar_schema_migrations`: schema history

Writes acquire advisory locks for the affected tenant and entity kind. A write for one tenant does not lock every other tenant. Cross-tenant correlation uses indexed SQL aggregation instead of loading all analyses into a global state blob.

The backend automatically imports the legacy `ciradar_state` row when the relational tables are empty. The legacy table is retained for rollback and should be removed only after backup and verification.

This is a scalable self-hosted entity store, not a claim of hyperscale distributed analytics. Some dashboard and business operations still hydrate a bounded tenant-scoped set of rows in the Go process. Very large installations should monitor query latency, retention, and row counts and may evolve high-volume analyses into partitioned tables.

## Indexes and maintenance

The migration creates indexes for:

- tenant and entity kind by event time
- fingerprints by event time
- repository history
- status and state queries
- notification and extension deduplication
- queue claiming and tenant queue status

Use normal PostgreSQL maintenance, autovacuum, backups, connection limits, and storage monitoring. Apply retention policies so analysis and test-observation history do not grow without bound.

## Backup and restore

```bash
pg_dump --format=custom --file=ciradar.dump "$CIRADAR_DATABASE_URL"
pg_restore --clean --if-exists --dbname="$CIRADAR_DATABASE_URL" ciradar.dump
```

Back up the database, configuration, GitHub App private key, master encryption key, dashboard and SSO session keys, and fingerprint HMAC key. Losing encryption keys makes encrypted configuration values unrecoverable. Changing the fingerprint key starts a new correlation namespace.

## Test telemetry partitions and idempotency

`ciradar_test_observations` is range-partitioned by month and has tenant/repository/time, tenant/test/time, status/time, and BRIN time indexes. Startup and cleanup maintain nearby monthly partitions, while a default partition protects ingestion outside the prepared window. Observation IDs are idempotency keys: duplicate deliveries are filtered before compact test statistics are updated, so a retried webhook cannot inflate flake confidence or time-lost estimates.

PostgreSQL remains the transactional system of record, not an unlimited log warehouse. Keep raw build logs in object storage or the CI provider and retain compact CIRadar telemetry. At sustained high ingest or long analytical retention, export observations to a columnar/time-series system such as ClickHouse or TimescaleDB rather than forcing all exploratory log analytics through the primary OLTP database.

## Production readiness checklist

Before calling a deployment production-ready, operators should complete and record:

1. a representative load test covering expected test-result and analysis ingest, dashboard reads, cleanup, and concurrent workers
2. automated `pg_dump`/physical backup plus a restore drill into an isolated database
3. replication/failover testing, including client reconnect behavior and recovery-point/recovery-time objectives
4. migration rehearsal on a copy of production data and a documented rollback point
5. autovacuum, WAL, connection, disk-I/O, partition growth, default-partition growth, and query-latency alerts
6. retention sizing and deletion/partition-drop verification

The repository does not claim that these operator-specific exercises have been completed for an arbitrary installation. Passing unit and integration tests is not a substitute for them.
