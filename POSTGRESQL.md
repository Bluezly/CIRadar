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

## RC.3 storage model

RC.3 no longer stores the installation in one global JSONB row.

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
