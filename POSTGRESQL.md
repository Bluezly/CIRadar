# PostgreSQL deployment

CI Radar includes a pure-Go PostgreSQL wire client, so the distributed binary needs no CGO and no external driver files.

## Supported connection properties

- `postgres://` DSN
- TLS modes including verify-full
- password, MD5, and SCRAM-SHA-256 authentication
- transactions and row locks

## Docker Compose

The bundled Compose file uses PostgreSQL 18.4 and mounts `/var/lib/postgresql`, matching the official PostgreSQL 18 image layout.

```bash
cp .env.example .env
docker compose up --build
```

## Backup

```bash
pg_dump --format=custom --file=ciradar.dump "$CIRADAR_DATABASE_URL"
pg_restore --clean --if-exists --dbname="$CIRADAR_DATABASE_URL" ciradar.dump
```

Keep backups of:

- PostgreSQL database
- `ciradar.json`
- GitHub App private key
- `CIRADAR_MASTER_KEY`
- fingerprint HMAC key

Losing the master key makes encrypted config values unrecoverable. Changing the fingerprint key starts a new fingerprint namespace.

## Current RC limitation

The compatibility backend stores the canonical application state in one transactionally locked JSONB row. This is correct under multiple processes and supports standard PostgreSQL durability/backup, but write throughput is serialized. It is appropriate for a private beta and moderate installations, not a claim of high-write hyperscale.
