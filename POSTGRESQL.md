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

Supported authentication includes password, MD5 and SCRAM-SHA-256. TLS modes include certificate and hostname verification.

## Docker Compose

```bash
cp .env.example .env
cp ciradar.example.json ciradar.json
docker compose up --build
```

Replace every placeholder before exposing the service.

## Backup and restore

```bash
pg_dump --format=custom --file=ciradar.dump "$CIRADAR_DATABASE_URL"
pg_restore --clean --if-exists --dbname="$CIRADAR_DATABASE_URL" ciradar.dump
```

Back up the database, configuration, GitHub App private key, master encryption key and fingerprint HMAC key. Losing the master key makes encrypted configuration values unrecoverable. Changing the fingerprint key creates a new correlation namespace.

## RC.2 write model

RC.2 stores canonical state in one JSONB row protected by a transaction and row lock. Multiple processes cannot overwrite one another, but write throughput is serialized. This is an explicit compatibility design, not a claim of horizontally scalable analytics storage.
