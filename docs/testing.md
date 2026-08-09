# Testing

CI Radar uses unit, integration, race, fuzz, syntax, benchmark-harness, and cross-platform build checks. Tests establish implementation behavior; they do not establish production scale or real-world diagnosis accuracy.

## Local verification

```bash
go test -count=1 ./...
go test -race ./...
go vet ./...
```

If Staticcheck is installed:

```bash
staticcheck ./...
```

Additional repository checks include:

```bash
test -z "$(gofmt -l .)"
node --check internal/server/dashboard.js
python3 -m json.tool ciradar.example.json >/dev/null
```

## PostgreSQL integration

Set a disposable PostgreSQL DSN and run:

```bash
CIRADAR_TEST_POSTGRES_DSN='postgres://...' \
  go test -count=1 -run TestPostgresIntegration ./internal/db
```

CI runs these tests against a live single-node PostgreSQL service.

## Areas covered

- deterministic classification, custom rules, redaction, fingerprints, and runtime diagnostic memory;
- benchmark loading, limits, metrics, digests, split selection, and gates;
- tenant isolation, API keys, audit, OAuth/OIDC, Slack ChatOps binding, SAML validation, and replay state;
- PostgreSQL parameter binding, SCRAM state validation, migrations, jobs, rate limits, and retention;
- provider webhook ingestion, replay protection, incident correlation, and safe rerun handling;
- notification routing, retries, deduplication, quarantine events, and repair-PR events;
- GitHub Checks, issue lifecycle, pull-request comments, source retrieval, and draft repair pull requests;
- JUnit-family ingestion, test history, quarantine, critical tests, and impact selection;
- MCP transport, OAuth/PKCE, sessions, SSE, and confirmed writes;
- HTTP request limits, API fallbacks, error sanitization, CSP, and graceful shutdown.

## Explicit limits

A passing suite does not prove replicated failover, backup restoration, long-running production load, native behavior on every target OS, or interoperability with every identity provider. Those belong to deployment acceptance.
