# Tested Features — CI Radar 0.3.0 Beta 5

Automated tests cover:

- built-in and custom classification rules
- code/external/mixed/toolchain attribution
- positive and negative evidence scoring
- redaction and non-persistence of raw logs
- environment extraction and drift for OS, image, architecture, tools, Actions and containers
- tenant correlation isolation and optional cross-tenant correlation
- API key hashing, roles and revocation
- disabled-tenant queue isolation
- repository and criticality validation
- notification routing, quiet hours, HMAC, retries, 429s and atomic deduplication
- repository criticality severity escalation
- API tenant isolation and RBAC
- root tenant selection
- incident acknowledge/resolve audit trail
- separate API and webhook rate-limit buckets
- GitHub JWT, installation token, jobs, logs, prior-success lookup and Check Run flow
- worker end-to-end GitHub failure processing under the correct tenant
- critical repository incident escalation
- successful-run environment-change notification generation
- state backup/recovery and cleanup

Release verification commands:

```text
go test ./...
go test -race ./...
go vet ./...
```

Also verified during packaging:

- Windows amd64 cross-build
- Linux amd64 static build
- CLI smoke classifications
- config initialization and generated root token
- dashboard/API authentication
- tenant and API-key CLI flows
- source ZIP extraction, retest and rebuild
