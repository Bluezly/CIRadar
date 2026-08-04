# Test Intelligence

## Identity

A test key is derived from tenant, repository, framework, suite, class, test name and parameters. This prevents unrelated tests with the same short name from sharing history.

## Flake score

The score combines pass/fail transition rate and failure balance. Classification requires history:

- `insufficient_history`
- `stable`
- `flaky`
- `consistently_failing`
- `mixed`

## Quarantine

Quarantine requires owner, reason and expiry. It is auditable and expires automatically. Auto-quarantine is disabled by default and capped at 30 days.

## CI enforcement

```bash
ciradar tests ingest --repo acme/api junit.xml
ciradar tests gate --repo acme/api junit.xml
```

`gate` returns failure when any failed/error test is not actively quarantined. It returns success when failures are all quarantined. CI Radar does not modify the underlying runner or test framework.

## API

```text
POST   /api/v1/tests/junit
GET    /api/v1/tests
GET    /api/v1/tests/quarantines
GET    /api/v1/tests/quarantine-manifest
POST   /api/v1/tests/{key}/quarantine
DELETE /api/v1/tests/{key}/quarantine
```
