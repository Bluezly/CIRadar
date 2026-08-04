# Security Notes — CI Radar Beta 5

## Implemented

- GitHub webhook HMAC-SHA256 verification.
- GitHub delivery deduplication.
- RSA GitHub App JWT and short-lived installation tokens.
- Secret redaction before fingerprinting and persistence.
- HMAC-based shared fingerprints when `fingerprint_hmac_key` is configured; `init` generates one automatically.
- Raw-log persistence disabled by default.
- API tokens stored as SHA-256 digests; plaintext is shown once.
- Viewer, operator, admin and root authorization.
- Tenant-scoped reads, writes, jobs, incidents, baselines and notifications.
- Installation-to-tenant binding required by default.
- Audit trail for privileged actions and automatic retries.
- HMAC signatures for generic outbound webhooks.
- Notification URL/token sanitization in error records.
- Per-channel retries, cooldown and atomic duplicate suppression.
- Separate high-volume rate-limit bucket for authenticated GitHub webhooks.
- Secure response headers and no-store caching.
- Config generated with owner-only file permissions where supported.

## Deployment requirements

- Put the server behind TLS; do not expose plain HTTP publicly.
- Store GitHub keys, webhook secrets, root tokens and notification credentials in a secret manager or environment variables.
- Restrict inbound GitHub webhook traffic where operationally possible.
- Back up the state file and test recovery.
- Rotate API keys and the root token periodically.
- Keep `store_raw_logs`, `cross_tenant_correlation`, `automatic_retry_enabled`, and `allow_unauthenticated_localhost` disabled until deliberately reviewed.
- Run the service as an unprivileged OS account.

## Not yet provided

- encrypted database columns at rest
- SAML/OIDC SSO and SCIM
- enterprise KMS integration
- formal SOC 2 / ISO 27001 controls
- PostgreSQL row-level security
- multi-region or multi-replica HA

The portable backend is for a single trusted host. Do not market Beta 5 as a certified enterprise SaaS platform.
