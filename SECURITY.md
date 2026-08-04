# Security

## Defaults

- raw log storage off
- automatic retry off
- cross-tenant correlation off
- unauthenticated localhost API off
- test auto-quarantine off
- MCP read-only

## Secrets

Config supports environment references and AES-256-GCM ciphertext. API tokens are hashed. Reversible delivery secrets must be encrypted or supplied through environment variables. Delivery errors are redacted.

## Webhooks

- GitHub HMAC-SHA256
- GitLab token or HMAC signing token
- Buildkite token or timestamped HMAC with replay window
- CircleCI HMAC
- Jenkins custom token/HMAC adapter
- duplicate-delivery suppression and bounded bodies

## Tenant controls

API principal resolution occurs before data access. Root can choose a tenant explicitly; ordinary API keys remain locked to their tenant. Disabled tenants cannot authenticate or execute queued jobs.

## MCP

HTTP requires authentication and validates Origin to reduce DNS-rebinding risk. Tools are read-only. The implementation does not expose raw logs through MCP.

## Reporting vulnerabilities

Do not submit real customer logs, private keys, webhook URLs or access tokens in a public issue. Provide a minimized synthetic reproducer.
