# Security Policy

CI Radar handles CI metadata, logs, repository context, credentials, webhooks, and identity data. Treat every deployment as security-sensitive.

## Supported versions

| Version | Security updates |
| --- | --- |
| 1.3.2-oss-rc.15 | Yes |
| Earlier release candidates | Upgrade before reporting a newly discovered issue |

CI Radar is still a release candidate. Security fixes may require configuration or schema changes before a stable compatibility policy is established.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting for this repository when available. If private reporting is unavailable, contact the repository maintainers privately through the repository owner or organization.

Include only the minimum information needed to reproduce the issue. Do not send real customer logs, access tokens, private keys, database URLs, SAML assertions, webhook secrets, or production credentials.

A useful report includes:

- affected version and deployment mode;
- attack preconditions and required privileges;
- reproduction steps or a minimal proof of concept;
- expected and actual security boundary;
- impact assessment;
- suggested fix, if known.

No public response-time SLA is promised. Please allow maintainers time to reproduce and coordinate a fix before disclosure.

## Safe defaults

The default configuration is intentionally conservative:

- raw-log persistence is disabled;
- external LLM use is disabled;
- automatic rerun is disabled;
- automatic repair and draft repair pull requests are disabled;
- automatic quarantine is disabled;
- cross-tenant correlation is disabled;
- MCP writes require Operator authorization and explicit confirmation;
- forwarded client identity is ignored unless the direct proxy is trusted;
- outbound integration targets reject private, loopback, link-local, metadata-service, and other non-public addresses unless that integration explicitly allows private networking.

## Tenant isolation and authorization

Tenant identity is derived from authenticated context rather than ordinary request payloads. API keys, OAuth tokens, browser sessions, storage operations, audit records, and state-changing actions are tenant-scoped.

Slack ChatOps binds the verified Slack Team ID to a tenant before executing an action. A signed button payload cannot switch the target tenant independently of the verified workspace identity.

State-changing MCP operations require an Operator role and a short-lived confirmation token bound to actor, tenant, action, and target.

## Browser security

The dashboard uses a restrictive Content Security Policy and same-origin assets. Browser token login exchanges credentials for an encrypted HttpOnly, SameSite=Strict session cookie. Cookie-authenticated writes require a same-origin `Origin` or `Referer`. HSTS is emitted when HTTPS is known.

Unknown API paths return JSON 404 responses rather than dashboard HTML.

## Authentication throttling

General request limiting is supplemented by failure-aware authentication throttling. Repeated bearer-token and token-exchange failures are tracked separately and can trigger exponential blocking.

With PostgreSQL storage, distributed rate-limit and authentication-failure state is shared between instances. Protected paths fail closed when shared limiter state cannot be checked.

## SSO

OIDC validates issuer identity, audience, authorized party, signature, expiration, not-before, nonce, stable subject, JWK properties, and PKCE state. Login return paths are constrained to local application paths.

Native SAML uses a strict response profile. XML signatures are verified through an operator-configured `xmlsec1` executable whose resolved file is SHA-256 pinned and rechecked immediately before use. The parser validates response/assertion shape, same-document signature references, SHA-2 algorithms, issuer, destination, audience, request binding, recipient, time conditions, and replay state. Encrypted assertions are not accepted.

The SAML parser/orchestration remains project-maintained and is an explicit independent-review boundary.

## PostgreSQL protocol boundary

Application values are sent as Extended Query Protocol parameters and are not interpolated into SQL text. SCRAM message sizes, attributes, and authentication state transitions are bounded and validated.

`internal/pgwire` is still a project-maintained PostgreSQL wire implementation. It should receive independent protocol and security review before high-risk production use. Parameterized values reduce SQL injection risk but do not prove complete protocol correctness.

## Secrets and redaction

Environment references and AES-256-GCM encrypted configuration values are supported. API keys are stored as hashes.

Redaction covers known provider tokens, authorization headers, credential URLs, private keys, JWTs, sensitive variables, custom organization patterns, and optional high-entropy values. Redaction is defense in depth and cannot prove removal of every organization-specific secret format.

For sensitive repositories, prefer local-only or metadata-only model/similarity modes. Remote source-code transmission requires explicit opt-in.

`CIRADAR_MASTER_KEY` must be the 32-byte base64url value generated by `ciradar secret key`. It is not a human passphrase.

## Outbound network policy

Notifications, connectors, provider-status checks, GitHub API access, OIDC discovery, model endpoints, and embedding endpoints enforce network destination policy. Private-network access must be explicitly enabled per integration when an internal destination is intentional.

Do not enable private-network access for untrusted or user-controlled destinations.

## Repair and automation

Safe rerun is allowlisted and idempotent. Repair operates on bounded patch plans, validates patch application, requires explicit enablement, and does not auto-merge. Draft repair pull requests use deterministic branch state and resume checks.

Automatic quarantine is opt-in, cannot automatically quarantine critical tests, and emits a dedicated notification only after persistence succeeds.

## Release integrity

Release builds are reproducible with fixed version, commit, and build timestamp inputs. The GitHub release workflow publishes `SHA256SUMS` and build-provenance attestations beside release assets.

Checksums detect corruption or substitution only when the checksum file itself is trusted. Deployments that require stronger provenance should sign release metadata with an organization-controlled identity.

## Production responsibility

Operators remain responsible for network isolation, TLS termination, PostgreSQL hardening, secret rotation, provider permissions, backup/restore, disaster recovery, SSO recovery, logging, and capacity planning.

See [Production acceptance](docs/production-acceptance.md) before approving a production deployment.
