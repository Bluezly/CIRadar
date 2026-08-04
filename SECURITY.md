# Security model

CI Radar is designed for self-hosting around sensitive CI metadata. Operators still own network isolation, identity policy, PostgreSQL hardening, secret rotation, backups, and provider permissions.

## Safe defaults

- raw-log persistence disabled
- external LLM disabled
- automatic rerun disabled
- repair and draft repair PR disabled
- automatic quarantine disabled
- cross-tenant correlation disabled
- MCP writes require Operator role and confirmation
- forwarded client headers ignored unless the direct proxy is trusted

## Browser security

The dashboard has a restrictive Content Security Policy with external same-origin assets and no inline event handlers. Browser token login exchanges the token for an AES-GCM encrypted HttpOnly, SameSite=Strict cookie. Cookie-authenticated writes require a same-origin `Origin` or `Referer`. HSTS is emitted when HTTPS is known.

## SSO

OIDC validates discovery metadata, issuer, audience, signature, expiration, not-before, nonce, and PKCE state.

Native SAML accepts a strict response profile and verifies XML signatures with a pinned IdP certificate through the configured `xmlsec1` executable. The executable path is operator-controlled; arguments are fixed; input uses temporary files; execution is time-limited. Encrypted assertions are not accepted.

Trusted proxy identity remains optional and is accepted only from configured CIDRs with a shared secret.

## Secrets and redaction

Environment references and AES-256-GCM encrypted configuration values are supported. API keys are stored as hashes. Redaction covers known tokens, authorization headers, credential URLs, private keys, sensitive variables, JWTs, custom organization patterns, and optional high-entropy values.

A denylist cannot guarantee discovery of every proprietary secret. Keep raw logs and external model transmission disabled until the data boundary is reviewed.

## Provider and webhook security

Webhook bodies are size-limited, signatures or configured secrets are verified, duplicate deliveries are suppressed, and connector HTTP requests stay inside provider-configured trust boundaries. Slack includes timestamp replay protection. GitHub Marketplace state is metadata only and never gates OSS features.

## MCP and automation

MCP OAuth tokens and API keys remain tenant-scoped. Stateful mutations require a prepared confirmation token bound to the actor, action, target, tenant, and expiry. Safe rerun is allowlisted and idempotent. Repair cannot execute arbitrary commands and cannot auto-merge.

## Reporting vulnerabilities

Do not place customer logs, keys, tokens, database URLs, SAML assertions, or webhook URLs in public reports. Use the project's private security contact.
