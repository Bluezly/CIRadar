# Security

## Safe defaults

- raw log storage off
- automatic retry off
- auto-quarantine off
- cross-tenant correlation off
- optional LLM off
- remote embeddings off
- ChatOps writes off
- MCP read-only
- unauthenticated API access off
- trusted proxy list empty
- PostgreSQL TLS defaults to certificate and hostname verification

## Reverse proxies and rate limits

`X-Forwarded-For` and `X-Real-IP` are ignored unless the direct peer is inside `trusted_proxy_cidrs`. Configure only the load balancers and reverse proxies you operate.

```json
{
  "trusted_proxy_cidrs": ["10.20.0.0/16", "2001:db8:1234::/48"]
}
```

CI Radar walks the forwarding chain from the trusted edge toward the original client. Untrusted clients cannot select their own rate-limit identity. Localhost bypass also uses the resolved client address, so a local reverse proxy does not make remote clients local administrators.

## Browser security

The dashboard is served with a restrictive Content Security Policy and contains no inline script, inline style, or inline event handlers. Browser token login exchanges the token for an AES-GCM encrypted, HttpOnly, SameSite=Strict session cookie. The token is not retained in Web Storage.

OIDC flow state and SSO identity sessions are also AES-GCM encrypted. Cookie-authenticated write requests require a same-origin `Origin` or `Referer`. HSTS is emitted when HTTPS is detected directly, through the configured public URL, or through a trusted proxy.

## Secrets and redaction

Environment references and AES-256-GCM encrypted configuration values are supported. API keys are stored as hashes. PostgreSQL indexes the hash for direct lookup instead of scanning and stopping at a matching key.

Redaction includes known token formats, authorization headers, credential URLs, private keys, sensitive environment variables, JWTs, and an optional high-entropy detector. Operators can add organization-specific regular expressions with `redaction_patterns`. Custom patterns and entropy detection reduce risk but cannot prove that every proprietary secret format is recognized. Keep raw-log storage and external LLM transmission disabled unless the data boundary is understood.

## Webhook verification

- GitHub and GitHub Marketplace HMAC-SHA256
- GitLab token or HMAC
- Buildkite token or timestamped HMAC
- CircleCI HMAC
- provider adapter token or HMAC for Jenkins, Azure DevOps, Bitrise, TeamCity, Travis CI, and CodeBuild
- Slack timestamped request signing
- Teams outgoing-webhook HMAC

Requests are size-limited and duplicate deliveries are suppressed.

## SSO

Native OIDC validates discovery metadata, issuer, audience, signature, expiration, not-before, nonce, and PKCE state. SAML uses a trusted authentication proxy. Identity headers are accepted only from configured proxy CIDRs and require a shared secret.

## LLM boundary

The deterministic analysis is the source of truth. Raw logs are not sent by the LLM layer. Redacted excerpts and changed filenames are separately configurable. Repository and log text are untrusted data. Generated patches are suggestions and are never automatically applied.

## Reporting vulnerabilities

Do not include customer logs, private keys, tokens, database URLs, or webhook URLs in public reports. Use the private security contact configured by the project operator.
