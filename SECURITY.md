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

## Secrets

Environment references and AES-256-GCM encrypted values are supported. API keys are stored as hashes. Reversible delivery and provider secrets should be supplied through environment variables or encrypted configuration. Transport errors are redacted before persistence.

## Webhook verification

- GitHub HMAC-SHA256
- GitLab token or HMAC
- Buildkite token or timestamped HMAC
- CircleCI HMAC
- provider adapter token or HMAC for Jenkins, Azure DevOps, Bitrise, TeamCity, Travis CI and CodeBuild
- Slack timestamped request signing
- Teams outgoing-webhook HMAC

Requests are size-limited and duplicate deliveries are suppressed.

## SSO

Native OIDC validates discovery metadata, issuer, audience, signature, expiration, nonce and PKCE state. SAML uses a trusted authentication proxy. Identity headers are accepted only from configured proxy CIDRs and require a shared secret.

## LLM boundary

The deterministic analysis is the source of truth. Raw logs are never sent by the LLM layer. Redacted excerpts and changed filenames are separately configurable. Repository and log text are treated as untrusted data. Generated patches are suggestions and are not automatically applied.

## Reporting vulnerabilities

Do not include customer logs, private keys, tokens or webhook URLs in public reports. Use the private security contact configured by the project operator.
