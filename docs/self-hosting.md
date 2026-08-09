# Self-hosting

Production deployments should use PostgreSQL, HTTPS, encrypted secrets, SSO, restricted provider credentials, and at least one isolated worker.

```text
load balancer or reverse proxy
              |
      CI Radar replicas
              |
          PostgreSQL
```

## Production checklist

- set `public_base_url` to the HTTPS origin
- trust only exact load-balancer networks in `trusted_proxy_cidrs`
- use PostgreSQL `sslmode=verify-full` and the expected CA
- use environment references or encrypted configuration values for secrets
- generate `CIRADAR_MASTER_KEY` with `ciradar secret key`; do not use a human passphrase
- set a dedicated persistent `CIRADAR_DASHBOARD_SESSION_SECRET` on every replica
- enable OIDC or native SAML and secure cookies
- install `xmlsec1` on every replica when native SAML is enabled and pin the SHA-256 of the resolved executable with `saml_xmlsec_sha256`
- keep raw logs off unless retention and access policy are explicit
- configure analysis, audit, job, test, and delivery retention
- back up PostgreSQL and the exact source revision
- monitor `/readyz`, `/metrics`, queue age, database latency, and failed notifications
- set `source_url` to the corresponding AGPL source revision
- validate every enabled CI connector against a non-production repository
- leave `allow_private_network` false for public webhooks and providers; enable it only on the exact integration that must reach a trusted internal SMTP, Jenkins, TeamCity, OIDC, or webhook endpoint

The embedded backend is intended for evaluation and small single-process use.

## Outbound network policy

Notification webhooks, SMTP, CI connectors, provider-status polling, GitHub API, LLM/embedding endpoints, and OIDC discovery/token/JWKS requests reject private, loopback, link-local, metadata-service, multicast, unspecified, and other reserved address ranges by default. DNS answers and redirects are checked at request time. Secret-bearing and write requests refuse cross-origin redirects. Read-only CI log downloads may follow a public cross-origin redirect only after CI Radar removes authorization, cookie, webhook, and custom headers.

Set `allow_private_network: true` only inside the specific notification channel, connector, or SSO block that must reach a trusted internal service. This opt-in disables address-range blocking for that integration; it does not allow non-HTTP schemes or URL-embedded credentials. Guarded outbound HTTP clients deliberately ignore `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`; route them explicitly at the network layer when an egress proxy is mandatory.

## Secret migration

Generated 32-byte CI Radar master keys continue to decrypt existing `enc:v1:` values. A legacy human passphrase used directly as `CIRADAR_MASTER_KEY` is now rejected. Before upgrading such an installation, use the prior release to decrypt the values, generate a new key with `ciradar secret key`, and encrypt the plaintext values again.

Older configurations that relied on `admin_token`, `fingerprint_hmac_key`, or `master_key` as an implicit dashboard session key no longer do so. The service now refuses to load a configuration without a dedicated `dashboard_session_secret`; set the same persistent value on every replica before upgrading.

## Multi-platform binaries

Release builds include Windows, Linux, and macOS for amd64 and arm64. macOS binaries are cross-built without CGO; test them on the exact macOS and Apple Silicon versions used by the organization.

## Native SAML dependencies

The service account needs execute access to `xmlsec1`, read access to the pinned IdP certificate, and write access to the operating system temporary directory. Do not point `saml_xmlsec_path` at a wrapper controlled by untrusted users. Native SAML now requires `saml_xmlsec_sha256`; configuration resolves symlinks, validates the executable, and hashes it, and the SAML verification path checks the digest again immediately before execution.

```bash
sha256sum /usr/bin/xmlsec1
```

Copy only the 64-character digest into `saml_xmlsec_sha256`. Recompute and deliberately update the pin when `xmlsec1` is upgraded.

## Similarity deployment choices

- `lexical`: no model, deterministic hashing fallback
- `ollama`: local neural embeddings through an Ollama endpoint
- `local-vectors`: local word-vector file
- `remote`: configured embedding API

Keep the selected endpoint on a trusted network and treat repository and log text as untrusted input.

## Restricted outbound networks

Provider-status polling is independent of GitHub App configuration. In an environment that intentionally blocks public status endpoints, set `provider_polling` to `false` or `CIRADAR_PROVIDER_POLLING=false`. Persistent failures are summarized once and repeated identical failures are logged only at debug level; recovery is logged when connectivity returns.
