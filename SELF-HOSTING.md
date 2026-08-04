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
- enable OIDC or native SAML and secure cookies
- install `xmlsec1` on every replica when native SAML is enabled
- keep raw logs off unless retention and access policy are explicit
- configure analysis, audit, job, test, and delivery retention
- back up PostgreSQL and the exact source revision
- monitor `/readyz`, `/metrics`, queue age, database latency, and failed notifications
- set `source_url` to the corresponding AGPL source revision
- validate every enabled CI connector against a non-production repository

The embedded backend is intended for evaluation and small single-process use.

## Multi-platform binaries

Release builds include Windows, Linux, and macOS for amd64 and arm64. macOS binaries are cross-built without CGO; test them on the exact macOS and Apple Silicon versions used by the organization.

## Native SAML dependencies

The service account needs execute access to `xmlsec1`, read access to the pinned IdP certificate, and write access to the operating system temporary directory. Do not point `saml_xmlsec_path` at a wrapper controlled by untrusted users.

## Similarity deployment choices

- `lexical`: no model, deterministic hashing fallback
- `ollama`: local neural embeddings through an Ollama endpoint
- `local-vectors`: local word-vector file
- `remote`: configured embedding API

Keep the selected endpoint on a trusted network and treat repository and log text as untrusted input.
