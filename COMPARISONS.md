# CI Radar comparison guide

This page explains product positioning rather than claiming that one self-hosted service replaces every CI or observability product.

## Where CI Radar is strongest

- free AGPL self-hosting and auditable source
- deterministic attribution with visible evidence and contradictory signals
- fifteen CI providers normalized into one incident and test model
- PostgreSQL, SSO, test intelligence, DORA, cost, alerts, ChatOps, and MCP in one service
- optional Ollama, local vectors, remote embeddings, and BYOK LLM paths
- conservative automation with audit and human confirmation

## Category comparison

| Capability | CI Radar OSS | Managed CI observability | Flaky-test specialist | AI repair platform |
|---|---|---|---|---|
| Self-hosted source | core | varies | varies | varies |
| Deterministic diagnosis | core | often proprietary or mixed | test-focused | model-focused |
| Multi-CI ingestion | 15 providers | common | varies | varies |
| Test history and quarantine | included | often included | core specialty | varies |
| Coverage/import-aware test selection | included | often proprietary | varies | varies |
| Globally distributed event store | not claimed | common in mature SaaS | vendor-managed | vendor-managed |
| Neural local similarity | Ollama or local vectors | vendor-managed | varies | commonly hosted |
| Native OIDC and SAML | included | common | varies | common |
| Automatic source repair | bounded proposal and draft PR | varies | sometimes | core specialty |
| MCP writes | confirmed Operator actions | varies | varies | increasing |

## Honest limits

- the impact graph is static imports plus optional per-test coverage, not a complete dynamic call graph
- local neural similarity requires an Ollama embedding model or a supplied vector file; lexical hashing is labeled as fallback
- native SAML requires `xmlsec1` on the host and supports a strict assertion profile
- PostgreSQL is relational and tenant-scoped, but is not a globally distributed Datadog-scale event plane
- macOS and ARM binaries are cross-built in CI; operators should run platform acceptance tests
- project age, maintainer count, support history, and production scale must be evaluated from repository activity, not source claims
