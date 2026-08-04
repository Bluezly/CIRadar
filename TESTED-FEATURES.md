# Tested features — 1.3.2 OSS RC.6

Automated tests cover:

- deterministic classification, contrary evidence, redaction, and HMAC fingerprints
- tenant isolation, RBAC, API-key hashing, audit, encrypted browser and SSO sessions
- embedded persistence and relational PostgreSQL protocol behavior
- GitHub Checks, sticky PR comments, GitLab sticky MR notes, and GitHub Marketplace metadata
- webhook parsing for fifteen CI providers
- provider-scoped log retrieval and native safe-rerun request construction
- Slack, Teams, Discord, Telegram, email, PagerDuty, Opsgenie, and generic webhooks
- notification retries, cooldowns, quiet hours, deduplication, and ChatOps authorization
- JUnit, Playwright, Jest, pytest, Cypress, and Mocha ingestion
- flaky-cause inference, quarantine, gate behavior, impact graph indexing, and coverage-aware selection
- DORA, usage, cost, and historical trends
- lexical fallback, local vector files, Ollama embeddings, remote embeddings, and cache behavior
- optional LLM enhancement, bounded repair plans, and GitHub draft repair pull requests
- OIDC, native SAML flow and metadata, trusted proxy SSO, replay and binding checks
- MCP stdio, HTTP sessions, OAuth/PKCE, SSE notifications, resources, read tools, and confirmed write tools
- Windows, Linux, and macOS builds for amd64 and arm64

Third-party credentials are not present in the automated suite. Provider behavior is tested with protocol-compatible local servers. Native SAML signature tests use a controlled `xmlsec1` fixture; deployment acceptance must use the real binary and IdP. Cross-built macOS binaries require runtime acceptance on macOS.
