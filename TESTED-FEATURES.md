# Tested features — 1.2.0 OSS RC.3

Automated tests cover:

- deterministic classification and contradictory evidence
- secret redaction and HMAC fingerprints
- tenant isolation, RBAC, API-key hashing and audit records
- embedded persistence and PostgreSQL protocol transactions
- GitHub App JWT, webhook verification, logs, Checks and sticky PR comments
- GitLab sticky MR notes
- webhook parsing for ten CI providers
- Slack, Teams, Discord, Telegram, email, PagerDuty, Opsgenie and generic webhooks
- notification routing, retries, cooldowns, quiet hours and deduplication
- Slack and Teams ChatOps authorization
- JUnit, Playwright, Jest, pytest, Cypress and Mocha ingestion
- flaky-cause inference, quarantine and CI gate behavior
- DORA, usage, cost and trends
- local similarity, optional remote embedding fallback and predictive test selection
- optional OpenAI-compatible LLM enhancement
- OIDC claim mapping and trusted proxy SSO
- read-only tenant-scoped MCP
- Windows and Linux static builds

Live credentials for third-party providers are not part of the automated suite. Protocol-compatible local servers are used for integration tests. A real PostgreSQL server should be included in the operator's deployment acceptance test.

## RC.3 hardening

- relational PostgreSQL object rows and independent queue
- legacy global-state migration
- tenant-scoped advisory locks
- indexed cross-repository correlation
- direct API-key hash lookup
- trusted-proxy rate limiting
- strict CSP without inline dashboard code
- encrypted dashboard and SSO cookies
- CSRF protection for cookie writes
- verified PostgreSQL TLS defaults
- custom and entropy-based redaction
- optional GitHub Marketplace metadata without feature gates
