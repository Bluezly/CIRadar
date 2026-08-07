# Tested features — 1.3.2 OSS RC.13

The automated suite verifies implementation behavior. It does not establish production scale or real-world diagnosis accuracy.

- deterministic classification and custom rules
- redaction, encoded-secret detection, and residual-risk checks
- benchmark loading, traversal limits, immutable digests, Wilson intervals, macro metrics, confusion matrices, split selection, thresholds, and analyzer-configuration digesting
- tenant isolation, RBAC, API keys, audit events, OAuth/OIDC, SAML replay and strict validation
- Extended Query Protocol parameter binding and guards against manual SQL-literal helpers in PostgreSQL storage code
- embedded-state atomic persistence, backup recovery, rollback, retention, and job leases
- PostgreSQL migrations, relational state, pooling, operation timeouts, distributed request/auth rate limiting, and optional live integration tests
- CI provider webhook ingestion, replay protection, source metadata, incident correlation, and retry handling
- notification delivery, deduplication, repair-PR notification events, ChatOps, and provider payload rendering
- GitHub Issues lifecycle, Checks, Pull Request comments, source retrieval, and resumable/idempotent draft repair Pull Requests
- LLM redaction gates, source-context limits, provider request formats, patch validation, and local/remote modes
- JUnit-family ingestion, test history, variants, flaky-state transitions, confidence intervals, quarantine, critical-test policy, and impact selection
- MCP stdio/HTTP sessions, OAuth/PKCE, SSE deadlines, resources, read tools, and confirmation-gated writes
- API fallback behavior, request-size limits, admission control, sanitized 5xx responses, CSP, and graceful shutdown
- build scripts and six cross-platform release targets

Provider behavior is tested with protocol-compatible local servers. Native SAML signature acceptance still requires the actual `xmlsec1` binary and a real IdP interoperability environment. PostgreSQL integration tests run in CI against a single PostgreSQL service but do not prove replication or failover. Cross-built macOS binaries require runtime acceptance on macOS.

`benchmarks/example` is deliberately synthetic. Its score is a harness regression check, not a product accuracy result.
