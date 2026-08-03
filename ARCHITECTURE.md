# Architecture

CI Radar is a single Go executable with modular internal packages:

1. HTTP server receives GitHub `workflow_run` webhooks.
2. HMAC verification and delivery de-duplication happen before enqueueing.
3. Background workers exchange a GitHub App JWT for an installation token.
4. Failed job logs are downloaded with the GitHub REST API.
5. The redactor removes common tokens, credentials, user paths, and private keys.
6. Rules classify the failure and extract provider/operation/error family.
7. Normalized, redacted data produces shared and tenant-private fingerprints.
8. The state store correlates occurrences across repositories and organizations.
9. Provider status and previous successful environment snapshots enrich evidence.
10. A neutral GitHub Check is published with evidence and a recommendation.

The embedded JSON state store is deliberately dependency-free for the first
portable build. Replace `internal/db` with PostgreSQL before high-volume SaaS use;
the rest of the program depends only on the Store method contract.
