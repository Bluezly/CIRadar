# Contributing

Bug fixes, diagnosis rules, connectors, tests, and documentation improvements are welcome.

For a large feature, schema change, authentication change, or new external integration, open an issue first. It is easier to review the design before a large patch exists.

## Development

```bash
make check
make test
make race
make vet
```

Release CI also runs Staticcheck, `govulncheck`, PostgreSQL integration tests, CodeQL, and cross-platform builds.

## Diagnosis rules

A new rule should include a positive fixture and at least one nearby negative case. Prefer signatures that belong to the tool or ecosystem instead of repository-specific strings.

## Security-sensitive changes

Changes to authentication, tenancy, ChatOps, SSO, outbound requests, secrets, repair, or MCP should include failure-path and abuse-case tests.

Do not put real credentials, customer logs, private repository names, SAML assertions, database URLs, or webhook secrets in tests or issues.

## Pull requests

Keep a pull request focused. Explain what changed, why it changed, and how it was tested. Call out configuration, API, database, or migration impact when there is any.

Contributions are accepted under AGPL-3.0-or-later.
