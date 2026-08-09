# Contributing

Bug fixes, diagnosis rules, connectors, tests, and documentation improvements are welcome.

For a large feature, schema change, authentication change, or new external integration, open an issue before starting the implementation.

## Development

```bash
make check
make test
make race
make vet
```

CI also runs Staticcheck, `govulncheck`, PostgreSQL integration tests, CodeQL, and cross-platform builds.

## Diagnosis rules

Add a positive fixture and at least one nearby negative case with every new rule. Prefer signatures from the tool or ecosystem itself instead of repository-specific text.

## Security-sensitive changes

Changes to authentication, tenancy, ChatOps, SSO, outbound requests, secrets, repair, or MCP should include failure-path and abuse-case tests.

Do not put real credentials, customer logs, private repository names, SAML assertions, database URLs, or webhook secrets in tests or issues.

## Pull requests

Keep each pull request focused. Explain the problem, the change, and how it was tested. Call out API, configuration, database, or migration impact when relevant.

Contributions are accepted under AGPL-3.0-or-later.
