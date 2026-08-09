# Contributing to CI Radar

Contributions are welcome for bug fixes, deterministic diagnosis rules, connectors, tests, security hardening, documentation, and focused product improvements.

## Before you start

For large features, storage changes, authentication changes, or new external integrations, open an issue first so the design and compatibility impact can be reviewed before implementation.

Never include real customer logs, private repository names, credentials, webhook URLs, SAML assertions, database URLs, or access tokens in issues, fixtures, commits, or pull requests.

## Development setup

The module language level is Go 1.23. Release CI currently uses Go 1.26.5. Node and Python are used only for lightweight repository checks.

```bash
go test -count=1 ./...
go test -race ./...
go vet ./...
```

Before submitting a pull request, also run:

```bash
test -z "$(gofmt -l .)"
node --check internal/server/dashboard.js
python3 -m json.tool ciradar.example.json >/dev/null
```

CI runs Staticcheck 2026.1 and `govulncheck`. Run them locally when available.

## Change expectations

### Diagnosis rules

New deterministic rules need positive fixtures and nearby negative cases that prove the rule does not over-match. Prefer general ecosystem/tool signatures over repository-specific strings.

### Storage

Storage behavior must preserve tenant isolation and pass the embedded/PostgreSQL contract where both backends support the behavior. PostgreSQL values must remain parameterized.

### Security-sensitive code

Authentication, authorization, ChatOps, SSO, secret handling, outbound networking, repair, and MCP changes need explicit abuse-case tests and failure-path coverage.

### Source style

Keep changes small and readable. Preserve the repository's source style: there are no Go or JavaScript `//` comments in the checked-in source. Prefer clear names, small functions, tests, and documentation files over line comments.

## Pull requests

A good pull request explains:

- the problem being solved;
- the behavior before and after the change;
- security, tenancy, compatibility, and migration impact;
- the tests or fixtures that prove the behavior;
- documentation changes when user-visible behavior changes.

Keep unrelated cleanup out of functional changes when possible. Do not commit build outputs, local state, generated secrets, or private fixtures.

## License

Contributions are accepted under AGPL-3.0-or-later.
