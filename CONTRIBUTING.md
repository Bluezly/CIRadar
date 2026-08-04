# Contributing to CI Radar

CI Radar accepts bug reports, connector fixtures, deterministic diagnosis rules, security improvements, documentation, and code changes.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

Keep the deterministic diagnosis core explainable. New rules need positive and negative fixtures. New connectors need signed-webhook tests, terminal-state tests, and log-fetch tests. New storage behavior must pass both the embedded backend contract and the PostgreSQL backend contract.

## Pull requests

Use focused commits. Describe the failure mode, security impact, test evidence, and any migration requirement. Do not include real access tokens, webhook URLs, private logs, or customer data.

## License

Contributions are accepted under AGPL-3.0-or-later.
