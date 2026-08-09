# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a suspected security problem.

Use GitHub private vulnerability reporting when it is available. Otherwise contact the repository owner privately with the affected revision or version, reproduction steps, required privileges, and expected impact. Do not send production credentials or unredacted customer data.

## Supported code

Security fixes target the current `main` branch and the latest tagged release.

## Deployment notes

CI Radar handles build logs, repository metadata, webhooks, credentials, and identity data. Internet-facing deployments should use HTTPS, separate secrets for each purpose, restricted provider credentials, and PostgreSQL access limited to the service.

Remote model use, automatic reruns, automatic quarantine, and repair automation are disabled by default.

Two implementation areas deserve particular review in higher-assurance deployments:

- `internal/pgwire`, the repository-maintained PostgreSQL wire client
- native SAML parsing and orchestration around `xmlsec1` verification

See [Deployment](docs/self-hosting.md), [PostgreSQL](docs/postgresql.md), [SSO](docs/sso.md), and [Limitations](docs/limitations.md).
