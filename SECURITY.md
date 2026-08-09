# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a suspected security problem.

Use GitHub private vulnerability reporting when it is enabled for the repository. Otherwise contact the repository owner privately and include the affected version, reproduction steps, required privileges, and impact. Do not send production credentials or unredacted customer data.

## Supported version

Security fixes are made against the current release candidate. Older release candidates should be upgraded before a new report is evaluated.

## Deployment notes

CI Radar handles build logs, repository metadata, webhooks, credentials, and identity data. Public deployments should use HTTPS, separate secrets for each purpose, restricted provider credentials, and PostgreSQL access limited to the CI Radar service.

The default configuration leaves remote model use, automatic reruns, automatic quarantine, and repair automation disabled.

Two implementation areas remain explicit review boundaries:

- `internal/pgwire`, the project-maintained PostgreSQL wire client;
- native SAML parsing and orchestration around `xmlsec1` verification.

See [Self-hosting](docs/self-hosting.md), [PostgreSQL](docs/postgresql.md), [SSO](docs/sso.md), and [Known limits](docs/known-limits.md) for deployment details.
