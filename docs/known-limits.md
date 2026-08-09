# Known limits

CI Radar is still a release candidate. These are the main boundaries to keep in mind when evaluating it.

## Diagnosis coverage

The built-in rules cover many common failure signatures, but not every tool or provider-specific error. `UNKNOWN` is an expected result when the evidence does not support a rule. The example benchmark dataset is a smoke fixture, not a public accuracy score.

## PostgreSQL

The PostgreSQL backend uses bound parameters, but `internal/pgwire` is a project-maintained wire client. It should receive independent protocol and security review before high-risk deployment.

Some storage operations intentionally hydrate selected tenant rows into the shared in-memory store so the embedded and PostgreSQL backends reuse the same validation logic. High-volume installations should watch row counts, query latency, and memory use.

## SAML

Native SAML delegates signature verification to a pinned `xmlsec1` executable, while the surrounding parsing and orchestration remain project-maintained. Test it against the IdP and policy used by the deployment.

## Production evidence

The repository does not establish sustained production scale, replicated PostgreSQL failover, backup/restore behavior under production data volume, or interoperability with every identity provider. Use [Production acceptance](production-acceptance.md) to record those checks in the target environment.

## Model-assisted features

Remote model use is optional. Redaction reduces exposure but cannot prove removal of every organization-specific secret format. Sensitive deployments should prefer local-only or metadata-only modes.
