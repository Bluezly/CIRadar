# Limitations

CI Radar deliberately returns `UNKNOWN` when the available evidence does not support a diagnosis. The bundled benchmark data is a regression fixture, not a claim of real-world accuracy.

The PostgreSQL backend uses bound parameters, but `internal/pgwire` is maintained in this repository rather than provided by a third-party PostgreSQL driver. Deployments with strict interoperability or assurance requirements should review that boundary independently.

Native SAML delegates signature verification to a pinned `xmlsec1` executable. The surrounding SAML parsing and request handling are project code and should be tested against the identity provider used in the target environment.

Some PostgreSQL operations reuse the in-memory Store implementation by hydrating tenant-scoped rows before applying shared validation logic. High-volume installations should watch database latency, row counts, and process memory.

The automated test suite does not establish long-running production scale, replicated database failover, backup/restore behavior at production data volume, or compatibility with every identity provider.

Remote model and embedding features are optional. Redaction reduces exposure but cannot guarantee removal of every organization-specific secret format. Sensitive deployments should prefer local-only or metadata-only modes.
