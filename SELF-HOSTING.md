# Self-hosting

Use PostgreSQL, TLS termination, encrypted secrets, a restricted service account, and a dedicated hostname for production.

Recommended topology:

```text
reverse proxy / SSO gateway
        |
CI Radar server and workers
        |
PostgreSQL
```

Keep webhook endpoints reachable only from the required providers when possible. Store database, SSO, webhook, LLM, SMTP, and incident-management secrets as environment references or AES-GCM encrypted values.

Back up PostgreSQL and the exact source revision. Set `source_url` to the corresponding source for the deployed binary.

The embedded backend is intended for local evaluation and small single-node installations. PostgreSQL is required for multiple server instances.
