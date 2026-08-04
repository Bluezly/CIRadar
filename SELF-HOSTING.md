# Self-hosting

Use PostgreSQL, TLS termination, encrypted secrets, a restricted service account, and a dedicated hostname for production.

```text
reverse proxy or SSO gateway
             |
     CI Radar replicas
             |
         PostgreSQL
```

## Production checklist

- configure `public_base_url` with HTTPS
- set `trusted_proxy_cidrs` to the exact proxy networks, not `0.0.0.0/0`
- enable secure dashboard and SSO cookies
- use PostgreSQL `sslmode=verify-full` with the expected CA
- provide secrets through environment references or encrypted values
- keep raw logs off unless a retention and access policy exists
- set retention limits for analyses, audits, deliveries, jobs, and test observations
- back up PostgreSQL and the exact source revision
- monitor `/readyz`, `/metrics`, queue age, notification failures, and database latency
- set `source_url` to the corresponding source for the deployed AGPL binary

The embedded backend is for evaluation and small single-process installations. PostgreSQL is required for multiple server and worker processes.

## Proxy example

```json
{
  "public_base_url": "https://ci-radar.example.com",
  "trusted_proxy_cidrs": ["10.30.0.0/16"],
  "dashboard_cookie_secure": true
}
```

Forward the original `Host` and `X-Forwarded-Proto`. Send `X-Forwarded-For` only from trusted infrastructure.

## Secrets

Store database, SSO, GitHub, webhook, SMTP, LLM, embedding, and incident-management secrets outside the repository. Rotate dashboard, SSO, API, and webhook keys under a documented procedure. Rotation of cookie encryption keys invalidates existing sessions, which is safer than accepting old sessions indefinitely.
