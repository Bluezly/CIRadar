# Security model — CI Radar 0.2.0 Beta 4

- Raw CI logs are not stored by default.
- Redaction runs before fingerprinting, persistence, notifications, and GitHub Checks.
- Notification payloads contain structured analysis results, never the raw CI log.
- GitHub webhook signatures are verified with HMAC-SHA256 and duplicate deliveries are ignored.
- Generic outgoing webhooks can be signed with `X-CI-Radar-Signature-256`.
- Slack/Discord webhook URLs, Telegram bot tokens, and HMAC secrets are not returned by API status endpoints.
- HTTP transport errors are sanitized before persistence to avoid leaking secret webhook URLs.
- Each channel has independent delivery state, so retries do not duplicate channels that already succeeded.
- Administrative endpoints can be protected with `admin_token`.
- Automatic CI retries remain disabled by default.

Production recommendations:

1. Store `ciradar.json`, GitHub PEM, and bot/webhook credentials in a secret manager.
2. Run behind TLS and a reverse proxy.
3. Use a strong `admin_token` and firewall administrative endpoints.
4. Keep `store_raw_logs=false`.
5. Rotate webhook URLs and bot tokens after any suspected exposure.
6. Replace the embedded JSON store with PostgreSQL before multi-tenant SaaS use.
7. Add tenant isolation, RBAC, audit logs, encrypted backups, and outbound egress controls.
