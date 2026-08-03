# CI Radar 0.2.0 Beta 4

A dependency-free Go executable that diagnoses GitHub Actions failures, redacts secrets, fingerprints and correlates failures, detects environment drift, publishes GitHub Checks, and alerts Slack, Discord, Telegram, or any generic webhook endpoint.

## Quick start

```bash
ciradar init --config ciradar.json
ciradar analyze samples/npm-econnreset.log
ciradar serve --config ciradar.json
```

Notification commands:

```bash
ciradar notify test --config ciradar.json --channel slack-ops
ciradar notify list --config ciradar.json
```

Notification features include per-channel filters, minimum scores, repository globs, external-only mode, incident severity filters, cooldown deduplication, independent delivery state, retries, HTTP 429 handling, and optional HMAC-SHA256 signing for generic webhooks.

See `README-AR.md` for the full setup guide and `SECURITY.md` before exposing the service publicly.
