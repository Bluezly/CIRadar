# Architecture — CI Radar 0.2.0 Beta 4

CI Radar is a modular monolith compiled into one Go executable.

1. The HTTP server receives verified GitHub `workflow_run` webhooks.
2. Background workers exchange a GitHub App JWT for installation tokens.
3. Failed job logs are downloaded, bounded by `max_log_bytes`, and redacted.
4. The analyzer classifies failures and extracts environment metadata.
5. The store correlates fingerprints and maintains successful environment baselines.
6. GitHub Checks publish the diagnosis in the developer's existing workflow.
7. Notification events are enqueued separately from workflow processing.
8. The notification dispatcher applies per-channel policies.
9. Slack, Discord, Telegram, and generic webhook adapters build platform-specific payloads.
10. Delivery records provide deduplication, retries, cooldowns, and failure visibility.

Notification queue behavior:

- A successful channel is marked `sent` and skipped on later job retries.
- Retryable failures remain `retrying` and are retried by the embedded queue.
- Permanent 4xx configuration errors are recorded as `failed` without retry loops.
- Repeated fingerprints can be marked `suppressed` during a channel cooldown.
- Generic outgoing payloads may be HMAC signed.

The embedded JSON state store is designed for portable evaluation. Its Store API is the seam for replacing persistence with PostgreSQL without changing analyzer, GitHub, server, worker, or notification packages.
