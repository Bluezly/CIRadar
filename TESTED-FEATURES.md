# Tested features — CI Radar 0.2.0 Beta 4

- Existing analyzer, redaction, custom rules, state backup, incident correlation, environment drift, and mocked GitHub API tests.
- Slack payload delivery to an HTTP test server.
- Discord embed delivery to an HTTP test server.
- Telegram `sendMessage` payload delivery to an HTTP test server.
- Generic webhook JSON delivery with verified HMAC-SHA256 signature.
- Per-channel category, repository, score, and external-only filters.
- Cooldown suppression for repeated fingerprints.
- Independent delivery state: successful channels are not resent when another channel retries.
- Permanent and retryable HTTP failure handling.
- Sanitization of secret webhook URLs from stored transport errors.
- Race detector and `go vet` checks.

External credentials were not available, so Slack, Discord, and Telegram were tested against protocol-compatible local HTTP servers rather than live accounts.
