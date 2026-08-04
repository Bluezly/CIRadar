# ChatOps

## Slack

Configure Slack interactivity to send requests to `/chatops/slack`. CI Radar validates the Slack timestamp and v0 HMAC signature. Incident notifications include Acknowledge and Resolve buttons. Flaky-test notifications include a time-limited Quarantine button.

## Microsoft Teams

Teams incoming webhook cards cannot submit write actions. Two-way Teams operations use an outgoing webhook to `/chatops/teams`. CI Radar validates the Teams HMAC authorization header.

Commands:

```text
ack <fingerprint>
resolve <fingerprint>
quarantine <test-key>
```

ChatOps actions are allowlisted, tenant-scoped, audited, and separately enabled.
