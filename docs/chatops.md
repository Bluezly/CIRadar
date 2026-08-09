# ChatOps

## Slack

Configure Slack interactivity to send requests to `/chatops/slack`. CI Radar validates the Slack timestamp and v0 HMAC signature. Every allowed Slack workspace must also have an explicit `slack_team_tenants` mapping; the authenticated Slack Team ID is authoritative for tenant selection, and an action whose embedded tenant disagrees with that mapping is rejected. Incident notifications include Acknowledge and Resolve buttons. Flaky-test notifications include a time-limited Quarantine button. A successful automatic quarantine emits a separate `test_quarantined` notification rather than relying on the manual button.

## Microsoft Teams

Teams incoming webhook cards cannot submit write actions. Two-way Teams operations use an outgoing webhook to `/chatops/teams`. CI Radar validates the Teams HMAC authorization header.

Commands:

```text
ack <fingerprint>
resolve <fingerprint>
quarantine <test-key>
```

ChatOps actions are allowlisted, tenant-scoped, audited, and separately enabled.


Example multi-tenant binding:

```json
{
  "slack_allowed_teams": ["T-ALPHA", "T-BETA"],
  "slack_team_tenants": {
    "t-alpha": "alpha",
    "t-beta": "beta"
  }
}
```

A Slack signing secret without explicit workspace-to-tenant bindings is rejected at configuration load time.
