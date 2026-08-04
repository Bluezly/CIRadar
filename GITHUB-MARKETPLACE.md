# GitHub Marketplace integration

CI Radar remains free, open source, and fully functional without GitHub Marketplace. The Marketplace integration is optional distribution and installation metadata. It does not enable or disable product features.

## Events

CI Radar handles `marketplace_purchase` actions:

- `purchased`
- `changed`
- `cancelled`
- `pending_change`
- `pending_change_cancelled`

Events are accepted on the primary GitHub App webhook route and on the dedicated Marketplace route. Both verify HMAC signatures and use delivery IDs for idempotency. Older events are ignored when their effective date predates the stored subscription state.

## Tenant linking

The service resolves the tenant in this order:

1. an existing GitHub installation binding
2. an existing Marketplace account index
3. automatic creation of a stable tenant when enabled

The installation is then bound to the resolved tenant.

## Cancellation

The default `retain_free` policy records the account as free and keeps the tenant enabled. This is the recommended behavior for the free OSS distribution. An optional `disable_tenant` policy exists for operators with a different administrative model, but it is not a license gate.

## Configuration

```json
{
  "github_marketplace": {
    "enabled": true,
    "webhook_secret": "env:CIRADAR_MARKETPLACE_WEBHOOK_SECRET",
    "auto_create_tenant": true,
    "cancellation_policy": "retain_free",
    "free_plan_name": "free"
  }
}
```

The Marketplace secret falls back to the GitHub App webhook secret when omitted.

Administrative endpoints expose stored metadata:

```text
GET /api/v1/marketplace/subscription
GET /api/v1/marketplace/subscriptions
```

Responses explicitly report that feature gates are disabled.
