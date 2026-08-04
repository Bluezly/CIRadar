# CI connectors

All connectors normalize provider-specific payloads into the same tenant-scoped `CIEvent`. The analyzer, incident engine, DORA metrics, cost tracking and notifications are shared across providers.

## Common connector fields

```json
{
  "name": "provider-prod",
  "provider": "azuredevops",
  "enabled": true,
  "tenant_id": "acme",
  "base_url": "https://dev.azure.com/acme",
  "token": "env:CIRADAR_PROVIDER_TOKEN",
  "webhook_secret": "env:CIRADAR_PROVIDER_WEBHOOK_SECRET"
}
```

Supported secret forms are `env:NAME` and `enc:v1:...`.

## Provider endpoints

| Provider | Webhook endpoint | Log source |
|---|---|---|
| GitHub Actions | `/webhooks/github` | GitHub Actions job logs |
| GitLab CI | `/webhooks/gitlab` | Job trace API |
| Buildkite | `/webhooks/buildkite` | Build/job log API |
| CircleCI | `/webhooks/circleci` | Job steps and output URLs |
| Jenkins | `/webhooks/jenkins` | `consoleText` from an allowlisted base URL |
| Azure DevOps Pipelines | `/webhooks/azuredevops` | Build Logs REST API |
| Bitrise | `/webhooks/bitrise` | Build log API |
| TeamCity | `/webhooks/teamcity` | Build log endpoint |
| Travis CI | `/webhooks/travis` | Job log API |
| AWS CodeBuild | `/webhooks/codebuild` | EventBridge phase context or supplied log context |

## GitHub Actions

GitHub uses a GitHub App installation. CI Radar verifies HMAC-SHA256 webhooks, resolves the installation to a tenant, retrieves failed job logs, publishes a Check Run and optionally maintains one sticky Pull Request comment.

## GitLab CI

Enable job webhooks and configure the project access token needed to read traces. When an event contains a Merge Request IID, CI Radar maintains a sticky Merge Request note.

## Jenkins adapter

Jenkins payloads differ by plugin. CI Radar accepts a stable adapter payload and enforces the configured base URL before fetching `consoleText`.

```json
{
  "name": "unit-tests",
  "repository": "acme/api",
  "commit": "abc123",
  "branch": "main",
  "build": {
    "number": 42,
    "phase": "FINALIZED",
    "status": "FAILURE",
    "full_url": "https://jenkins.example/job/api/42/"
  }
}
```

## Delivery controls

- terminal events only
- bounded request bodies and logs
- webhook replay and duplicate suppression
- fetch timeouts and maximum byte limits
- secret redaction in transport errors
- tenant resolution before queueing
- disabled tenant rejection
