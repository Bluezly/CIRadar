# CI connectors

## Shared configuration

```json
{
  "connectors": [
    {
      "name": "gitlab-prod",
      "provider": "gitlab",
      "enabled": true,
      "tenant_id": "acme",
      "base_url": "https://gitlab.com",
      "token": "env:GITLAB_TOKEN",
      "webhook_secret": "env:GITLAB_WEBHOOK_SECRET"
    }
  ]
}
```

Secrets may be `env:NAME` or AES-GCM `enc:v1:...`.

## GitLab

Webhook: `/webhooks/gitlab`

Enable Job events. CI Radar accepts the standard secret token and GitLab HMAC signing token format. The API token needs permission to read job traces. When the Job Hook contains a merge request IID, CI Radar creates/updates a sticky merge request note.

## Buildkite

Webhook: `/webhooks/buildkite`

Enable job/build events. Verification supports `X-Buildkite-Token` and timestamped HMAC signatures. The API token needs build-log read access.

## CircleCI

Webhook: `/webhooks/circleci`

Use `job-completed` or `workflow-completed` and configure a signing secret. CI Radar validates `circleci-signature`, fetches job steps, then follows output URLs.

## Jenkins

Webhook: `/webhooks/jenkins`

Jenkins has no universal webhook payload across plugins. CI Radar accepts a stable adapter payload:

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

Send `X-CI-Radar-Token` or `X-CI-Radar-Signature-256`. The configured `base_url` is enforced before fetching `/consoleText` to block SSRF. Use username + API token for Basic authentication.

## Delivery safety

- Webhook deliveries are deduplicated.
- Only terminal conclusions are queued.
- Payload size is bounded.
- Log fetch has timeouts and byte limits.
- Provider errors are redacted before persistence.
