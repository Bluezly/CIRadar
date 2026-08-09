# CI connectors

All provider adapters normalize webhook and API data into the same tenant-scoped `CIEvent`. Diagnosis, incidents, DORA metrics, CI cost, notifications, safe rerun, and test intelligence operate on that shared model.

## Supported providers

| Provider | Webhook ingestion | Log retrieval | Native safe rerun |
|---|---:|---:|---:|
| GitHub Actions | yes | yes | yes |
| GitLab CI | yes | yes | yes |
| Buildkite | yes | yes | yes |
| CircleCI | yes | yes | yes |
| Jenkins | yes | supplied or configured endpoint | configured endpoint |
| Azure DevOps Pipelines | yes | yes | yes |
| Bitrise | yes | yes | yes |
| TeamCity | yes | yes | yes |
| Travis CI | yes | yes | yes |
| AWS CodeBuild | yes | event context or configured endpoint | configured endpoint |
| Bitbucket Pipelines | yes | yes | yes |
| Drone CI | yes | yes | yes |
| Semaphore | yes | yes | yes |
| AppVeyor | yes | yes | yes |
| Google Cloud Build | yes | yes | yes |

The generic retry endpoint exists for deployments where Jenkins or CodeBuild log and retry operations are exposed through an operator-controlled adapter.

## Routes

```text
POST /webhooks/github
POST /webhooks/gitlab
POST /webhooks/buildkite
POST /webhooks/circleci
POST /webhooks/jenkins
POST /webhooks/azuredevops
POST /webhooks/bitrise
POST /webhooks/teamcity
POST /webhooks/travis
POST /webhooks/codebuild
POST /webhooks/bitbucket
POST /webhooks/drone
POST /webhooks/semaphore
POST /webhooks/appveyor
POST /webhooks/cloudbuild
```

## Authentication and SSRF boundary

Each connector has its own token or webhook secret. Provider log and retry requests use the configured provider base URL or a provider-defined host. Arbitrary log URLs from webhook payloads are not fetched unless they match the trusted connector boundary. Boundary checks use normalized path segments and reject encoded path traversal and prefix-confusable paths.

Outbound connector requests reject non-public address ranges by default and refuse cross-origin redirects. For an internal Jenkins, TeamCity, GitLab, or adapter endpoint, set `allow_private_network: true` only on that connector after reviewing the target and its DNS. This is an explicit trust override, not a global switch.

Keep connector tokens in environment references or encrypted secret values. Assign each connector to one tenant.

## Safe rerun

Automatic rerun is disabled by default. It can run only when:

- deterministic attribution is `EXTERNAL`
- the positive externality score meets `automatic_retry_min_score`
- the category is on the safe-rerun allowlist
- the run has not already been retried by CI Radar
- no provider-wide incident suppresses individual reruns

Every attempt is idempotently recorded and audited. Safe rerun does not modify source code or workflow configuration.

## GitHub Issues linked to analyses

Authenticated operators can create and manage a GitHub Issue directly from an analysis:

- `POST /api/v1/analyses/{id}/github-issue`
- `GET /api/v1/analyses/{id}/github-issue`
- `PATCH /api/v1/analyses/{id}/github-issue`
- `POST /api/v1/analyses/{id}/github-issue/comments`

Create/update supports labels, assignees, milestone, issue type and issue fields when the installed GitHub App and repository permit them. Update also supports open/closed state, state reason, duplicate issue linkage, lock/unlock and lock reason. The stored link is tenant-scoped and refreshed from GitHub.
