# Tested features — 1.0.0 RC.1

Automated tests cover:

- deterministic analyzer, evidence scoring, actions and redaction
- encrypted secret resolution
- tenant isolation and RBAC
- atomic embedded storage and recovery
- PostgreSQL wire protocol, TLS/auth flows, migrations and transactional backend contract via mocks
- GitHub App mock end-to-end: token, jobs, logs, previous success, Check Run and sticky PR comment
- GitLab/Buildkite/CircleCI/Jenkins webhook parsing, signatures and mock log APIs
- sticky GitLab MR note create/update
- notifications: Slack, Discord, Telegram, webhook HMAC, SMTP, Teams, PagerDuty, Opsgenie
- notification retries, rate limits, cooldown, quiet hours and race prevention
- JUnit parsing, test history, auto-quarantine, manifest and CLI gate
- diagnosis feedback and dashboard metrics
- MCP tenant isolation, read-only tools, resources and HTTP guards
- worker generic CI and GitHub paths

Not live-tested in this environment:

- real PostgreSQL daemon
- real GitHub/GitLab/Buildkite/CircleCI/Jenkins accounts
- real Slack/Teams/PagerDuty/Opsgenie/SMTP credentials
