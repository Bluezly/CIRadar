# CI Radar comparison guide

This page explains product positioning, not a claim that one tool replaces every other category. Competitor capabilities change, so verify current vendor documentation before publishing a purchasing comparison.

## Positioning

CI Radar is strongest when a team wants:

- self-hosted and auditable source code
- a deterministic diagnosis core with visible evidence
- multi-CI ingestion in one service
- test intelligence, incidents, DORA, cost, ChatOps, and MCP without sending raw logs to a closed SaaS
- optional BYOK LLM and embeddings rather than a mandatory AI data path

## Category comparison

| Capability | CI Radar OSS | CI observability suites | Flaky-test specialists | AI CI repair tools |
|---|---|---|---|---|
| Self-hosted source available | Core design | Varies | Varies | Varies |
| Deterministic explainable diagnosis | Core design | Often mixed with proprietary analysis | Usually test-focused | Usually model-focused |
| Multi-CI ingestion | Included | Common | Varies | Varies |
| Test-level history and quarantine | Included | Often included | Core specialty | Varies |
| Distributed hyperscale event store | Not claimed | Common in mature SaaS | Vendor-managed | Vendor-managed |
| Automatic code repair | Deliberately not automatic | Varies | Sometimes | Core specialty |
| BYOK LLM layer | Optional | Varies | Varies | Often required or hosted |
| Read-only MCP | Included | Varies | Varies | Increasingly common |
| AGPL self-hosting | Included | Usually no | Usually no | Usually no |

## Honest tradeoffs

CI Radar does not have the operational history, contributor count, support organization, or globally distributed data plane of long-running SaaS vendors. Its advantage is control, inspectability, conservative automation, and coverage in one self-hosted service. Organizations needing contractual SLA, managed global scale, or fully automatic code repair should evaluate those requirements explicitly.
