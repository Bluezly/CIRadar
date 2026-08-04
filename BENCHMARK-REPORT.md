# CI Radar Benchmark Context

An earlier classifier-development corpus contained 215 curated excerpts from public GitHub issues across package managers, runners, caches, language toolchains and deployment systems. After iterative rule work, the earlier release agreed with the expected CI Radar taxonomy on 215/215 examples.

That number is **historical regression context**, not a Beta 5 claim of 100% real-world accuracy:

- examples were selected and labeled by the product developer;
- several sets influenced rule development;
- the labels are CI Radar taxonomy judgments, not official root-cause labels;
- the full excerpt corpus is not bundled in this source archive, so it was not freshly rerun during Beta 5 packaging.

Beta 5 verification instead focuses on reproducible code tests included in the source:

- analyzer and redaction tests;
- positive/negative evidence and attribution tests;
- HMAC fingerprint stability and key separation;
- tenant isolation, RBAC and queue isolation;
- notification retries, routing, quiet hours and deduplication;
- environment drift for runner, architecture, tools, Actions and containers;
- mock GitHub API end-to-end worker processing;
- incident escalation for critical repositories;
- server authorization and live API smoke tests.

The correct interpretation remains: CI Radar handles its known regression classes and deliberately returns `UNKNOWN` for insufficient evidence. Accuracy on arbitrary unseen production logs still requires a genuinely independent evaluation corpus.
