# Governance

CI Radar is developed as an open-source project. Technical decisions prioritize security, deterministic evidence, tenant isolation, privacy, interoperability, conservative automation, and reproducible releases.

Changes to authentication, authorization, storage, cryptography, webhook verification, automated actions, tenancy, data retention, or release integrity require additional review and regression coverage.

Breaking API, configuration, or schema changes must include a migration path and changelog entry. Behavior changes should be documented in the same pull request that introduces them.

The AGPL distribution contains the complete self-hosted runtime. Optional Marketplace metadata does not act as a feature gate.
