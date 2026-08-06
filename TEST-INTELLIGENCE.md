# Test intelligence and impact selection

CI Radar ingests JUnit XML, Playwright JSON, Jest JSON, pytest-json-report, Cypress JSON, and Mocha JSON. It tracks individual test identity, execution variant, pass/fail history, unique Pull Requests impacted, likely flake cause, quarantine state, critical-test policy, owner, expiry, and audit history. Failure messages and details are redacted before persistence, and stored run URLs discard credentials, query strings, fragments, and unsafe schemes.

## Impact-aware selection

Selection uses three evidence layers, in descending strength:

1. per-test coverage maps supplied by the test runner or coverage tooling
2. a repository impact graph built from Go, JavaScript/TypeScript, and Python imports
3. transparent historical and path-proximity heuristics

Each selected test reports:

- `strategy`: `coverage`, `dependency_graph`, or a heuristic strategy
- `confidence`
- `priority_score`
- `impact_path` when a dependency path was found
- the human-readable reason

Build the repository graph:

```bash
ciradar tests index --repo acme/app --root .
```

Merge a coverage map:

```bash
ciradar tests coverage --repo acme/app coverage-map.json
```

Example coverage input:

```json
{
  "repository": "acme/app",
  "coverage": {
    "tests/payments.spec.ts::declines expired cards": [
      "src/payments/card.ts",
      "src/ledger/write.ts"
    ]
  }
}
```

Select tests:

```bash
ciradar tests select --repo acme/app --changed src/payments/card.ts,src/ledger/write.ts
```

Coverage identities may use the test hash, test name, `suite::name`, `class::name`, or readable paths such as `payments/PaymentServiceTest/retries_transient_gateway_error`. Empty selections include diagnostics showing whether history, graph, coverage identity matching, or the score threshold prevented selection.

The impact graph is a static import graph, not a whole-program dynamic call graph. Coverage data is the strongest available signal. Reflection, runtime code generation, framework routing, and native calls may require explicit coverage mappings or always-run suites.


### Fail-safe behavior

Partial selection is rejected by default when CI Radar cannot prove adequate impact coverage. The response sets `full_suite_required=true` and returns every test known to repository history when any of these conditions apply:

- no dependency graph is available, or a changed file is absent from the graph
- coverage identities are missing or only partially resolve to known tests
- configuration, environment, migration/schema, dependency manifest/lockfile, CI, container, or build-system files changed
- changed files are empty or otherwise insufficient to establish impact

`allow_unsafe_partial=true` is an explicit escape hatch. It is reported as `unsafe_override_applied=true`, with risk reasons and diagnostics. “Full known suite” means all tests CIRadar has observed; a runner must still define a canonical full-suite command so brand-new tests are not omitted.

## Flake classification

CI Radar can classify likely causes such as timing, selector, network, environment, resource pressure, order/state, concurrency, and data. These labels are evidence-based hints, not proof of a root cause.

Flake statistics distinguish total observations from executed runs. `skipped` observations do not increase history confidence or dilute the failure rate. Replayed observation IDs are idempotent, out-of-order history cannot overwrite the latest execution, and classification uses a warm-up period before confirming `flaky`. Responses include a Wilson 95% failure-rate interval, history confidence, transition rate, same-context rerun recoveries, average duration, estimated compute minutes lost, and a conservative engineering-minutes-lost estimate. These estimates are operational indicators, not payroll accounting.


## Quarantine and gate

Quarantine requires an owner, reason, and expiry. It accepts either the stable hash or a readable identity:

```bash
ciradar tests quarantine --repo acme/app --test payments/PaymentServiceTest/retries_transient_gateway_error --owner payments --reason "intermittent gateway fixture" --duration 72h
ciradar tests unquarantine --repo acme/app --test payments/PaymentServiceTest/retries_transient_gateway_error
```

`ciradar tests list --repo acme/app` includes `display_name` and accepted aliases. The CI gate ignores only active quarantines and fails on other failing tests:

```bash
ciradar tests gate --repo acme/app --format junit results.xml
```

Critical tests can be protected from automatic quarantine through the API, dashboard, or CLI:

```bash
ciradar tests critical --repo acme/app --test payments/PaymentServiceTest/retries_transient_gateway_error
ciradar tests noncritical --repo acme/app --test payments/PaymentServiceTest/retries_transient_gateway_error
```

Automatic quarantine is optional and disabled by default. Even when enabled, it skips tests marked critical.
