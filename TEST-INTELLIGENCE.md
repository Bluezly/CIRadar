# Test intelligence and impact selection

CI Radar ingests JUnit XML, Playwright JSON, Jest JSON, pytest-json-report, Cypress JSON, and Mocha JSON. It tracks individual test identity, pass/fail history, likely flake cause, quarantine state, owner, expiry, and audit history.

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

The impact graph is a static import graph, not a whole-program dynamic call graph. Coverage data is the strongest available signal. Reflection, runtime code generation, framework routing, and native calls may require explicit coverage mappings or always-run suites.

## Flake classification

CI Radar can classify likely causes such as timing, selector, network, environment, resource pressure, order/state, concurrency, and data. These labels are evidence-based hints, not proof of a root cause.

## Quarantine and gate

Quarantine requires an owner, reason, and expiry. The CI gate ignores only active quarantines and fails on other failing tests:

```bash
ciradar tests gate --repo acme/app --format junit results.xml
```

Automatic quarantine is optional and disabled by default.
