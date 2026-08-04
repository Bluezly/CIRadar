# Test Intelligence

## Accepted report formats

- JUnit XML
- Playwright JSON reporter
- Jest JSON output
- pytest-json-report
- Cypress JSON output
- Mocha JSON output

```bash
ciradar tests ingest --repo acme/api --format playwright examples/playwright-report.json
ciradar tests ingest --repo acme/api --format jest examples/jest-results.json
ciradar tests ingest --repo acme/api --format pytest examples/pytest-report.json
ciradar tests ingest --repo acme/api --format cypress examples/cypress-results.json
ciradar tests ingest --repo acme/api --format junit examples/junit-failing.xml
```

## Test identity

A test key includes tenant, repository, framework, suite, class, test name and parameters. File location, workflow, job, runner environment and commit metadata are retained as context.

## Flaky classification

Historical pass/fail transitions and failure balance produce these states:

- `insufficient_history`
- `stable`
- `flaky`
- `consistently_failing`
- `mixed`

Probable cause categories include selector, timing, network, environment, resource, order/state, concurrency, data and unknown. Cause confidence is evidence-based and is not presented as certainty.

## Quarantine and enforcement

Quarantine requires an owner, reason and expiry and is written to the audit trail. Auto-quarantine is off by default.

```bash
ciradar tests gate --repo acme/api --format junit examples/junit-failing.xml
```

The command fails when a failed test is not actively quarantined and succeeds when all failures are quarantined. CI Radar does not alter the test runner itself.

## Predictive selection

```bash
ciradar tests select --repo acme/api --changed src/payments.go,src/ledger.go
```

The RC.2 selector uses changed-file proximity, test names, file identity, historical failures and optional flaky coverage. It is a transparent ranking model, not a learned coverage graph.
