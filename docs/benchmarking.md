# Detection benchmark policy

CI Radar unit tests verify implementation behavior. They are not evidence of real-world diagnostic accuracy because most unit fixtures are written alongside the rules they exercise.

The `ciradar benchmark` command evaluates the deterministic analyzer against an external, labeled corpus and reports category accuracy, macro precision/recall/F1, abstention coverage, UNKNOWN rate, covered accuracy, 95% Wilson intervals, secondary-label accuracy, rule-match coverage, a confusion matrix, and case-level errors.

## Publication rules

Do not publish accuracy from `benchmarks/example`. It exists only to exercise the dataset format and command.

A publishable benchmark should meet all of these conditions:

1. Logs come from projects or organizations not used to author the matching rule being evaluated.
2. Every case records provenance and the dataset version is immutable after publication.
3. Labels are assigned from the failure evidence, not from CI Radar's prediction. Prefer two independent labelers plus adjudication for disputed cases.
4. Keep a held-out `test` split. Rule tuning belongs on `train`/`dev`; do not repeatedly tune against the published test split.
5. Preserve UNKNOWN cases. Removing difficult or organization-specific failures inflates recall and hides cold-start behavior.
6. Report the dataset SHA-256 and analyzer SHA-256 printed by the command, case count, class distribution, CI Radar version, and configuration used. The analyzer digest covers rule content/order and redaction behavior so a result cannot silently be compared across changed rule sets.
7. Report confidence intervals and the full confusion matrix, not a single accuracy number.
8. Run the deterministic analyzer without LLM enhancement for the primary classification benchmark. Evaluate LLM diagnosis or repair in a separate track because provider/model revisions otherwise make the result non-reproducible.
9. Do not include secrets or private logs without a documented right to use them. Redaction is a risk reduction control, not proof that a log is safe to publish.
10. Publish failures and UNKNOWN predictions with the successes. A benchmark that hides misses is marketing, not measurement.

## Candidate public corpora

Useful sources for building an external detection corpus include LogChunks, which contains manually labeled failure-reason chunks from Travis CI logs, and BugSwarm, which provides reproducible real-world CI build pairs. Their native labels do not exactly match CI Radar's categories, so category mapping must be documented and manually reviewed rather than inferred from CI Radar itself. CI repair should be evaluated separately with execution-backed corpora such as CI-Repair-Bench, where a proposed repair is judged by re-running the original repository workflow rather than by whether a patch looks plausible.

Public data should be redistributed only under its original license and terms. A benchmark manifest may reference local log files instead of embedding them.

## Dataset format

See `benchmarks/dataset.schema.json` and `benchmarks/example/dataset.json`.

Each case has an immutable ID, optional source/split/tags, normal `AnalysisInput` fields, optional analyzer context, and an expected category. Attribution, provider, and error family labels are optional and are scored only when present.

A log can be inline:

```json
{
  "id": "case-001",
  "split": "test",
  "input": {"log": "..."},
  "expected": {"category": "NETWORK_FAILURE"}
}
```

or stored beside the manifest:

```json
{
  "id": "case-002",
  "source": "public-corpus-v1",
  "split": "test",
  "input": {"repository": "owner/repo", "source_provider": "github"},
  "log_file": "logs/case-002.log",
  "expected": {"category": "CODE_FAILURE", "attribution": "CODE"}
}
```

`log_file` is restricted to the dataset directory after both lexical and symlink resolution. Absolute paths, `..` traversal, and symlink escapes are rejected. The manifest is limited to 32 MiB, each resolved case log to 8 MiB, aggregate resolved log material to 256 MiB, and a dataset to 100,000 cases. If a case names a `source`, that source must be declared in the manifest; reports include case counts by source.

## Run

```text
ciradar benchmark --dataset /path/to/dataset.json --split test --json
```

Write an auditable report:

```text
ciradar benchmark \
  --dataset /path/to/dataset.json \
  --split test \
  --output benchmark-report.json \
  --min-cases 500 \
  --min-category-accuracy 0.80 \
  --min-macro-f1 0.75 \
  --min-coverage 0.80 \
  --max-unknown-rate 0.20
```

A threshold violation exits with an error, so the benchmark can be used as a regression gate. Thresholds are project policy; they are not claims about current CI Radar accuracy.

Pass `--config` only when intentionally benchmarking custom rules. The JSON and human reports include an analyzer SHA-256 so changed rules or redaction policy are visible. Keep the configuration itself with published artifacts for auditability.

## Reading the numbers

- **Category accuracy**: fraction of all cases whose top-level category matches the label.
- **Macro precision/recall/F1**: equal weight per non-UNKNOWN category appearing in truth or predictions. Predicted-only classes are included, so spurious categories cannot disappear from the macro score.
- **Coverage**: fraction where CI Radar did not abstain as `UNKNOWN`.
- **UNKNOWN rate**: complement of coverage. This exposes cold-start and unsupported-tool behavior.
- **Covered accuracy**: accuracy only among non-UNKNOWN predictions. Read this together with coverage; high covered accuracy with very low coverage is not strong recall.
- **Rule match coverage**: cases where at least one named deterministic rule contributed. This is not the same as correctness.
- **95% CI**: Wilson interval for category accuracy and coverage. Small corpora should visibly produce wide intervals.

The JSON report also contains per-category TP/FP/FN, the full confusion matrix, matched-rule counts, and all mismatches.

## Runtime feedback is not benchmark precision

The `/api/v1/analyses/{id}/feedback` endpoint can collect reviewer verdicts and optional `actual_category`, `actual_cause`, `actual_provider`, and `actual_error_family` labels. `agreement_percent` is a weighted reviewer-agreement signal, not precision. Labeled category and attribution accuracy are calculated only when ground-truth labels are available.
