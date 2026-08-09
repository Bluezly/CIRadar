# Benchmark datasets

`example/dataset.json` is a synthetic smoke fixture. It must not be quoted as product accuracy.

For a real evaluation, create a separate immutable dataset directory containing a schema-v1 manifest and optional log files. Use `train` and `dev` while changing rules and reserve `test` for held-out reporting.

Run:

```text
ciradar benchmark --dataset benchmarks/example/dataset.json --split test
```

The authoritative methodology and publication rules are in [docs/benchmarking.md](../docs/benchmarking.md).

A benchmark report records both the resolved dataset SHA-256 and the analyzer SHA-256. Publish both values with any result. The example dataset is synthetic and is only a command/format smoke test.
