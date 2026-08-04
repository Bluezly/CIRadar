#!/usr/bin/env sh
set -eu
BIN="${1:-./ciradar-linux-x64}"
[ -f ciradar.json ] || "$BIN" init --config ciradar.json >/dev/null
for f in samples/npm-econnreset.log samples/go-compile-error.log samples/runner-lost.log samples/docker-rate-limit.log samples/ruby-bundler-conflict.log samples/toolchain-pip-internal.log; do
  printf '\nTesting %s\n' "$f"
  "$BIN" analyze --config ciradar.json "$f"
done
"$BIN" tests ingest --config ciradar.json --repo demo/payments --format junit examples/junit-failing.xml >/dev/null
"$BIN" tests ingest --config ciradar.json --repo demo/payments --format playwright examples/playwright-report.json >/dev/null
"$BIN" tests list --config ciradar.json --repo demo/payments --limit 10
