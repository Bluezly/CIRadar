#!/usr/bin/env sh
set -eu
BIN="${1:-./ciradar-linux-x64}"
[ -f ciradar.json ] || "$BIN" init --config ciradar.json >/dev/null
"$BIN" demo --config ciradar.json npm-econnreset
"$BIN" demo --config ciradar.json go-test-failure
"$BIN" analyze --config ciradar.json examples/npm-econnreset.txt
"$BIN" analyze --config ciradar.json examples/go-test-failure.txt
"$BIN" tests ingest --config ciradar.json --repo demo/payments --format junit examples/junit-failing.xml >/dev/null
"$BIN" tests ingest --config ciradar.json --repo demo/payments --format playwright examples/playwright-report.json >/dev/null
"$BIN" tests list --config ciradar.json --repo demo/payments --limit 10
