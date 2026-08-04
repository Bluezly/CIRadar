#!/usr/bin/env sh
set -eu
BIN="${1:-./ciradar-linux-x64}"
[ -f ciradar.json ] || "$BIN" init --config ciradar.json >/dev/null
printf '\nBuilt-in npm sample\n'
"$BIN" analyze --config ciradar.json --sample npm-econnreset
printf '\nBuilt-in Go test sample\n'
"$BIN" analyze --config ciradar.json --sample go-test-failure
"$BIN" tests ingest --config ciradar.json --repo demo/payments --format junit examples/junit-failing.xml >/dev/null
"$BIN" tests list --config ciradar.json --repo demo/payments --limit 10
"$BIN" doctor --config ciradar.json
