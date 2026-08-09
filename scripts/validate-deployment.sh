#!/usr/bin/env sh
set -eu

if [ -z "${CIRADAR_TEST_POSTGRES_DSN:-}" ]; then
  echo "CIRADAR_TEST_POSTGRES_DSN is required" >&2
  exit 2
fi

echo "[1/4] PostgreSQL integration"
go test -count=1 ./internal/db -run '^TestPostgresIntegration'

echo "[2/4] PostgreSQL protocol and SAML regressions"
go test -count=1 ./internal/pgwire ./internal/sso

echo "[3/4] ChatOps and notification regressions"
go test -count=1 ./internal/server ./internal/notifications

echo "[4/4] Full test suite"
go test -count=1 ./...

echo "Deployment checks passed"
