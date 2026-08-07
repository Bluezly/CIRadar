#!/usr/bin/env sh
set -eu

if [ -z "${CIRADAR_TEST_POSTGRES_DSN:-}" ]; then
  echo "CIRADAR_TEST_POSTGRES_DSN is required for production preflight" >&2
  exit 2
fi

echo "[1/4] live PostgreSQL integration tests"
go test -count=1 ./internal/db -run '^TestPostgresIntegration'

echo "[2/4] PostgreSQL protocol and SAML security regressions"
go test -count=1 ./internal/pgwire ./internal/sso

echo "[3/4] ChatOps and notification regressions"
go test -count=1 ./internal/server ./internal/notifications

echo "[4/4] uncached full suite"
go test -count=1 ./...

cat <<'MSG'
Automated preflight passed.
This is not production certification. Record representative load, backup/restore,
replication/failover, migration rehearsal, real-IdP SAML interoperability, and
platform-native binary acceptance before approving a production deployment.
MSG
