#!/usr/bin/env sh
set -eu
VERSION="${VERSION:-1.3.2-oss-rc.6-hardening-fix.5}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}"
STRIP="${STRIP:-1}"
LDFLAGS="-X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE -X ciradar/internal/version.Commit=$COMMIT"
case "$STRIP" in
  1|true|TRUE|yes|YES) LDFLAGS="-s -w $LDFLAGS" ;;
  0|false|FALSE|no|NO) ;;
  *) printf 'STRIP must be 0 or 1\n' >&2; exit 2 ;;
esac
mkdir -p dist
rm -f dist/SHA256SUMS
go test ./...
go test -race ./...
go vet ./...
build(){ CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -buildvcs=false -trimpath -ldflags "$LDFLAGS" -o "$3" ./cmd/ciradar; }
build windows amd64 dist/CIRadar-Windows-x64.exe
build windows arm64 dist/CIRadar-Windows-arm64.exe
build linux amd64 dist/ciradar-linux-x64
build linux arm64 dist/ciradar-linux-arm64
build darwin amd64 dist/ciradar-darwin-x64
build darwin arm64 dist/ciradar-darwin-arm64
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum CIRadar-Windows-x64.exe CIRadar-Windows-arm64.exe ciradar-linux-x64 ciradar-linux-arm64 ciradar-darwin-x64 ciradar-darwin-arm64 > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd dist && shasum -a 256 CIRadar-Windows-x64.exe CIRadar-Windows-arm64.exe ciradar-linux-x64 ciradar-linux-arm64 ciradar-darwin-x64 ciradar-darwin-arm64 > SHA256SUMS)
else
  printf 'No SHA-256 utility found; install sha256sum or shasum\n' >&2
  exit 1
fi
printf 'Built CI Radar %s (STRIP=%s) and dist/SHA256SUMS\n' "$VERSION" "$STRIP"
