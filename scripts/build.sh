#!/usr/bin/env sh
set -eu
VERSION="${VERSION:-1.3.0-oss-rc.4}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}"
LDFLAGS="-s -w -X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE -X ciradar/internal/version.Commit=$COMMIT"
mkdir -p dist
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
