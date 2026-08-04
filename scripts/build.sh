#!/usr/bin/env sh
set -eu
VERSION="${VERSION:-1.2.0-oss-rc.3}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}"
mkdir -p dist
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE -X ciradar/internal/version.Commit=$COMMIT" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE -X ciradar/internal/version.Commit=$COMMIT" -o dist/ciradar-linux-x64 ./cmd/ciradar
