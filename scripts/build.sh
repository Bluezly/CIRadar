#!/usr/bin/env sh
set -eu
VERSION="0.1.0-beta.1"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p dist
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$VERSION -X ciradar/internal/version.BuildDate=$BUILD_DATE" -o dist/ciradar-linux-x64 ./cmd/ciradar
