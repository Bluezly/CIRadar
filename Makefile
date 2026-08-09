.PHONY: check test race vet staticcheck vuln build windows linux darwin checksums clean

VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
STRIP ?= 1
STRIP_FLAGS := $(if $(filter 1 true yes,$(STRIP)),-s -w,)
LDFLAGS := $(STRIP_FLAGS) -X github.com/Bluezly/CIRadar/internal/version.Version=$(VERSION) -X github.com/Bluezly/CIRadar/internal/version.Commit=$(COMMIT) -X github.com/Bluezly/CIRadar/internal/version.BuildDate=$(BUILD_DATE)

check:
	./scripts/repo-check.sh

test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

staticcheck:
	staticcheck ./...

vuln:
	govulncheck ./...

windows:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/CIRadar-Windows-arm64.exe ./cmd/ciradar

linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-linux-x64 ./cmd/ciradar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-linux-arm64 ./cmd/ciradar

darwin:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-darwin-x64 ./cmd/ciradar
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-darwin-arm64 ./cmd/ciradar

checksums:
	cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum CIRadar-Windows-x64.exe CIRadar-Windows-arm64.exe ciradar-linux-x64 ciradar-linux-arm64 ciradar-darwin-x64 ciradar-darwin-arm64 > SHA256SUMS; else shasum -a 256 CIRadar-Windows-x64.exe CIRadar-Windows-arm64.exe ciradar-linux-x64 ciradar-linux-arm64 ciradar-darwin-x64 ciradar-darwin-arm64 > SHA256SUMS; fi

build: windows linux darwin checksums

clean:
	rm -rf dist
