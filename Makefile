.PHONY: test vet build windows linux clean
VERSION ?= 1.1.0-oss-rc.2
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X ciradar/internal/version.Version=$(VERSION) -X ciradar/internal/version.Commit=$(COMMIT) -X ciradar/internal/version.BuildDate=$(BUILD_DATE)
test:
	go test ./...
	go test -race ./...
vet:
	go vet ./...
windows:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-linux-x64 ./cmd/ciradar
build: windows linux
clean:
	rm -rf dist
