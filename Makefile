.PHONY: test vet build windows linux darwin clean
VERSION ?= 1.3.2-oss-rc.6-threshold-fix.1
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
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/CIRadar-Windows-arm64.exe ./cmd/ciradar
linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-linux-x64 ./cmd/ciradar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-linux-arm64 ./cmd/ciradar
darwin:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-darwin-x64 ./cmd/ciradar
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o dist/ciradar-darwin-arm64 ./cmd/ciradar
build: windows linux darwin
clean:
	rm -rf dist
