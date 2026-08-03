$ErrorActionPreference = "Stop"
$Version = "0.2.0-beta.4"
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go test ./...
go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$Version -X ciradar/internal/version.BuildDate=$BuildDate" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
Write-Host "Built dist/CIRadar-Windows-x64.exe"
