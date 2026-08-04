$ErrorActionPreference = "Stop"
$Version = if ($env:VERSION) { $env:VERSION } else { "1.1.0-oss-rc.2" }
$BuildDate = if ($env:BUILD_DATE) { $env:BUILD_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
try { $Commit = if ($env:COMMIT) { $env:COMMIT } else { (git rev-parse --short HEAD).Trim() } } catch { $Commit = "unknown" }
New-Item -ItemType Directory -Force -Path dist | Out-Null
go test ./...
go vet ./...
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -buildvcs=false -trimpath -ldflags "-s -w -X ciradar/internal/version.Version=$Version -X ciradar/internal/version.BuildDate=$BuildDate -X ciradar/internal/version.Commit=$Commit" -o dist/CIRadar-Windows-x64.exe ./cmd/ciradar
Write-Host "Built dist/CIRadar-Windows-x64.exe"
