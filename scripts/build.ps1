$ErrorActionPreference = "Stop"
$Version = if ($env:VERSION) { $env:VERSION } else { "1.3.2-oss-rc.14" }
$BuildDate = if ($env:BUILD_DATE) { $env:BUILD_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
try { $Commit = if ($env:COMMIT) { $env:COMMIT } else { (git rev-parse --short HEAD).Trim() } } catch { $Commit = "unknown" }
$Strip = if ($env:STRIP) { $env:STRIP.ToLowerInvariant() } else { "1" }
$MetadataFlags = "-X ciradar/internal/version.Version=$Version -X ciradar/internal/version.BuildDate=$BuildDate -X ciradar/internal/version.Commit=$Commit"
if ($Strip -in @("1", "true", "yes")) {
  $Ldflags = "-s -w $MetadataFlags"
} elseif ($Strip -in @("0", "false", "no")) {
  $Ldflags = $MetadataFlags
} else {
  throw "STRIP must be 0 or 1"
}
New-Item -ItemType Directory -Force -Path dist | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue dist/SHA256SUMS
go test ./...
go test -race ./...
go vet ./...
$targets = @(
  @{ OS="windows"; Arch="amd64"; Output="dist/CIRadar-Windows-x64.exe" },
  @{ OS="windows"; Arch="arm64"; Output="dist/CIRadar-Windows-arm64.exe" },
  @{ OS="linux"; Arch="amd64"; Output="dist/ciradar-linux-x64" },
  @{ OS="linux"; Arch="arm64"; Output="dist/ciradar-linux-arm64" },
  @{ OS="darwin"; Arch="amd64"; Output="dist/ciradar-darwin-x64" },
  @{ OS="darwin"; Arch="arm64"; Output="dist/ciradar-darwin-arm64" }
)
foreach ($target in $targets) {
  $env:CGO_ENABLED = "0"
  $env:GOOS = $target.OS
  $env:GOARCH = $target.Arch
  go build -buildvcs=false -trimpath -ldflags $Ldflags -o $target.Output ./cmd/ciradar
  Write-Host "Built $($target.Output)"
}
$checksumLines = foreach ($target in $targets) {
  $hash = (Get-FileHash -Algorithm SHA256 $target.Output).Hash.ToLowerInvariant()
  "$hash  $([System.IO.Path]::GetFileName($target.Output))"
}
$checksumLines | Set-Content -Encoding ascii dist/SHA256SUMS
Write-Host "Built CI Radar $Version (STRIP=$Strip) and dist/SHA256SUMS"
