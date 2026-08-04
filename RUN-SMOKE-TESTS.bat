@echo off
setlocal
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul

echo ============================================================
echo CI Radar 1.1.0 OSS RC2 - Smoke Tests
echo ============================================================
for %%F in (
  samples\npm-econnreset.log
  samples\go-compile-error.log
  samples\runner-lost.log
  samples\docker-rate-limit.log
  samples\ruby-bundler-conflict.log
  samples\toolchain-pip-internal.log
) do (
  echo.
  echo Testing %%F
  CIRadar-Windows-x64.exe analyze --config ciradar.json %%F
)
echo.
echo.
echo Testing JUnit ingestion...
CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --workflow ci --job tests --run-id 1 examples\junit-failing.xml >nul
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe tests list --config ciradar.json --repo demo/payments --limit 5

echo.
echo Finished. These are smoke tests, not an accuracy benchmark.
pause
