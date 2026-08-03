@echo off
setlocal
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul

echo ============================================================
echo CI Radar Beta 4 - Smoke Tests
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
echo Finished. These are smoke tests, not the 215-case benchmark.
pause
