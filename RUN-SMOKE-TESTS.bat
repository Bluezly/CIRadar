@echo off
setlocal
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul

echo ============================================================
echo CI Radar OSS RC5 - Smoke Tests
echo ============================================================
echo.
echo Testing built-in npm sample
CIRadar-Windows-x64.exe analyze --config ciradar.json --sample npm-econnreset
if errorlevel 1 exit /b %errorlevel%
echo.
echo Testing built-in Go test sample
CIRadar-Windows-x64.exe analyze --config ciradar.json --sample go-test-failure
if errorlevel 1 exit /b %errorlevel%
echo.
echo Testing JUnit ingestion
CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --workflow ci --job tests --run-id 1 examples\junit-failing.xml >nul
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe tests list --config ciradar.json --repo demo/payments --limit 5
CIRadar-Windows-x64.exe doctor --config ciradar.json
echo.
echo Finished. These are smoke tests, not an accuracy benchmark.
pause
