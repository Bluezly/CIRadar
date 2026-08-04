@echo off
setlocal
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul

echo ============================================================
echo CI Radar Smoke Tests
echo ============================================================
CIRadar-Windows-x64.exe demo --config ciradar.json npm-econnreset
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe demo --config ciradar.json go-test-failure
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe analyze --config ciradar.json examples\npm-econnreset.txt
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe analyze --config ciradar.json examples\go-test-failure.txt
if errorlevel 1 exit /b %errorlevel%

echo Testing JUnit ingestion...
CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --workflow ci --job tests --run-id 1 examples\junit-failing.xml >nul
if errorlevel 1 exit /b %errorlevel%
CIRadar-Windows-x64.exe tests list --config ciradar.json --repo demo/payments --limit 5

echo Finished. These are smoke tests, not an accuracy benchmark.
pause
