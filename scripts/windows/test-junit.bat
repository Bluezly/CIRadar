@echo off
setlocal
cd /d "%~dp0\..\.."
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul

echo Ingesting example JUnit report...
CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --workflow ci --job tests --run-id 1 examples\junit-failing.xml
if errorlevel 1 exit /b %errorlevel%

echo.
echo Tracked tests:
CIRadar-Windows-x64.exe tests list --config ciradar.json --repo demo/payments
pause
