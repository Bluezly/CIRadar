@echo off
setlocal
cd /d "%~dp0\..\.."
if "%~1"=="" (
  echo Usage: test-notification.bat CHANNEL_NAME
  echo Example: test-notification.bat slack-ops
  exit /b 2
)
CIRadar-Windows-x64.exe notify test --config ciradar.json --channel "%~1"
pause
