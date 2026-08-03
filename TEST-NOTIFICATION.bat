@echo off
setlocal
if "%~1"=="" (
  echo Usage: TEST-NOTIFICATION.bat CHANNEL_NAME
  echo Example: TEST-NOTIFICATION.bat slack-ops
  exit /b 2
)
CIRadar-Windows-x64.exe notify test --config ciradar.json --channel "%~1"
pause
