@echo off
setlocal
cd /d "%~dp0\..\.."
chcp 65001 >nul
if not exist ciradar.json (
  CIRadar-Windows-x64.exe init --config ciradar.json
  echo.
  echo A secure root token was generated inside ciradar.json.
  echo Open that file and copy admin_token into the dashboard login field.
  echo.
)
echo Dashboard: http://127.0.0.1:8787/
CIRadar-Windows-x64.exe serve --config ciradar.json
pause
