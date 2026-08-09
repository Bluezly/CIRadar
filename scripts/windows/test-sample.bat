@echo off
setlocal
cd /d "%~dp0\..\.."
chcp 65001 >nul
CIRadar-Windows-x64.exe init --config ciradar.json 2>nul
CIRadar-Windows-x64.exe demo --config ciradar.json npm-econnreset
pause
