@echo off
chcp 65001 >nul
CIRadar-Windows-x64.exe init --config ciradar.json 2>nul
CIRadar-Windows-x64.exe analyze --config ciradar.json samples\npm-econnreset.log
pause
