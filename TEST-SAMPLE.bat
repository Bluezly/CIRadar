@echo off
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json
CIRadar-Windows-x64.exe analyze --config ciradar.json --sample npm-econnreset
pause
