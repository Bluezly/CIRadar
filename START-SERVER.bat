@echo off
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json
CIRadar-Windows-x64.exe serve --config ciradar.json
pause
