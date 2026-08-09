@echo off
setlocal
cd /d "%~dp0\..\.."
chcp 65001 >nul
if not exist ciradar.json CIRadar-Windows-x64.exe init --config ciradar.json >nul
for %%P in (playwright jest pytest cypress) do (
  echo.
  echo Testing %%P report
  if "%%P"=="playwright" CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --format playwright examples\playwright-report.json
  if "%%P"=="jest" CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --format jest examples\jest-results.json
  if "%%P"=="pytest" CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --format pytest examples\pytest-report.json
  if "%%P"=="cypress" CIRadar-Windows-x64.exe tests ingest --config ciradar.json --repo demo/payments --format cypress examples\cypress-results.json
  if errorlevel 1 exit /b %errorlevel%
)
echo.
CIRadar-Windows-x64.exe tests list --config ciradar.json --repo demo/payments --limit 20
pause
