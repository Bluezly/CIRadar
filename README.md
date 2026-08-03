# CI Radar 0.1 Beta.3

Portable, dependency-free Go prototype for GitHub Actions failure intelligence.
It analyzes failed job logs, redacts secrets, fingerprints recurring failures,
correlates incidents, detects environment drift, and can publish GitHub Checks.

The first release has no web dashboard. Its interfaces are the CLI, local REST
API, and GitHub Checks. See [README-AR.md](README-AR.md) for full setup and
[BENCHMARK-REPORT.md](BENCHMARK-REPORT.md) for the test methodology and limits.

Quick test:

```text
CIRadar-Windows-x64.exe init
CIRadar-Windows-x64.exe analyze samples/npm-econnreset.log
CIRadar-Windows-x64.exe serve
```
