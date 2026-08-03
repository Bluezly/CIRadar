# Tested features — CI Radar 0.1.0-beta.3

Executed for this build:

- `gofmt` over all Go sources.
- `go test ./...`.
- `go test -race ./...`.
- `go vet ./...`.
- JWT generation and RSA signature verification.
- GitHub webhook HMAC verification and delivery de-duplication.
- Mock GitHub API end-to-end flow: installation token, workflow jobs, job logs,
  previous successful run detection, and Check Run creation.
- Embedded state persistence, atomic backup, and recovery behavior.
- Raw-log non-persistence when `store_raw_logs=false`.
- Redaction of common CI tokens, credentials, cloud keys, user paths, and PEM keys.
- Failure classification across npm, PyPI, RubyGems/Bundler, Docker/GHCR, APT,
  NuGet, Go/Cargo/Git, GitHub Artifacts/cache/runners, Gradle/Maven, Composer,
  Bazel, Terraform, Helm, and Kubernetes examples.
- Separate `TOOLCHAIN_FAILURE` classification for internal package-manager,
  compiler, or build-tool defects so they are not mislabeled as project code.
- Environment extraction, successful baseline storage, and runner/tool drift detection.
- Cross-repository incident simulation and provider-status enrichment.
- Custom JSON rule loading and validation.
- Local HTTP API, bearer-token protection, health/status endpoints, and report export.
- Windows amd64 and Linux amd64 cross-compilation with `CGO_ENABLED=0`.
- Curated regression run against 215 public error examples; see
  `BENCHMARK-REPORT.md` for why this is not a claim of 100% unseen-world accuracy.

Not tested against a live GitHub App installation because no real App ID/private
key was supplied. The network flow was tested against an in-process mock GitHub
API. Use a disposable repository for the first live installation.
