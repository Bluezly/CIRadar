# Tested features — CI Radar 0.1.0-beta.1

The following checks were executed for this build:

- `gofmt` clean check.
- `go test ./...`.
- `go test -race ./...`.
- `go vet ./...`.
- JWT generation and RSA signature verification.
- GitHub webhook HMAC verification.
- Mock GitHub API flow: installation token, workflow jobs, job logs, prior successful run, and Check Run creation.
- Embedded state persistence and backup behavior.
- Raw-log non-persistence when `store_raw_logs=false`.
- npm registry failure classification.
- deterministic Go compiler failure classification.
- runner communication failure classification.
- environment extraction from timestamped GitHub logs.
- successful baseline storage and runner/tool drift detection.
- cross-repository incident simulation.
- custom JSON rule loading and validation.
- local HTTP API, bearer-token protection, health/status endpoints.
- report export.
- Windows amd64 cross-compilation with `CGO_ENABLED=0`.

Not tested against a live GitHub account because no GitHub App credentials were
provided. The network flow was tested against an in-process mock API. Run the
first live installation on a disposable repository before broader deployment.
