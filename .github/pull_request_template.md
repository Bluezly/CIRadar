## Summary

Describe the user-visible or operator-visible change.

## Reason

Explain the problem being solved and why this approach was chosen.

## Validation

- [ ] `make check` passes
- [ ] `go test -count=1 ./...` passes
- [ ] `go test -race -count=1 ./...` passes for concurrency-sensitive changes
- [ ] `go vet ./...` passes
- [ ] New behavior has regression coverage
- [ ] Tenant isolation, authentication, outbound network, and secret-handling impact were reviewed where relevant
- [ ] Documentation and `CHANGELOG.md` were updated when behavior changed

## Compatibility

Describe configuration, API, database, migration, and rollout impact. Write `None` when there is no compatibility impact.
