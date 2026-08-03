# CI Radar Beta 3 benchmark report

## What was tested

The classifier was exercised against **215 curated error excerpts** collected
from public GitHub issues and discussions. The sets cover GitHub Actions,
package registries, runners, caches, Go/Rust, JVM builds, .NET/NuGet, Docker,
Composer/Bazel, Terraform, Helm/Kubernetes, and RubyGems/Bundler.

| Dataset | Agreement | Score |
|---|---:|---:|
| core-public-issues-40 | 40/40 | 100.0% |
| github-actions-artifacts-30 | 30/30 | 100.0% |
| go-rust-holdout-20 | 20/20 | 100.0% |
| jvm-holdout-25 | 25/25 | 100.0% |
| dotnet-docker-holdout-20 | 20/20 | 100.0% |
| composer-bazel-holdout-20 | 20/20 | 100.0% |
| terraform-holdout-20 | 20/20 | 100.0% |
| helm-k8s-holdout-20 | 20/20 | 100.0% |
| ruby-bundler-holdout-20 | 20/20 | 100.0% |
| **Total** | **215/215** | **100.0%** |

## Honest development history

- The previous Beta 2 rules scored **26/40 (65%)** on the first real public set.
- A new Ruby/Bundler blind set initially scored **4/20 (20%)** because the
  product had no Ruby-specific resolver, permission, native-extension, or
  package-integrity rules.
- After adding general Ruby/Bundler rules, that set reached **20/20**.
- A taxonomy audit added `TOOLCHAIN_FAILURE` so internal failures explicitly
  reported by pip, Bundler, or a compiler are not mislabeled as project code.

## What the 215/215 number does not mean

This is a **regression agreement score**, not proof of perfect accuracy. Some of
these examples were used while improving the rules, so the full set is not an
independent statistical holdout. The expected categories are human judgments
under CI Radar's product taxonomy, not labels published by the source projects.

The safe interpretation is: all known regression examples now behave as
intended. It does not mean every future CI log will be classified correctly.
The product deliberately returns `UNKNOWN` when evidence is insufficient.

## Additional verification

- Unit, race, and vet checks pass.
- Secret redaction and raw-log non-persistence are tested.
- GitHub App authentication, log retrieval, previous-success lookup, and Check
  creation are exercised against an in-process mock GitHub API.
- A live GitHub App installation was not tested because no real credentials
  were supplied. The first live trial should use a disposable repository.

Machine-readable details are in `BENCHMARK-SUMMARY.json` and the separate
benchmark-results archive delivered with the build.
