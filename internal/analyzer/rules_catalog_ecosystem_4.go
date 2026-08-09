package analyzer

import "github.com/Bluezly/CIRadar/internal/model"

func catalogEcosystemRules4() []catalogRuleSpec {
	return []catalogRuleSpec{
		ossRule(`eco-extra-android-sdk-package`, model.CategoryToolchainFailure, `Android SDK`, `sdk`, `sdk-package-missing`, 99, `toolchain`, `Inspect the first Android SDK failure, correct the sdk package missing, and rerun the failed step.`, `Failed to find target with hash string .* in:|Installed Build Tools revision .* is corrupted|failed to find Build Tools revision`),
		ossRule(`eco-extra-android-ndk`, model.CategoryToolchainFailure, `Android NDK`, `native-build`, `ndk-missing`, 99, `toolchain`, `Inspect the first Android NDK failure, correct the ndk missing, and rerun the failed step.`, `NDK not configured|No version of NDK matched the requested version|NDK .* did not have a source\.properties file`),
		ossRule(`eco-extra-github-rate`, model.CategoryResourceExhaustion, `GitHub API`, `api`, `rate-limit-exceeded`, 90, `resource`, `Inspect the first GitHub API failure, correct the rate limit exceeded, and rerun the failed step.`, `API rate limit exceeded for|You have exceeded a secondary rate limit`),
		ossRule(`eco-extra-github-branch-protection`, model.CategoryCodeFailure, `GitHub`, `push`, `branch-protection-rejected`, -96, `deterministic`, `Inspect the first GitHub failure, correct the branch protection rejected, and rerun the failed step.`, `GH006: Protected branch update failed|GH013: Repository rule violations found(?s:.*)(?:required status check|protected branch|cannot force-push|changes must be made through a pull request)`),
		ossRule(`eco-extra-github-secret-scanning`, model.CategoryCodeFailure, `GitHub Push Protection`, `push`, `secret-detected`, -99, `deterministic`, `Inspect the first GitHub Push Protection failure, correct the secret detected, and rerun the failed step.`, `GH013: Repository rule violations found(?s:.*)Push cannot contain secrets|push declined due to repository rule violations(?s:.*)secret`),
	}
}
