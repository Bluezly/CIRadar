package analyzer

import (
	"fmt"
	"strings"

	"ciradar/internal/model"
)

func SuggestedActions(result model.AnalysisResult) []model.SuggestedAction {
	seen := map[string]struct{}{}
	out := make([]model.SuggestedAction, 0, 4)
	add := func(a model.SuggestedAction) {
		if _, ok := seen[a.ID]; ok {
			return
		}
		seen[a.ID] = struct{}{}
		out = append(out, a)
	}

	for _, id := range result.MatchedRules {
		switch {
		case strings.Contains(id, "econnreset"), strings.Contains(id, "network"), strings.Contains(id, "dns"), strings.Contains(id, "tls"):
			add(model.SuggestedAction{ID: "verify-connectivity", Type: "VERIFY", Title: "Verify provider and runner connectivity", Description: "Check provider status, DNS, TLS interception, and runner egress before changing dependencies.", Risk: "SAFE"})
		case strings.Contains(id, "rate-limit"):
			add(model.SuggestedAction{ID: "backoff-rate-limit", Type: "RETRY", Title: "Retry with backoff", Description: "Wait for the provider rate-limit window, then retry once with bounded exponential backoff.", Risk: "SAFE", Automatic: true})
		case strings.Contains(id, "cache"):
			add(model.SuggestedAction{ID: "clean-cache", Type: "CLEAN_CACHE", Title: "Retry with a clean cache", Description: "Invalidate only the affected cache key or use a fresh runner. Avoid deleting unrelated shared caches.", Risk: "REVIEW_REQUIRED"})
		case strings.Contains(id, "disk"), strings.Contains(id, "memory"), strings.Contains(id, "resource"):
			add(model.SuggestedAction{ID: "increase-resource", Type: "INCREASE_RESOURCE", Title: "Inspect and raise resource limits", Description: "Capture disk and memory telemetry, remove unnecessary artifacts, or move the job to a larger runner.", Risk: "REVIEW_REQUIRED"})
		case strings.Contains(id, "auth"), strings.Contains(id, "permission"), strings.Contains(id, "forbidden"):
			add(model.SuggestedAction{ID: "fix-auth", Type: "FIX_CONFIGURATION", Title: "Validate credentials and scopes", Description: "Rotate the affected credential if needed and verify repository, registry, and workflow permissions.", Risk: "REVIEW_REQUIRED"})
		case strings.Contains(id, "version"), strings.Contains(id, "resolution"), strings.Contains(id, "manifest"), strings.Contains(id, "lock"):
			add(model.SuggestedAction{ID: "review-dependency-constraints", Type: "PIN", Title: "Review dependency constraints", Description: "Compare lockfiles and runtime compatibility, then pin or loosen only the conflicting dependency.", Risk: "REVIEW_REQUIRED"})
		case strings.Contains(id, "runner"):
			add(model.SuggestedAction{ID: "retry-runner", Type: "RETRY", Title: "Retry on a fresh runner", Description: "Retry once on a new runner and compare the runner image and tool versions with the last successful run.", Risk: "SAFE", Automatic: true})
		case strings.Contains(id, "test-flake"):
			add(model.SuggestedAction{ID: "isolate-flaky-test", Type: "VERIFY", Title: "Isolate and repeat the test", Description: "Run the test repeatedly with the same commit and environment; quarantine only after a measured flake history exists.", Risk: "SAFE"})
		case strings.Contains(id, "compiler"), strings.Contains(id, "assertion"), strings.Contains(id, "syntax"):
			add(model.SuggestedAction{ID: "fix-first-error", Type: "FIX_CONFIGURATION", Title: "Fix the first deterministic error", Description: "Start with the first compiler or assertion error. Later errors may be cascading failures.", Risk: "REVIEW_REQUIRED"})
		case strings.Contains(id, "internal") || strings.Contains(id, "panic"):
			add(model.SuggestedAction{ID: "toolchain-reproduce", Type: "VERIFY", Title: "Reproduce the toolchain failure", Description: "Pin the tool version, reproduce with a minimal command, and upgrade or report the tool defect with the stack trace.", Risk: "SAFE"})
		}
	}

	if result.ProviderIncident {
		add(model.SuggestedAction{ID: "wait-provider", Type: "CONTACT_PROVIDER", Title: "Track the provider incident", Description: fmt.Sprintf("The %s provider reports an active incident. Avoid speculative code changes and retry after recovery.", result.Provider), Risk: "SAFE"})
	}
	if result.EnvironmentDrift {
		add(model.SuggestedAction{ID: "pin-environment", Type: "PIN", Title: "Pin the changed CI environment", Description: "Review the detected runner, action, container, and tool changes; pin critical versions where reproducibility matters.", Risk: "REVIEW_REQUIRED"})
	}
	if result.Attribution == model.AttributionExternal && result.Score >= 75 {
		add(model.SuggestedAction{ID: "safe-retry", Type: "RETRY", Title: "Retry the failed job once", Description: "Evidence strongly favors an external or transient cause. Retry once and stop automatic retries if the same failure repeats.", Risk: "SAFE", Automatic: true})
	}
	if len(out) == 0 {
		add(model.SuggestedAction{ID: "collect-evidence", Type: "VERIFY", Title: "Collect more evidence", Description: "Preserve the first deterministic error, compare with a successful run, and avoid broad configuration changes until attribution improves.", Risk: "SAFE"})
	}
	return out
}
