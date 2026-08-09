package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestClassificationCanUseRawLogAfterSafeRedaction(t *testing.T) {
	tests := []struct {
		name      string
		log       string
		category  model.Category
		provider  string
		family    string
		matchedID string
	}{
		{name: "rubygems certificate url", log: "Could not verify the SSL certificate for https://rubygems.org/quick/Marshal.4.8/rake.gemspec.rz. certificate verify failed", category: model.CategoryNetworkFailure, provider: "RubyGems", family: "certificate-verification-failed", matchedID: "eco-ruby-rubygems-cert"},
		{name: "pypi retry timeout", log: "WARNING: Retrying (Retry(total=4)) after connection broken by 'ReadTimeoutError(HTTPSConnectionPool(host='pypi.org', port=443): Read timed out.)': /simple/requests/", category: model.CategoryNetworkFailure, provider: "PyPI", family: "registry-connectivity", matchedID: "pypi-network"},
		{name: "git lfs batch auth", log: "batch response: Authentication required: Authorization error: https://github.com/org/repo.git/info/lfs/objects/batch", category: model.CategoryCodeFailure, provider: "Git LFS", family: "lfs-authentication-failure", matchedID: "git-lfs-auth"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: "org/repo", Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.family {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
			found := false
			for _, id := range r.MatchedRules {
				if id == tt.matchedID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected %s in matches, got %v", tt.matchedID, r.MatchedRules)
			}
		})
	}
}
