package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestRealLogVariantMatching(t *testing.T) {
	tests := []struct {
		name string
		log string
		provider string
		family string
	}{
		{name: "pypi urllib3 timeout", log: "WARNING: Retrying (Retry(total=4)) after connection broken by 'ReadTimeoutError(HTTPSConnectionPool(host='pypi.org', port=443): Read timed out.)': /simple/requests/", provider: "PyPI", family: "registry-connectivity"},
		{name: "pypi pythonhosted dns", log: "HTTPSConnectionPool(host='files.pythonhosted.org', port=443): Max retries exceeded with url: /packages/pkg.whl (Caused by NameResolutionError: Failed to resolve files.pythonhosted.org)", provider: "PyPI", family: "registry-connectivity"},
		{name: "git lfs batch 401", log: "batch response: Authentication required: Authorization error: https://github.com/org/repo.git/info/lfs/objects/batch", provider: "Git LFS", family: "lfs-authentication-failure"},
		{name: "git lfs ansi auth", log: "\x1b[31mgit-lfs: objects/batch returned HTTP 401 credentials rejected\x1b[0m", provider: "Git LFS", family: "lfs-authentication-failure"},
		{name: "smart quotes r package", log: "Error in library(foo) : there is no package called ‘foo’", provider: "R", family: "package-not-found"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: tt.log}, Context{})
			if r.Provider != tt.provider || r.ErrorFamily != tt.family {
				t.Fatalf("got provider=%q family=%q category=%s rules=%v", r.Provider, r.ErrorFamily, r.Category, r.MatchedRules)
			}
		})
	}
}
