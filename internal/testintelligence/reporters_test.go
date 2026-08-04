package testintelligence

import (
	"strings"
	"testing"
)

func TestNativeReporters(t *testing.T) {
	meta := Metadata{Repository: "acme/api"}
	cases := []struct{ format, body, wantFile string }{
		{"playwright", `{"suites":[{"title":"auth","specs":[{"title":"logs in","file":"tests/auth.spec.ts","tests":[{"status":"unexpected","projectName":"chromium","results":[{"duration":100,"error":{"message":"locator timed out"}}]}]}]}]}`, "tests/auth.spec.ts"},
		{"jest", `{"testResults":[{"name":"src/a.test.ts","assertionResults":[{"ancestorTitles":["A"],"title":"works","status":"failed","duration":4,"failureMessages":["Expected 1"]}]}]}`, "src/a.test.ts"},
		{"pytest", `{"tests":[{"nodeid":"tests/test_a.py::TestA::test_ok","outcome":"failed","duration":0.2,"call":{"longrepr":"timeout waiting"}}]}`, "tests/test_a.py"},
		{"cypress", `{"results":[{"spec":{"relative":"cypress/e2e/a.cy.ts"},"tests":[{"title":["A","works"],"state":"failed","attempts":[{"state":"failed","error":{"message":"element not found"},"timings":{"duration":12}}]}]}]}`, "cypress/e2e/a.cy.ts"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			v, e := ParseReport(tc.format, strings.NewReader(tc.body), meta)
			if e != nil {
				t.Fatal(e)
			}
			if len(v) != 1 || v[0].File != tc.wantFile || v[0].Status != "failed" {
				t.Fatalf("unexpected %#v", v)
			}
		})
	}
}
func TestInferFlakeCause(t *testing.T) {
	v, _ := ParseReport("playwright", strings.NewReader(`{"suites":[{"title":"ui","specs":[{"title":"button","file":"a.ts","tests":[{"status":"unexpected","results":[{"error":{"message":"locator timed out waiting for element"}}]}]}]}]}`), Metadata{Repository: "a/b"})
	cause, confidence := InferFlakeCause(v[0])
	if cause != "selector" || confidence <= 0 {
		t.Fatalf("%s %f", cause, confidence)
	}
}
