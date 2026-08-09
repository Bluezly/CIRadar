package testintelligence

import (
	"strings"
	"testing"
)

func TestParseJUnit(t *testing.T) {
	xml := `<testsuites><testsuite name="unit"><testcase classname="Calc" name="adds[1,2]" time="0.12"/><testcase classname="Calc" name="fails"><failure message="want 2 got 3">stack</failure></testcase><testcase name="skip"><skipped message="later"/></testcase></testsuite></testsuites>`
	o, e := ParseJUnit(strings.NewReader(xml), Metadata{Repository: "acme/api", Framework: "junit"})
	if e != nil {
		t.Fatal(e)
	}
	if len(o) != 3 || o[0].Status != "passed" || o[1].Status != "failed" || o[2].Status != "skipped" {
		t.Fatalf("%+v", o)
	}
	if o[0].Name != "adds" || o[0].Parameters != "[1,2]" {
		t.Fatalf("params %+v", o[0])
	}
}
func TestRejectEmpty(t *testing.T) {
	_, e := ParseJUnit(strings.NewReader(`<testsuite/>`), Metadata{Repository: "x/y"})
	if e == nil {
		t.Fatal("expected error")
	}
}

func TestJUnitDurationRejectsNonFiniteAndNegativeValues(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-1", "not-a-number"} {
		xml := `<testsuite><testcase name="test" time="` + value + `"/></testsuite>`
		observations, err := ParseJUnit(strings.NewReader(xml), Metadata{Repository: "acme/api"})
		if err != nil {
			t.Fatalf("value=%q err=%v", value, err)
		}
		if len(observations) != 1 || observations[0].DurationMS != 0 {
			t.Fatalf("value=%q observations=%+v", value, observations)
		}
	}
}

func TestParseJUnitRedactsSecretsAndSanitizesRunURL(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("a", 32)
	report := `<testsuite name="unit"><testcase name="payment"><failure message="token=` + token + `">Authorization: Bearer secret-value-1234567890</failure></testcase></testsuite>`
	observations, err := ParseJUnit(strings.NewReader(report), Metadata{Repository: "acme/api", RunURL: "https://user:password@ci.example/runs/7?token=secret#logs"})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("observations=%d", len(observations))
	}
	got := observations[0]
	if strings.Contains(got.Message+got.Details, "ghp_") || strings.Contains(got.Message+got.Details, "secret-value") {
		t.Fatalf("secret leaked: message=%q details=%q", got.Message, got.Details)
	}
	if got.RunURL != "https://ci.example/runs/7" {
		t.Fatalf("run_url=%q", got.RunURL)
	}
}

func TestSanitizeRunURLRejectsUnsafeSchemes(t *testing.T) {
	for _, value := range []string{"javascript:alert(1)", "data:text/html,boom", "/relative/path", "not a url"} {
		if got := sanitizeRunURL(value); got != "" {
			t.Fatalf("sanitizeRunURL(%q)=%q", value, got)
		}
	}
}
