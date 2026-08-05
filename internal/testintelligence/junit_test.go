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
