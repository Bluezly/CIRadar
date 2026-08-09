package analyzer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestLargeLogHintIndexKeepsNonDiagnosticMatches(t *testing.T) {
	rule := Rule{ID: "hidden-single-line", Category: model.CategoryCodeFailure, Patterns: []*regexp.Regexp{re(`RARE_TOKEN\s+status\s+42`)}}
	var log strings.Builder
	for i := 0; i < 4000; i++ {
		log.WriteString("ordinary build output completed\n")
	}
	log.WriteString("RARE_TOKEN status 42\n")
	for i := 0; i < 4000; i++ {
		log.WriteString("ordinary build output completed\n")
	}
	if !matchesRule(rule, log.String()) {
		t.Fatal("large-log hint index dropped a valid single-line match")
	}
}

func TestLargeLogMatcherFallsBackForMultilineRules(t *testing.T) {
	rule := Rule{ID: "hidden-multiline", Category: model.CategoryCodeFailure, Patterns: []*regexp.Regexp{re(`BEGIN-COMPARE(?s:.*?)END-COMPARE`)}}
	var log strings.Builder
	for i := 0; i < 4000; i++ {
		log.WriteString("ordinary build output completed\n")
	}
	log.WriteString("BEGIN-COMPARE\n")
	for i := 0; i < 100; i++ {
		log.WriteString("neutral comparison payload\n")
	}
	log.WriteString("END-COMPARE\n")
	for i := 0; i < 4000; i++ {
		log.WriteString("ordinary build output completed\n")
	}
	if !matchesRule(rule, log.String()) {
		t.Fatal("large-log matcher failed to fall back for a multiline rule")
	}
}
