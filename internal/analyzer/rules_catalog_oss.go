package analyzer

import (
	"strings"

	"github.com/Bluezly/CIRadar/internal/model"
)

func ossRule(id string, category model.Category, provider, operation, family string, weight int, signalGroup, recommendation, pattern string) catalogRuleSpec {
	return catalogRuleSpec{
		id:             id,
		category:       category,
		provider:       provider,
		operation:      operation,
		errorFamily:    family,
		weight:         weight,
		signalGroup:    signalGroup,
		summary:        provider + " failure: " + strings.ReplaceAll(family, "-", " "),
		recommendation: recommendation,
		pattern:        pattern,
	}
}

func catalogOSSRules() []catalogRuleSpec {
	rules := make([]catalogRuleSpec, 0, 175)
	rules = append(rules, catalogOSSCIRules()...)
	rules = append(rules, catalogOSSLanguageRules()...)
	rules = append(rules, catalogOSSInfrastructureRules()...)
	rules = append(rules, catalogOSSDataRules()...)
	return rules
}
