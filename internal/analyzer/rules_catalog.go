package analyzer

import (
	"regexp"

	"github.com/Bluezly/CIRadar/internal/model"
)

type catalogRuleSpec struct {
	id             string
	category       model.Category
	provider       string
	operation      string
	errorFamily    string
	weight         int
	signalGroup    string
	summary        string
	recommendation string
	pattern        string
}

func catalogRules() []Rule {
	specs := make([]catalogRuleSpec, 0, 473)
	specs = append(specs, catalogNetworkRules()...)
	specs = append(specs, catalogLanguageRules()...)
	specs = append(specs, catalogBackendRules()...)
	specs = append(specs, catalogInfrastructureRules()...)
	specs = append(specs, catalogMainframeRules()...)
	specs = append(specs, catalogCIRules()...)
	specs = append(specs, catalogRealWorldRules()...)
	specs = append(specs, catalogOSSRules()...)
	rules := make([]Rule, 0, len(specs))
	for _, spec := range specs {
		rules = append(rules, Rule{ID: spec.id, Category: spec.category, Provider: spec.provider, Operation: spec.operation, ErrorFamily: spec.errorFamily, Summary: spec.summary, Recommendation: spec.recommendation, Weight: spec.weight, SignalGroup: spec.signalGroup, Patterns: []*regexp.Regexp{re(spec.pattern)}})
	}
	return rules
}
