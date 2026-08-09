package analyzer

func catalogModernRules() []catalogRuleSpec {
	rules := make([]catalogRuleSpec, 0, 126)
	rules = append(rules, catalogModernRules1()...)
	rules = append(rules, catalogModernRules2()...)
	return rules
}
