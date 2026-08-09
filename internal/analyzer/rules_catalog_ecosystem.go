package analyzer

func catalogEcosystemRules() []catalogRuleSpec {
	rules := make([]catalogRuleSpec, 0, 245)
	rules = append(rules, catalogEcosystemRules1()...)
	rules = append(rules, catalogEcosystemRules2()...)
	rules = append(rules, catalogEcosystemRules3()...)
	rules = append(rules, catalogEcosystemRules4()...)
	return rules
}
