package analyzer

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

type matchView struct {
	text string
}

type matchLogSet struct {
	fast      []matchView
	full      []matchView
	hintLines map[string][]string
}

type literalNode struct {
	next [128]int32
	fail int32
	out  []string
}

type literalMatcher struct {
	nodes []literalNode
}

type patternMatchHint struct {
	literals  []string
	multiline bool
}

type rulePatternHints struct {
	patterns []patternMatchHint
	excludes []patternMatchHint
}

func newLiteralMatcher(hints []rulePatternHints) *literalMatcher {
	m := &literalMatcher{nodes: []literalNode{{}}}
	seen := make(map[string]struct{})
	add := func(hint string) {
		if hint == "" {
			return
		}
		if _, ok := seen[hint]; ok {
			return
		}
		seen[hint] = struct{}{}
		state := int32(0)
		for i := 0; i < len(hint); i++ {
			b := hint[i]
			if b >= 128 {
				return
			}
			next := m.nodes[state].next[b]
			if next == 0 {
				next = int32(len(m.nodes))
				m.nodes = append(m.nodes, literalNode{})
				m.nodes[state].next[b] = next
			}
			state = next
		}
		m.nodes[state].out = append(m.nodes[state].out, hint)
	}
	for _, ruleHints := range hints {
		for _, patternHints := range ruleHints.patterns {
			for _, hint := range patternHints.literals {
				add(hint)
			}
		}
		for _, excludeHints := range ruleHints.excludes {
			for _, hint := range excludeHints.literals {
				add(hint)
			}
		}
	}
	m.buildFailures()
	return m
}

func (m *literalMatcher) buildFailures() {
	queue := make([]int32, 0, len(m.nodes))
	for b := 0; b < 128; b++ {
		child := m.nodes[0].next[b]
		if child != 0 {
			queue = append(queue, child)
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for b := 0; b < 128; b++ {
			child := m.nodes[state].next[b]
			if child == 0 {
				continue
			}
			fallback := m.nodes[state].fail
			for fallback != 0 && m.nodes[fallback].next[b] == 0 {
				fallback = m.nodes[fallback].fail
			}
			if next := m.nodes[fallback].next[b]; next != 0 && next != child {
				m.nodes[child].fail = next
			}
			if inherited := m.nodes[m.nodes[child].fail].out; len(inherited) > 0 {
				m.nodes[child].out = append(m.nodes[child].out, inherited...)
			}
			queue = append(queue, child)
		}
	}
}

func (m *literalMatcher) findLine(text string, hintLines map[string][]string) {
	if m == nil || len(m.nodes) == 0 {
		return
	}
	state := int32(0)
	var seen []string
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b >= 128 {
			state = 0
			continue
		}
		for state != 0 && m.nodes[state].next[b] == 0 {
			state = m.nodes[state].fail
		}
		if next := m.nodes[state].next[b]; next != 0 {
			state = next
		}
		for _, hint := range m.nodes[state].out {
			duplicate := false
			for _, prior := range seen {
				if prior == hint {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			seen = append(seen, hint)
			hintLines[hint] = append(hintLines[hint], text)
		}
	}
}

func buildRulePatternHints(rules []Rule) []rulePatternHints {
	out := make([]rulePatternHints, len(rules))
	for i, rule := range rules {
		out[i].patterns = make([]patternMatchHint, len(rule.Patterns))
		for j, pattern := range rule.Patterns {
			out[i].patterns[j] = regexMatchHint(pattern)
		}
		out[i].excludes = make([]patternMatchHint, len(rule.Excludes))
		for j, pattern := range rule.Excludes {
			out[i].excludes[j] = regexMatchHint(pattern)
		}
	}
	return out
}

func regexMatchHint(pattern *regexp.Regexp) patternMatchHint {
	if pattern == nil {
		return patternMatchHint{}
	}
	tree, err := syntax.Parse(pattern.String(), syntax.Perl)
	if err != nil {
		return patternMatchHint{}
	}
	tree = tree.Simplify()
	meta := patternMatchHint{multiline: regexpCanMatchNewline(tree)}
	hints, ok := literalCover(tree)
	if !ok || len(hints) == 0 {
		return meta
	}
	for _, hint := range hints {
		if len(hint) < 3 || strings.ContainsAny(hint, "\r\n") {
			return meta
		}
	}
	meta.literals = hints
	return meta
}

func regexpCanMatchNewline(expr *syntax.Regexp) bool {
	switch expr.Op {
	case syntax.OpAnyChar:
		return true
	case syntax.OpLiteral:
		for _, r := range expr.Rune {
			if r == '\n' {
				return true
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(expr.Rune); i += 2 {
			if expr.Rune[i] <= '\n' && '\n' <= expr.Rune[i+1] {
				return true
			}
		}
	}
	for _, sub := range expr.Sub {
		if regexpCanMatchNewline(sub) {
			return true
		}
	}
	return false
}

func literalCover(expr *syntax.Regexp) ([]string, bool) {
	switch expr.Op {
	case syntax.OpLiteral:
		if len(expr.Rune) == 0 {
			return nil, false
		}
		for _, r := range expr.Rune {
			if r > 127 {
				return nil, false
			}
		}
		return []string{strings.ToLower(string(expr.Rune))}, true
	case syntax.OpCapture:
		if len(expr.Sub) != 1 {
			return nil, false
		}
		return literalCover(expr.Sub[0])
	case syntax.OpConcat:
		var best []string
		for _, sub := range expr.Sub {
			candidate, ok := literalCover(sub)
			if !ok {
				continue
			}
			if betterLiteralCover(candidate, best) {
				best = candidate
			}
		}
		if len(best) == 0 {
			return nil, false
		}
		return best, true
	case syntax.OpAlternate:
		merged := make([]string, 0, len(expr.Sub))
		seen := make(map[string]struct{})
		for _, sub := range expr.Sub {
			candidate, ok := literalCover(sub)
			if !ok {
				return nil, false
			}
			for _, hint := range candidate {
				if _, exists := seen[hint]; exists {
					continue
				}
				seen[hint] = struct{}{}
				merged = append(merged, hint)
			}
		}
		return merged, len(merged) > 0
	case syntax.OpPlus:
		if len(expr.Sub) != 1 {
			return nil, false
		}
		return literalCover(expr.Sub[0])
	case syntax.OpRepeat:
		if expr.Min < 1 || len(expr.Sub) != 1 {
			return nil, false
		}
		return literalCover(expr.Sub[0])
	default:
		return nil, false
	}
}

func betterLiteralCover(candidate, current []string) bool {
	if len(candidate) == 0 {
		return false
	}
	if len(current) == 0 {
		return true
	}
	candidateMin := minHintLength(candidate)
	currentMin := minHintLength(current)
	if candidateMin != currentMin {
		return candidateMin > currentMin
	}
	return len(candidate) < len(current)
}

func minHintLength(hints []string) int {
	min := 0
	for _, hint := range hints {
		if min == 0 || len(hint) < min {
			min = len(hint)
		}
	}
	return min
}

func hintMayMatch(hints []string, lines map[string][]string) bool {
	if len(hints) == 0 || lines == nil {
		return true
	}
	for _, hint := range hints {
		if len(lines[hint]) > 0 {
			return true
		}
	}
	return false
}

func regexpMatchesViews(pattern *regexp.Regexp, views []matchView) bool {
	for _, view := range views {
		if pattern.MatchString(view.text) {
			return true
		}
	}
	return false
}

func regexpMatchesHintLines(pattern *regexp.Regexp, hints []string, lines map[string][]string) bool {
	for _, hint := range hints {
		for _, line := range lines[hint] {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func patternMatches(pattern *regexp.Regexp, hint patternMatchHint, logs matchLogSet) bool {
	if logs.hintLines == nil {
		return regexpMatchesViews(pattern, logs.fast)
	}
	if !hintMayMatch(hint.literals, logs.hintLines) {
		return false
	}
	if len(hint.literals) > 0 && !hint.multiline {
		return regexpMatchesHintLines(pattern, hint.literals, logs.hintLines)
	}
	if regexpMatchesViews(pattern, logs.fast) {
		return true
	}
	return regexpMatchesViews(pattern, logs.full)
}

func matchesRuleViews(rule Rule, hints rulePatternHints, logs matchLogSet) bool {
	matched := false
	for i, pattern := range rule.Patterns {
		var patternHint patternMatchHint
		if i < len(hints.patterns) {
			patternHint = hints.patterns[i]
		}
		if patternMatches(pattern, patternHint, logs) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for i, exclude := range rule.Excludes {
		var excludeHint patternMatchHint
		if i < len(hints.excludes) {
			excludeHint = hints.excludes[i]
		}
		if patternMatches(exclude, excludeHint, logs) {
			return false
		}
	}
	return true
}
