package analyzer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

type Context struct {
	CrossRepoCount      int
	CrossOrgCount       int
	RecentOccurrences   int
	ProviderIncident    bool
	PreviousEnvironment *model.Environment
}

type Analyzer struct {
	rules               []Rule
	ruleHintsOnce       sync.Once
	ruleHints           []rulePatternHints
	hintMatcherOnce     sync.Once
	hintMatcher         *literalMatcher
	redactor            *Redactor
	fingerprintKey      []byte
	maxExcerpt          int
	configurationDigest string
	memory              *diagnosticMemory
}

func New(fingerprintKey string, extraRules ...Rule) *Analyzer {
	return NewConfigured(fingerprintKey, nil, true, extraRules...)
}

func NewConfigured(fingerprintKey string, redactionPatterns []string, entropyDetection bool, extraRules ...Rule) *Analyzer {
	rules := BuiltinRules()
	rules = append(rules, extraRules...)
	return &Analyzer{rules: rules, redactor: NewRedactorWithPatterns(redactionPatterns, entropyDetection), fingerprintKey: []byte(strings.TrimSpace(fingerprintKey)), maxExcerpt: 5000, configurationDigest: configurationDigest(rules, redactionPatterns, entropyDetection), memory: newDiagnosticMemory()}
}

func (a *Analyzer) ConfigurationDigest() string {
	if a == nil {
		return ""
	}
	return a.configurationDigest
}

func configurationDigest(rules []Rule, redactionPatterns []string, entropyDetection bool) string {
	type digestRule struct {
		ID             string   `json:"id"`
		Category       string   `json:"category"`
		Provider       string   `json:"provider"`
		Operation      string   `json:"operation"`
		ErrorFamily    string   `json:"error_family"`
		Summary        string   `json:"summary"`
		Recommendation string   `json:"recommendation"`
		Weight         int      `json:"weight"`
		SignalGroup    string   `json:"signal_group"`
		Patterns       []string `json:"patterns"`
		Excludes       []string `json:"excludes"`
	}
	payload := struct {
		Version           int          `json:"version"`
		EntropyDetection  bool         `json:"entropy_detection"`
		RedactionPatterns []string     `json:"redaction_patterns"`
		Rules             []digestRule `json:"rules"`
	}{Version: 1, EntropyDetection: entropyDetection, RedactionPatterns: append([]string(nil), redactionPatterns...), Rules: make([]digestRule, 0, len(rules))}
	for _, rule := range rules {
		d := digestRule{ID: rule.ID, Category: string(rule.Category), Provider: rule.Provider, Operation: rule.Operation, ErrorFamily: rule.ErrorFamily, Summary: rule.Summary, Recommendation: rule.Recommendation, Weight: rule.Weight, SignalGroup: rule.SignalGroup}
		for _, pattern := range rule.Patterns {
			if pattern != nil {
				d.Patterns = append(d.Patterns, pattern.String())
			}
		}
		for _, exclude := range rule.Excludes {
			if exclude != nil {
				d.Excludes = append(d.Excludes, exclude.String())
			}
		}
		payload.Rules = append(payload.Rules, d)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (a *Analyzer) RuleIDs() []string {
	if a == nil {
		return nil
	}
	ids := make([]string, 0, len(a.rules))
	for _, rule := range a.rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}

func (a *Analyzer) Analyze(in model.AnalysisInput, ctx Context) model.AnalysisResult {
	now := time.Now().UTC()
	if !in.OccurredAt.IsZero() {
		now = in.OccurredAt.UTC()
	}
	redacted := a.redactor.Redact(in.Log)
	env := ExtractEnvironment(redacted)

	matchLogs := a.prepareMatchLogs(redacted, in.Log)
	matched := make([]Rule, 0, 4)
	for i, rule := range a.rules {
		var hints rulePatternHints
		if matchLogs.hintLines != nil {
			hints = a.ruleHints[i]
		}
		if matchesRuleViews(rule, hints, matchLogs) {
			matched = append(matched, rule)
		}
	}

	primary := Rule{ID: "unknown", Category: model.CategoryUnknown, Provider: "unknown", Operation: "unknown", ErrorFamily: "unknown", Summary: "The failure could not be classified safely", Recommendation: "Inspect the first deterministic error and collect another run before changing infrastructure or dependencies."}
	if len(matched) > 0 {
		sort.SliceStable(matched, func(i, j int) bool { return abs(matched[i].Weight) > abs(matched[j].Weight) })
		primary = matched[0]
	}

	observed := findObservedFailure(redacted, matched)
	if observed.Message != "" && primary.Category == model.CategoryUnknown {
		primary.Summary = "Unclassified CI failure — " + observed.Message
		primary.Recommendation = "Start with the observed failure shown in the diagnosis, then inspect the surrounding redacted excerpt before changing infrastructure or dependencies."
	}

	norm := normalizeForFingerprint(redacted, primary)
	fingerprint := fingerprintValue(a.fingerprintKey, []byte(norm))
	privateMaterial := []byte(tenantID(in.TenantID) + "\x00" + in.Repository + "\x00" + norm)
	privateFP := fingerprintValue(a.fingerprintKey, privateMaterial)

	score := 0
	positiveScore := 0
	negativeScore := 0
	var evidence []model.Evidence
	seenGroups := make(map[string]struct{})
	for _, rule := range matched {
		group := strings.TrimSpace(rule.SignalGroup)
		if group == "" {
			group = rule.ID
		}
		if _, duplicate := seenGroups[group]; duplicate {
			evidence = append(evidence, model.Evidence{Kind: "corroboration", Description: "Corroborating rule " + rule.ID + ": " + rule.Summary, Weight: 0})
			continue
		}
		seenGroups[group] = struct{}{}
		score += rule.Weight
		if rule.Weight > 0 {
			positiveScore += rule.Weight
		} else if rule.Weight < 0 {
			negativeScore += rule.Weight
		}
		evidence = append(evidence, model.Evidence{Kind: "rule", Description: "Matched rule " + rule.ID + ": " + rule.Summary, Weight: rule.Weight})
	}
	if observed.Message != "" {
		evidence = append(evidence, model.Evidence{Kind: "failure", Description: "Observed failure: " + observed.Message, Weight: 0})
	}
	if in.PreviousSuccess {
		score += 15
		positiveScore += 15
		evidence = append(evidence, model.Evidence{Kind: "history", Description: "The same commit or workflow previously succeeded", Weight: 15})
	}
	if in.ChangeInfoAvailable && !in.WorkflowChanged && in.Repository != "" {
		score += 8
		positiveScore += 8
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "No workflow change was reported", Weight: 8})
	}
	if in.ChangeInfoAvailable && !in.DependencyChanged && in.Repository != "" {
		score += 8
		positiveScore += 8
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "No dependency or lockfile change was reported", Weight: 8})
	}
	if in.ChangeInfoAvailable && in.WorkflowChanged {
		score -= 18
		negativeScore -= 18
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "Workflow configuration changed in this revision", Weight: -18})
	}
	if in.ChangeInfoAvailable && in.DependencyChanged {
		score -= 20
		negativeScore -= 20
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "Dependency or lockfile content changed in this revision", Weight: -20})
	}
	if ctx.ProviderIncident {
		score += 40
		positiveScore += 40
		evidence = append(evidence, model.Evidence{Kind: "provider", Description: "The relevant provider reports an active incident or degradation", Weight: 40})
	}
	if ctx.CrossRepoCount >= 3 {
		bonus := 15
		if ctx.CrossRepoCount >= 10 {
			bonus = 25
		}
		if ctx.CrossRepoCount >= 50 {
			bonus = 35
		}
		score += bonus
		positiveScore += bonus
		evidence = append(evidence, model.Evidence{Kind: "correlation", Description: fmt.Sprintf("The same fingerprint appeared in %d repositories", ctx.CrossRepoCount), Weight: bonus})
	}
	if ctx.CrossOrgCount >= 2 {
		bonus := 10
		if ctx.CrossOrgCount >= 5 {
			bonus = 20
		}
		score += bonus
		positiveScore += bonus
		evidence = append(evidence, model.Evidence{Kind: "correlation", Description: fmt.Sprintf("The same fingerprint appeared across %d organizations", ctx.CrossOrgCount), Weight: bonus})
	}
	if ctx.RecentOccurrences >= 5 {
		bonus := 10
		if ctx.RecentOccurrences >= 25 {
			bonus = 18
		}
		score += bonus
		positiveScore += bonus
		evidence = append(evidence, model.Evidence{Kind: "burst", Description: fmt.Sprintf("%d matching failures occurred in the incident window", ctx.RecentOccurrences), Weight: bonus})
	}

	var changes []string
	if ctx.PreviousEnvironment != nil {
		changes = CompareEnvironment(*ctx.PreviousEnvironment, env)
		if len(changes) > 0 {
			score += 22
			positiveScore += 22
			evidence = append(evidence, model.Evidence{Kind: "environment", Description: fmt.Sprintf("%d environment changes were detected since the last successful run", len(changes)), Weight: 22})
			if primary.Category == model.CategoryUnknown {
				primary.Category = model.CategoryRunnerImageDrift
				primary.Provider = "GitHub Actions"
				primary.Operation = "runner-image"
				primary.ErrorFamily = "environment-drift"
				primary.Summary = "The failed run used a changed CI environment"
				primary.Recommendation = "Pin required tools explicitly and review the detected environment changes."
			}
		}
	}
	rawScore := score
	externalEvidenceScore := clampEvidenceScore(positiveScore)
	codeEvidenceScore := clampEvidenceScore(-negativeScore)
	evidenceStrength := externalEvidenceScore
	if codeEvidenceScore > evidenceStrength {
		evidenceStrength = codeEvidenceScore
	}
	competingSignals := positiveScore >= 25 && negativeScore <= -25
	if score > 100 {
		score = 100
	}
	if score < -100 {
		score = -100
	}

	confidence := confidenceFor(score, primary.Category)
	if competingSignals {
		confidence = model.ConfidenceMixed
	}
	attribution := attributionFor(confidence, primary.Category, competingSignals)
	decisionReason := decisionReasonFor(attribution, positiveScore, negativeScore, ctx.ProviderIncident, len(changes) > 0)
	matchedIDs := make([]string, 0, len(matched))
	for _, m := range matched {
		matchedIDs = append(matchedIDs, m.ID)
	}
	excerpt := extractExcerptAt(redacted, matched, observed.Index, a.maxExcerpt)

	result := model.AnalysisResult{
		ID:                    newID("analysis", now, fingerprint),
		TenantID:              tenantID(in.TenantID),
		Category:              primary.Category,
		Attribution:           attribution,
		Provider:              primary.Provider,
		Operation:             primary.Operation,
		ErrorFamily:           primary.ErrorFamily,
		Confidence:            confidence,
		Score:                 score,
		ExternalityScore:      score,
		EvidenceStrength:      evidenceStrength,
		ExternalEvidenceScore: externalEvidenceScore,
		CodeEvidenceScore:     codeEvidenceScore,
		RawScore:              rawScore,
		PositiveScore:         positiveScore,
		NegativeScore:         negativeScore,
		CompetingSignals:      competingSignals,
		DecisionReason:        decisionReason,
		Fingerprint:           fingerprint,
		PrivateFingerprint:    privateFP,
		Summary:               primary.Summary,
		Recommendation:        primary.Recommendation,
		Evidence:              evidence,
		RedactedExcerpt:       excerpt,
		Environment:           env,
		MatchedRules:          matchedIDs,
		CreatedAt:             now,
		CrossRepoCount:        ctx.CrossRepoCount,
		CrossOrgCount:         ctx.CrossOrgCount,
		ProviderIncident:      ctx.ProviderIncident,
		EnvironmentDrift:      len(changes) > 0,
		EnvironmentChanges:    changes,
	}
	result.SuggestedActions = SuggestedActions(result)
	return result
}

func (a *Analyzer) prepareMatchLogs(logs ...string) matchLogSet {
	large := false
	for _, log := range logs {
		if len(log) > maxDirectMatchLogBytes {
			large = true
			break
		}
	}
	if !large {
		return prepareMatchLogs(nil, logs...)
	}
	a.ruleHintsOnce.Do(func() {
		a.ruleHints = buildRulePatternHints(a.rules)
	})
	a.hintMatcherOnce.Do(func() {
		a.hintMatcher = newLiteralMatcher(a.ruleHints)
	})
	return prepareMatchLogs(a.hintMatcher, logs...)
}

func clampEvidenceScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func fingerprintValue(key, material []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(material)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

var (
	ansiCSIRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSCRe = regexp.MustCompile(`\x1b\][^\x07]*(?:\x07|\x1b\\)`)
)

func canonicalMatchLog(log string) string {
	s := strings.ReplaceAll(log, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = ansiCSIRe.ReplaceAllString(s, "")
	s = ansiOSCRe.ReplaceAllString(s, "")
	replacer := strings.NewReplacer(
		"\u00a0", " ",
		"\u200b", "",
		"\u200c", "",
		"\u200d", "",
		"\ufeff", "",
		"‘", "'",
		"’", "'",
		"“", `"`,
		"”", `"`,
	)
	return replacer.Replace(s)
}

const maxDirectMatchLogBytes = 96 * 1024

var diagnosticTerms = []string{
	"error", "fail", "fatal", "panic", "exception", "warn", "timed out", "timeout",
	"denied", "forbidden", "unauthorized", "not found", "cannot", "could not", "unable",
	"invalid", "mismatch", "expected", "actual", "refused", "reset by peer", "unreachable",
	"terminated", "killed", "exit code", "segmentation", "out of memory", "no space left",
	"permission", "unsupported", "deprecated", "assert", "result:", "results:", "diff",
}

func isDiagnosticLine(line string) bool {
	lower := strings.ToLower(line)
	trimmed := strings.TrimSpace(lower)
	if strings.HasPrefix(trimmed, "--- ") || strings.HasPrefix(trimmed, "+++ ") || strings.HasPrefix(trimmed, "\\--- ") {
		return true
	}
	for _, term := range diagnosticTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func compactMatchLog(log string) string {
	if len(log) <= maxDirectMatchLogBytes {
		return log
	}

	normalized := strings.ReplaceAll(log, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	selected := make([]bool, len(lines))
	markRange := func(start, end int) {
		if start < 0 {
			start = 0
		}
		if end >= len(lines) {
			end = len(lines) - 1
		}
		for i := start; i <= end; i++ {
			selected[i] = true
		}
	}

	markRange(0, 63)
	markRange(len(lines)-96, len(lines)-1)
	for i, line := range lines {
		if isDiagnosticLine(line) {
			markRange(i-4, i+12)
		}
	}

	var b strings.Builder
	b.Grow(maxDirectMatchLogBytes)
	previous := -2
	for i, line := range lines {
		if !selected[i] {
			continue
		}
		if previous >= 0 && i != previous+1 {
			b.WriteString("\n... omitted log lines ...\n")
		}
		b.WriteString(line)
		b.WriteByte('\n')
		previous = i
	}
	return b.String()
}

func prepareMatchLogs(matcher *literalMatcher, logs ...string) matchLogSet {
	prepared := matchLogSet{}
	if matcher != nil {
		prepared.hintLines = make(map[string][]string)
	}
	fastSeen := make(map[string]struct{}, len(logs)*2)
	fullSeen := make(map[string]struct{}, len(logs)*2)
	addView := func(dst *[]matchView, seen map[string]struct{}, text string, collectHints bool) {
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		*dst = append(*dst, matchView{text: text})
		seen[text] = struct{}{}
		if collectHints && matcher != nil {
			for _, line := range strings.Split(text, "\n") {
				matcher.findLine(line, prepared.hintLines)
			}
		}
	}
	for _, log := range logs {
		if log == "" {
			continue
		}
		if matcher == nil {
			addView(&prepared.fast, fastSeen, log, false)
			addView(&prepared.fast, fastSeen, canonicalMatchLog(log), false)
			continue
		}
		addView(&prepared.full, fullSeen, log, true)
		addView(&prepared.full, fullSeen, canonicalMatchLog(log), true)
		matchLog := compactMatchLog(log)
		addView(&prepared.fast, fastSeen, matchLog, false)
		addView(&prepared.fast, fastSeen, canonicalMatchLog(matchLog), false)
	}
	return prepared
}

func matchesRule(rule Rule, log string) bool {
	if len(log) <= maxDirectMatchLogBytes {
		return matchesRuleViews(rule, rulePatternHints{}, prepareMatchLogs(nil, log))
	}
	hints := buildRulePatternHints([]Rule{rule})
	matcher := newLiteralMatcher(hints)
	return matchesRuleViews(rule, hints[0], prepareMatchLogs(matcher, log))
}

func confidenceFor(score int, category model.Category) model.Confidence {
	if category == model.CategoryCodeFailure && score <= 0 {
		return model.ConfidenceLikelyCode
	}
	if category == model.CategoryToolchainFailure && score >= 30 {
		return model.ConfidenceModerate
	}
	if score >= 75 {
		return model.ConfidenceStrong
	}
	if score >= 45 {
		return model.ConfidenceModerate
	}
	if score >= 20 {
		return model.ConfidenceMixed
	}
	if score < 0 {
		return model.ConfidenceLikelyCode
	}
	return model.ConfidenceInsufficient
}

func tenantID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return model.DefaultTenantID
	}
	return v
}

func attributionFor(conf model.Confidence, category model.Category, competing bool) model.Attribution {
	if competing || conf == model.ConfidenceMixed {
		return model.AttributionMixed
	}
	if category == model.CategoryToolchainFailure {
		return model.AttributionToolchain
	}
	if conf == model.ConfidenceLikelyCode || category == model.CategoryCodeFailure {
		return model.AttributionCode
	}
	if conf == model.ConfidenceStrong || conf == model.ConfidenceModerate {
		return model.AttributionExternal
	}
	return model.AttributionUnknown
}

func decisionReasonFor(a model.Attribution, positive, negative int, providerIncident, drift bool) string {
	parts := []string{fmt.Sprintf("external evidence %+d", positive), fmt.Sprintf("code evidence %+d", negative)}
	if providerIncident {
		parts = append(parts, "provider incident active")
	}
	if drift {
		parts = append(parts, "environment drift detected")
	}
	return fmt.Sprintf("%s attribution: %s", a, strings.Join(parts, "; "))
}

var (
	timestampRe = regexp.MustCompile(`(?m)^\s*(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s*|\[\d{2}:\d{2}:\d{2}\]\s*)`)
	uuidRe      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	hexRe       = regexp.MustCompile(`(?i)\b[0-9a-f]{12,64}\b`)
	lineNumRe   = regexp.MustCompile(`(?m)(:\d+)(:\d+)?`)
	numberRe    = regexp.MustCompile(`\b\d{4,}\b`)
	spaceRe     = regexp.MustCompile(`[ \t]+`)
)

func normalizeForFingerprint(log string, primary Rule) string {
	s := log
	if len(s) > 100_000 {
		s = s[len(s)-100_000:]
	}
	s = timestampRe.ReplaceAllString(s, "")
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = hexRe.ReplaceAllString(s, "<hex>")
	s = lineNumRe.ReplaceAllString(s, ":<line>")
	s = numberRe.ReplaceAllString(s, "<num>")
	s = spaceRe.ReplaceAllString(s, " ")
	lines := strings.Split(s, "\n")
	selected := make([]string, 0, 16)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "fail") || strings.Contains(strings.ToLower(line), "exception") || anyPattern(primary.Patterns, line) {
			selected = append(selected, line)
		}
		if len(selected) >= 16 {
			break
		}
	}
	if len(selected) == 0 {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				selected = append(selected, line)
			}
			if len(selected) >= 8 {
				break
			}
		}
	}
	return strings.ToLower(primary.Provider + "|" + primary.Operation + "|" + primary.ErrorFamily + "|" + strings.Join(selected, "\n"))
}

type observedFailure struct {
	Message string
	Index   int
	Score   int
}

const maxObservedFailureRunes = 360

func findObservedFailure(log string, matched []Rule) observedFailure {
	if strings.TrimSpace(log) == "" {
		return observedFailure{Index: -1}
	}
	best := observedFailure{Index: -1, Score: -1}
	offset := 0
	for _, rawLine := range strings.SplitAfter(log, "\n") {
		line := strings.TrimSuffix(rawLine, "\n")
		cleaned := cleanObservedFailureLine(line)
		if cleaned == "" {
			offset += len(rawLine)
			continue
		}
		score := observedFailureScore(line, matched)
		if score > best.Score || (score == best.Score && score >= 0 && offset > best.Index) {
			best = observedFailure{Message: cleaned, Index: offset, Score: score}
		}
		offset += len(rawLine)
	}
	if best.Score < 0 {
		return observedFailure{Index: -1}
	}
	return best
}

func cleanObservedFailureLine(line string) string {
	line = timestampRe.ReplaceAllString(line, "")
	line = strings.TrimSpace(line)
	for strings.HasPrefix(line, "> ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, ">"))
	}
	for _, prefix := range []string{"##[error]", "::error::", "[error]", "ERROR:", "Error:"} {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
			trimmed := strings.TrimSpace(line[len(prefix):])
			if trimmed != "" {
				line = trimmed
			}
			break
		}
	}
	line = strings.Join(strings.Fields(line), " ")
	if line == "" {
		return ""
	}
	runes := []rune(line)
	if len(runes) > maxObservedFailureRunes {
		line = string(runes[:maxObservedFailureRunes-1]) + "…"
	}
	return line
}

func observedFailureScore(line string, matched []Rule) int {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return -1
	}

	score := 0
	for _, rule := range matched {
		for _, pattern := range rule.Patterns {
			if pattern != nil && pattern.MatchString(line) {
				score += 220
				break
			}
		}
	}

	for _, signal := range []struct {
		Text  string
		Score int
	}{
		{"caused by:", 190},
		{"could not find", 180},
		{"cannot find", 175},
		{"failed to resolve", 170},
		{"unable to resolve", 170},
		{"no such file or directory", 165},
		{"undefined reference", 160},
		{"undefined:", 155},
		{"permission denied", 150},
		{"connection refused", 150},
		{"not found", 145},
		{"timed out", 140},
		{"timeout", 130},
		{"panic:", 145},
		{"fatal:", 140},
		{"exception", 125},
		{"failed to", 120},
		{"could not", 120},
		{"cannot", 115},
		{"unable to", 115},
		{"error:", 115},
		{"error ", 105},
		{"rejected", 100},
		{"mismatch", 95},
		{"invalid", 90},
		{"denied", 90},
	} {
		if strings.Contains(lower, signal.Text) {
			score += signal.Score
			break
		}
	}

	switch {
	case strings.Contains(lower, "process completed with exit code"):
		score = max(score, 25)
		score -= 140
	case strings.Contains(lower, "command failed with exit code"):
		score = max(score, 30)
		score -= 110
	case lower == "build failed" || strings.HasPrefix(lower, "build failed in "):
		score = max(score, 20)
		score -= 100
	case strings.Contains(lower, "failure: build failed with an exception"):
		score = max(score, 15)
		score -= 150
	case lower == "* what went wrong:" || lower == "what went wrong:":
		score -= 150
	case strings.HasPrefix(lower, "run with --stacktrace") || strings.HasPrefix(lower, "run with --info") || strings.HasPrefix(lower, "run with --scan"):
		score -= 140
	case strings.HasPrefix(lower, "get more help at "):
		score -= 140
	}

	if score <= 0 && isDiagnosticLine(line) {
		score = 20
	}
	if score <= 0 {
		return -1
	}
	return score
}

func extractExcerptAt(log string, matched []Rule, observedIndex, max int) string {
	if log == "" {
		return ""
	}
	idx := observedIndex
	if idx < 0 {
		for _, rule := range matched {
			for _, p := range rule.Patterns {
				if loc := p.FindStringIndex(log); loc != nil && (idx < 0 || loc[0] < idx) {
					idx = loc[0]
				}
			}
		}
	}
	if idx < 0 {
		idx = len(log) - max
	}
	start := idx - max/3
	if start < 0 {
		start = 0
	}
	end := start + max
	if end > len(log) {
		end = len(log)
	}
	return strings.TrimSpace(log[start:end])
}

func anyPattern(patterns []*regexp.Regexp, line string) bool {
	for _, p := range patterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

func newID(prefix string, t time.Time, seed string) string {
	h := sha256.Sum256([]byte(prefix + t.Format(time.RFC3339Nano) + seed))
	return prefix + "_" + hex.EncodeToString(h[:8])
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
