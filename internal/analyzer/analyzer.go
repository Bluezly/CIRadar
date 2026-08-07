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
	"time"

	"ciradar/internal/model"
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
	redactor            *Redactor
	fingerprintKey      []byte
	maxExcerpt          int
	configurationDigest string
}

func New(fingerprintKey string, extraRules ...Rule) *Analyzer {
	return NewConfigured(fingerprintKey, nil, true, extraRules...)
}

func NewConfigured(fingerprintKey string, redactionPatterns []string, entropyDetection bool, extraRules ...Rule) *Analyzer {
	rules := BuiltinRules()
	rules = append(rules, extraRules...)
	return &Analyzer{rules: rules, redactor: NewRedactorWithPatterns(redactionPatterns, entropyDetection), fingerprintKey: []byte(strings.TrimSpace(fingerprintKey)), maxExcerpt: 5000, configurationDigest: configurationDigest(rules, redactionPatterns, entropyDetection)}
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

	matched := make([]Rule, 0, 4)
	for _, rule := range a.rules {
		if matchesRule(rule, redacted) {
			matched = append(matched, rule)
		}
	}

	primary := Rule{ID: "unknown", Category: model.CategoryUnknown, Provider: "unknown", Operation: "unknown", ErrorFamily: "unknown", Summary: "The failure could not be classified safely", Recommendation: "Inspect the first deterministic error and collect another run before changing infrastructure or dependencies."}
	if len(matched) > 0 {
		sort.SliceStable(matched, func(i, j int) bool { return abs(matched[i].Weight) > abs(matched[j].Weight) })
		primary = matched[0]
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
	excerpt := extractExcerpt(redacted, matched, a.maxExcerpt)

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
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(material)
		return hex.EncodeToString(mac.Sum(nil)[:16])
	}
	h := sha256.Sum256(material)
	return hex.EncodeToString(h[:16])
}

func matchesRule(rule Rule, log string) bool {
	for _, ex := range rule.Excludes {
		if ex.MatchString(log) {
			return false
		}
	}
	for _, p := range rule.Patterns {
		if p.MatchString(log) {
			return true
		}
	}
	return false
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

func extractExcerpt(log string, matched []Rule, max int) string {
	if log == "" {
		return ""
	}
	idx := -1
	for _, rule := range matched {
		for _, p := range rule.Patterns {
			if loc := p.FindStringIndex(log); loc != nil && (idx < 0 || loc[0] < idx) {
				idx = loc[0]
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
