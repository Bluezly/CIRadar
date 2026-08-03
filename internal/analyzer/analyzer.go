package analyzer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	rules      []Rule
	redactor   *Redactor
	privateKey []byte
	maxExcerpt int
}

func New(privateKey string, extraRules ...Rule) *Analyzer {
	if privateKey == "" {
		privateKey = "ciradar-local-development-key"
	}
	rules := BuiltinRules()
	rules = append(rules, extraRules...)
	return &Analyzer{rules: rules, redactor: NewRedactor(), privateKey: []byte(privateKey), maxExcerpt: 5000}
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
	sharedHash := sha256.Sum256([]byte(norm))
	fingerprint := hex.EncodeToString(sharedHash[:16])
	mac := hmac.New(sha256.New, a.privateKey)
	_, _ = mac.Write([]byte(in.Repository + "\x00" + norm))
	privateFP := hex.EncodeToString(mac.Sum(nil)[:16])

	score := 5
	var evidence []model.Evidence
	for _, rule := range matched {
		score += rule.Weight
		evidence = append(evidence, model.Evidence{Kind: "rule", Description: "Matched rule " + rule.ID + ": " + rule.Summary, Weight: rule.Weight})
	}
	if in.PreviousSuccess {
		score += 15
		evidence = append(evidence, model.Evidence{Kind: "history", Description: "The same commit or workflow previously succeeded", Weight: 15})
	}
	if in.ChangeInfoAvailable && !in.WorkflowChanged && in.Repository != "" {
		score += 8
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "No workflow change was reported", Weight: 8})
	}
	if in.ChangeInfoAvailable && !in.DependencyChanged && in.Repository != "" {
		score += 8
		evidence = append(evidence, model.Evidence{Kind: "change", Description: "No dependency or lockfile change was reported", Weight: 8})
	}
	if ctx.ProviderIncident {
		score += 40
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
		evidence = append(evidence, model.Evidence{Kind: "correlation", Description: fmt.Sprintf("The same fingerprint appeared in %d repositories", ctx.CrossRepoCount), Weight: bonus})
	}
	if ctx.CrossOrgCount >= 2 {
		bonus := 10
		if ctx.CrossOrgCount >= 5 {
			bonus = 20
		}
		score += bonus
		evidence = append(evidence, model.Evidence{Kind: "correlation", Description: fmt.Sprintf("The same fingerprint appeared across %d organizations", ctx.CrossOrgCount), Weight: bonus})
	}
	if ctx.RecentOccurrences >= 5 {
		bonus := 10
		if ctx.RecentOccurrences >= 25 {
			bonus = 18
		}
		score += bonus
		evidence = append(evidence, model.Evidence{Kind: "burst", Description: fmt.Sprintf("%d matching failures occurred in the incident window", ctx.RecentOccurrences), Weight: bonus})
	}

	var changes []string
	if ctx.PreviousEnvironment != nil {
		changes = CompareEnvironment(*ctx.PreviousEnvironment, env)
		if len(changes) > 0 {
			score += 22
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
	if score > 100 {
		score = 100
	}
	if score < -100 {
		score = -100
	}

	confidence := confidenceFor(score, primary.Category)
	matchedIDs := make([]string, 0, len(matched))
	for _, m := range matched {
		matchedIDs = append(matchedIDs, m.ID)
	}
	excerpt := extractExcerpt(redacted, matched, a.maxExcerpt)

	return model.AnalysisResult{
		ID:                 newID("analysis", now, fingerprint),
		Category:           primary.Category,
		Provider:           primary.Provider,
		Operation:          primary.Operation,
		ErrorFamily:        primary.ErrorFamily,
		Confidence:         confidence,
		Score:              score,
		Fingerprint:        fingerprint,
		PrivateFingerprint: privateFP,
		Summary:            primary.Summary,
		Recommendation:     primary.Recommendation,
		Evidence:           evidence,
		RedactedExcerpt:    excerpt,
		Environment:        env,
		MatchedRules:       matchedIDs,
		CreatedAt:          now,
		CrossRepoCount:     ctx.CrossRepoCount,
		CrossOrgCount:      ctx.CrossOrgCount,
		ProviderIncident:   ctx.ProviderIncident,
		EnvironmentDrift:   len(changes) > 0,
		EnvironmentChanges: changes,
	}
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
