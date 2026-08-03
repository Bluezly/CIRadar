package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"ciradar/internal/model"
)

type RuleDefinition struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Provider       string   `json:"provider"`
	Operation      string   `json:"operation"`
	ErrorFamily    string   `json:"error_family"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
	Weight         int      `json:"weight"`
	Patterns       []string `json:"patterns"`
	Excludes       []string `json:"excludes,omitempty"`
}

func LoadCustomRules(dir string) ([]Rule, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var rules []Rule
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var defs []RuleDefinition
		if err := json.Unmarshal(b, &defs); err != nil {
			var single RuleDefinition
			if err2 := json.Unmarshal(b, &single); err2 != nil {
				return nil, fmt.Errorf("decode custom rule %s: %w", path, err)
			}
			defs = []RuleDefinition{single}
		}
		for idx, def := range defs {
			r, err := compileRuleDefinition(def)
			if err != nil {
				return nil, fmt.Errorf("%s rule %d: %w", path, idx+1, err)
			}
			if _, ok := seen[r.ID]; ok {
				return nil, fmt.Errorf("duplicate custom rule id %q", r.ID)
			}
			seen[r.ID] = struct{}{}
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func compileRuleDefinition(def RuleDefinition) (Rule, error) {
	if strings.TrimSpace(def.ID) == "" {
		return Rule{}, fmt.Errorf("id is required")
	}
	category := model.Category(strings.ToUpper(strings.TrimSpace(def.Category)))
	if !validCategory(category) {
		return Rule{}, fmt.Errorf("unsupported category %q", def.Category)
	}
	if len(def.Patterns) == 0 {
		return Rule{}, fmt.Errorf("at least one pattern is required")
	}
	if def.Weight < -100 || def.Weight > 100 {
		return Rule{}, fmt.Errorf("weight must be between -100 and 100")
	}
	patterns := make([]*regexp.Regexp, 0, len(def.Patterns))
	for _, pattern := range def.Patterns {
		r, err := regexp.Compile(`(?i)` + pattern)
		if err != nil {
			return Rule{}, fmt.Errorf("invalid pattern %q: %w", pattern, err)
		}
		patterns = append(patterns, r)
	}
	excludes := make([]*regexp.Regexp, 0, len(def.Excludes))
	for _, pattern := range def.Excludes {
		r, err := regexp.Compile(`(?i)` + pattern)
		if err != nil {
			return Rule{}, fmt.Errorf("invalid exclude %q: %w", pattern, err)
		}
		excludes = append(excludes, r)
	}
	return Rule{
		ID:             strings.TrimSpace(def.ID),
		Category:       category,
		Provider:       defaultString(def.Provider, "custom"),
		Operation:      defaultString(def.Operation, "unknown"),
		ErrorFamily:    defaultString(def.ErrorFamily, def.ID),
		Summary:        defaultString(def.Summary, "A custom CI Radar rule matched"),
		Recommendation: defaultString(def.Recommendation, "Review the custom rule guidance and the redacted failure excerpt."),
		Weight:         def.Weight,
		Patterns:       patterns,
		Excludes:       excludes,
	}, nil
}

func validCategory(c model.Category) bool {
	switch c {
	case model.CategoryCodeFailure, model.CategoryTestFlake, model.CategoryDependencyRegistry,
		model.CategoryNetworkFailure, model.CategoryRunnerFailure, model.CategoryRunnerImageDrift,
		model.CategoryCacheFailure, model.CategoryResourceExhaustion, model.CategoryProviderIncident,
		model.CategoryUnknown:
		return true
	default:
		return false
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}
