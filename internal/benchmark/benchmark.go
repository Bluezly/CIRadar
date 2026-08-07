package benchmark

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ciradar/internal/analyzer"
	"ciradar/internal/model"
)

const (
	SchemaVersion              = 1
	maxDatasetBytes            = 32 << 20
	maxBenchmarkCases          = 100000
	maxBenchmarkLogLen         = 8 << 20
	maxBenchmarkResolvedLogLen = 256 << 20
)

type Source struct {
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	License string `json:"license,omitempty"`
	Version string `json:"version,omitempty"`
}

type CaseContext struct {
	CrossRepoCount      int                `json:"cross_repo_count,omitempty"`
	CrossOrgCount       int                `json:"cross_org_count,omitempty"`
	RecentOccurrences   int                `json:"recent_occurrences,omitempty"`
	ProviderIncident    bool               `json:"provider_incident,omitempty"`
	PreviousEnvironment *model.Environment `json:"previous_environment,omitempty"`
}

type Expected struct {
	Category    model.Category    `json:"category"`
	Attribution model.Attribution `json:"attribution,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	ErrorFamily string            `json:"error_family,omitempty"`
}

type Case struct {
	ID       string              `json:"id"`
	Source   string              `json:"source,omitempty"`
	Split    string              `json:"split,omitempty"`
	Tags     []string            `json:"tags,omitempty"`
	Input    model.AnalysisInput `json:"input"`
	LogFile  string              `json:"log_file,omitempty"`
	Context  CaseContext         `json:"context,omitempty"`
	Expected Expected            `json:"expected"`
}

type Dataset struct {
	SchemaVersion int      `json:"schema_version"`
	Name          string   `json:"name"`
	Version       string   `json:"version,omitempty"`
	Description   string   `json:"description,omitempty"`
	Sources       []Source `json:"sources,omitempty"`
	Cases         []Case   `json:"cases"`
}

type ClassMetrics struct {
	Label     model.Category `json:"label"`
	Support   int            `json:"support"`
	TruePos   int            `json:"true_positive"`
	FalsePos  int            `json:"false_positive"`
	FalseNeg  int            `json:"false_negative"`
	Precision float64        `json:"precision"`
	Recall    float64        `json:"recall"`
	F1        float64        `json:"f1"`
}

type CaseResult struct {
	ID                   string            `json:"id"`
	ExpectedCategory     model.Category    `json:"expected_category"`
	PredictedCategory    model.Category    `json:"predicted_category"`
	ExpectedAttribution  model.Attribution `json:"expected_attribution,omitempty"`
	PredictedAttribution model.Attribution `json:"predicted_attribution,omitempty"`
	ExpectedProvider     string            `json:"expected_provider,omitempty"`
	PredictedProvider    string            `json:"predicted_provider,omitempty"`
	ExpectedErrorFamily  string            `json:"expected_error_family,omitempty"`
	PredictedErrorFamily string            `json:"predicted_error_family,omitempty"`
	MatchedRules         []string          `json:"matched_rules,omitempty"`
}

type Report struct {
	SchemaVersion            int                       `json:"schema_version"`
	Dataset                  string                    `json:"dataset"`
	Split                    string                    `json:"split,omitempty"`
	DatasetVersion           string                    `json:"dataset_version,omitempty"`
	DatasetDigestSHA256      string                    `json:"dataset_digest_sha256"`
	AnalyzerDigestSHA256     string                    `json:"analyzer_digest_sha256"`
	Cases                    int                       `json:"cases"`
	CategoryCorrect          int                       `json:"category_correct"`
	CategoryAccuracy         float64                   `json:"category_accuracy"`
	CategoryAccuracyCI95Low  float64                   `json:"category_accuracy_ci95_low"`
	CategoryAccuracyCI95High float64                   `json:"category_accuracy_ci95_high"`
	Coverage                 float64                   `json:"coverage"`
	CoverageCI95Low          float64                   `json:"coverage_ci95_low"`
	CoverageCI95High         float64                   `json:"coverage_ci95_high"`
	UnknownRate              float64                   `json:"unknown_rate"`
	CoveredAccuracy          float64                   `json:"covered_accuracy"`
	MacroPrecision           float64                   `json:"macro_precision"`
	MacroRecall              float64                   `json:"macro_recall"`
	MacroF1                  float64                   `json:"macro_f1"`
	AttributionCases         int                       `json:"attribution_cases"`
	AttributionAccuracy      float64                   `json:"attribution_accuracy,omitempty"`
	ProviderCases            int                       `json:"provider_cases"`
	ProviderAccuracy         float64                   `json:"provider_accuracy,omitempty"`
	ErrorFamilyCases         int                       `json:"error_family_cases"`
	ErrorFamilyAccuracy      float64                   `json:"error_family_accuracy,omitempty"`
	CasesWithMatchedRules    int                       `json:"cases_with_matched_rules"`
	RuleMatchCoverage        float64                   `json:"rule_match_coverage"`
	RulesAvailable           int                       `json:"rules_available"`
	DistinctRulesMatched     int                       `json:"distinct_rules_matched"`
	RuleUtilization          float64                   `json:"rule_utilization"`
	RuleHits                 map[string]int            `json:"rule_hits,omitempty"`
	SourceCases              map[string]int            `json:"source_cases,omitempty"`
	ByCategory               []ClassMetrics            `json:"by_category"`
	Confusion                map[string]map[string]int `json:"confusion"`
	Misclassified            []CaseResult              `json:"misclassified,omitempty"`
}

type Thresholds struct {
	MinimumCases              int
	MinimumCategoryAccuracy   float64
	MinimumMacroF1            float64
	MinimumCoverage           float64
	MaximumUnknownRate        float64
	MaximumUnknownRateEnabled bool
}

func Load(path string) (Dataset, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Dataset{}, errors.New("benchmark dataset path is required")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return Dataset{}, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxDatasetBytes+1))
	if err != nil {
		return Dataset{}, err
	}
	if len(body) > maxDatasetBytes {
		return Dataset{}, fmt.Errorf("benchmark dataset manifest exceeds %d bytes", maxDatasetBytes)
	}
	var ds Dataset
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ds); err != nil {
		return Dataset{}, fmt.Errorf("decode benchmark dataset: %w", err)
	}
	if err := ensureSingleJSONValue(dec); err != nil {
		return Dataset{}, err
	}
	if err := validateDataset(&ds); err != nil {
		return Dataset{}, err
	}
	base := filepath.Dir(path)
	totalLogBytes := int64(0)
	for i := range ds.Cases {
		c := &ds.Cases[i]
		if strings.TrimSpace(c.LogFile) == "" {
			totalLogBytes, err = consumeBenchmarkLogBudget(totalLogBytes, int64(len(c.Input.Log)))
			if err != nil {
				return Dataset{}, err
			}
			continue
		}
		if strings.TrimSpace(c.Input.Log) != "" {
			return Dataset{}, fmt.Errorf("benchmark case %q has both input.log and log_file", c.ID)
		}
		logPath, err := datasetPath(base, c.LogFile)
		if err != nil {
			return Dataset{}, fmt.Errorf("benchmark case %q: %w", c.ID, err)
		}
		logBody, err := readLimited(logPath, maxBenchmarkLogLen)
		if err != nil {
			return Dataset{}, fmt.Errorf("benchmark case %q log: %w", c.ID, err)
		}
		totalLogBytes, err = consumeBenchmarkLogBudget(totalLogBytes, int64(len(logBody)))
		if err != nil {
			return Dataset{}, err
		}
		c.Input.Log = string(logBody)
	}
	for _, c := range ds.Cases {
		if strings.TrimSpace(c.Input.Log) == "" {
			return Dataset{}, fmt.Errorf("benchmark case %q has no log content", c.ID)
		}
	}
	return ds, nil
}

func Select(ds Dataset, split string) (Dataset, error) {
	split = strings.ToLower(strings.TrimSpace(split))
	if split == "" || split == "all" {
		return ds, nil
	}
	out := ds
	out.Cases = nil
	for _, c := range ds.Cases {
		if strings.EqualFold(strings.TrimSpace(c.Split), split) {
			out.Cases = append(out.Cases, c)
		}
	}
	if len(out.Cases) == 0 {
		return Dataset{}, fmt.Errorf("benchmark dataset has no cases in split %q", split)
	}
	return out, nil
}

func Evaluate(a *analyzer.Analyzer, ds Dataset) Report {
	if a == nil {
		panic("benchmark analyzer is nil")
	}
	report := Report{
		SchemaVersion:        SchemaVersion,
		Dataset:              ds.Name,
		DatasetVersion:       ds.Version,
		DatasetDigestSHA256:  Digest(ds),
		AnalyzerDigestSHA256: a.ConfigurationDigest(),
		Cases:                len(ds.Cases),
		Confusion:            map[string]map[string]int{},
		RuleHits:             map[string]int{},
		SourceCases:          map[string]int{},
	}
	report.Split = commonSplit(ds.Cases)
	report.RulesAvailable = len(a.RuleIDs())
	labels := map[model.Category]struct{}{}
	unknown := 0
	covered := 0
	coveredCorrect := 0
	attributionCorrect := 0
	providerCorrect := 0
	errorFamilyCorrect := 0
	for _, c := range ds.Cases {
		if source := strings.TrimSpace(c.Source); source != "" {
			report.SourceCases[source]++
		}
		ctx := analyzer.Context{
			CrossRepoCount:      c.Context.CrossRepoCount,
			CrossOrgCount:       c.Context.CrossOrgCount,
			RecentOccurrences:   c.Context.RecentOccurrences,
			ProviderIncident:    c.Context.ProviderIncident,
			PreviousEnvironment: c.Context.PreviousEnvironment,
		}
		result := a.Analyze(c.Input, ctx)
		expected := c.Expected.Category
		predicted := result.Category
		labels[expected] = struct{}{}
		labels[predicted] = struct{}{}
		if len(result.MatchedRules) > 0 {
			report.CasesWithMatchedRules++
			seenRules := map[string]struct{}{}
			for _, rule := range result.MatchedRules {
				rule = strings.TrimSpace(rule)
				if rule == "" {
					continue
				}
				if _, seen := seenRules[rule]; seen {
					continue
				}
				seenRules[rule] = struct{}{}
				report.RuleHits[rule]++
			}
		}
		if report.Confusion[string(expected)] == nil {
			report.Confusion[string(expected)] = map[string]int{}
		}
		report.Confusion[string(expected)][string(predicted)]++
		categoryCorrect := predicted == expected
		if categoryCorrect {
			report.CategoryCorrect++
		}
		if predicted == model.CategoryUnknown {
			unknown++
		} else {
			covered++
			if categoryCorrect {
				coveredCorrect++
			}
		}
		caseWrong := !categoryCorrect
		if c.Expected.Attribution != "" {
			report.AttributionCases++
			if result.Attribution == c.Expected.Attribution {
				attributionCorrect++
			} else {
				caseWrong = true
			}
		}
		if strings.TrimSpace(c.Expected.Provider) != "" {
			report.ProviderCases++
			if equalText(result.Provider, c.Expected.Provider) {
				providerCorrect++
			} else {
				caseWrong = true
			}
		}
		if strings.TrimSpace(c.Expected.ErrorFamily) != "" {
			report.ErrorFamilyCases++
			if equalText(result.ErrorFamily, c.Expected.ErrorFamily) {
				errorFamilyCorrect++
			} else {
				caseWrong = true
			}
		}
		if caseWrong {
			report.Misclassified = append(report.Misclassified, CaseResult{
				ID:                   c.ID,
				ExpectedCategory:     expected,
				PredictedCategory:    predicted,
				ExpectedAttribution:  c.Expected.Attribution,
				PredictedAttribution: result.Attribution,
				ExpectedProvider:     c.Expected.Provider,
				PredictedProvider:    result.Provider,
				ExpectedErrorFamily:  c.Expected.ErrorFamily,
				PredictedErrorFamily: result.ErrorFamily,
				MatchedRules:         append([]string(nil), result.MatchedRules...),
			})
		}
	}
	if report.Cases > 0 {
		report.CategoryAccuracy = float64(report.CategoryCorrect) / float64(report.Cases)
		report.CategoryAccuracyCI95Low, report.CategoryAccuracyCI95High = wilson95(report.CategoryCorrect, report.Cases)
		report.Coverage = float64(covered) / float64(report.Cases)
		report.CoverageCI95Low, report.CoverageCI95High = wilson95(covered, report.Cases)
		report.UnknownRate = float64(unknown) / float64(report.Cases)
		report.RuleMatchCoverage = float64(report.CasesWithMatchedRules) / float64(report.Cases)
	}
	report.DistinctRulesMatched = len(report.RuleHits)
	if report.RulesAvailable > 0 {
		report.RuleUtilization = float64(report.DistinctRulesMatched) / float64(report.RulesAvailable)
	}
	if covered > 0 {
		report.CoveredAccuracy = float64(coveredCorrect) / float64(covered)
	}
	if report.AttributionCases > 0 {
		report.AttributionAccuracy = float64(attributionCorrect) / float64(report.AttributionCases)
	}
	if report.ProviderCases > 0 {
		report.ProviderAccuracy = float64(providerCorrect) / float64(report.ProviderCases)
	}
	if report.ErrorFamilyCases > 0 {
		report.ErrorFamilyAccuracy = float64(errorFamilyCorrect) / float64(report.ErrorFamilyCases)
	}
	report.ByCategory = categoryMetrics(labels, report.Confusion)
	for _, m := range report.ByCategory {
		report.MacroPrecision += m.Precision
		report.MacroRecall += m.Recall
		report.MacroF1 += m.F1
	}
	if len(report.ByCategory) > 0 {
		n := float64(len(report.ByCategory))
		report.MacroPrecision /= n
		report.MacroRecall /= n
		report.MacroF1 /= n
	}
	sort.Slice(report.Misclassified, func(i, j int) bool { return report.Misclassified[i].ID < report.Misclassified[j].ID })
	return report
}

func CheckThresholds(report Report, thresholds Thresholds) error {
	if thresholds.MinimumCases < 0 {
		return errors.New("minimum cases cannot be negative")
	}
	for name, value := range map[string]float64{
		"minimum category accuracy": thresholds.MinimumCategoryAccuracy,
		"minimum macro F1":          thresholds.MinimumMacroF1,
		"minimum coverage":          thresholds.MinimumCoverage,
	} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return fmt.Errorf("%s must be a finite value between 0 and 1", name)
		}
	}
	if math.IsNaN(thresholds.MaximumUnknownRate) || math.IsInf(thresholds.MaximumUnknownRate, 0) || thresholds.MaximumUnknownRate < 0 || thresholds.MaximumUnknownRate > 1 {
		return errors.New("maximum unknown rate must be a finite value between 0 and 1")
	}
	var failures []string
	if thresholds.MinimumCases > 0 && report.Cases < thresholds.MinimumCases {
		failures = append(failures, fmt.Sprintf("case count %d is below %d", report.Cases, thresholds.MinimumCases))
	}
	if thresholds.MinimumCategoryAccuracy > 0 && report.CategoryAccuracy < thresholds.MinimumCategoryAccuracy {
		failures = append(failures, fmt.Sprintf("category accuracy %.4f is below %.4f", report.CategoryAccuracy, thresholds.MinimumCategoryAccuracy))
	}
	if thresholds.MinimumMacroF1 > 0 && report.MacroF1 < thresholds.MinimumMacroF1 {
		failures = append(failures, fmt.Sprintf("macro F1 %.4f is below %.4f", report.MacroF1, thresholds.MinimumMacroF1))
	}
	if thresholds.MinimumCoverage > 0 && report.Coverage < thresholds.MinimumCoverage {
		failures = append(failures, fmt.Sprintf("coverage %.4f is below %.4f", report.Coverage, thresholds.MinimumCoverage))
	}
	if (thresholds.MaximumUnknownRateEnabled || thresholds.MaximumUnknownRate > 0) && report.UnknownRate > thresholds.MaximumUnknownRate {
		failures = append(failures, fmt.Sprintf("unknown rate %.4f exceeds %.4f", report.UnknownRate, thresholds.MaximumUnknownRate))
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func Digest(ds Dataset) string {
	copyDataset := ds
	copyDataset.Cases = append([]Case(nil), ds.Cases...)
	for i := range copyDataset.Cases {
		copyDataset.Cases[i].LogFile = ""
	}
	body, err := json.Marshal(copyDataset)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func validateDataset(ds *Dataset) error {
	if ds.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported benchmark schema_version %d; expected %d", ds.SchemaVersion, SchemaVersion)
	}
	ds.Name = strings.TrimSpace(ds.Name)
	if ds.Name == "" {
		return errors.New("benchmark dataset name is required")
	}
	if len(ds.Cases) == 0 {
		return errors.New("benchmark dataset has no cases")
	}
	if len(ds.Cases) > maxBenchmarkCases {
		return fmt.Errorf("benchmark dataset has %d cases; maximum is %d", len(ds.Cases), maxBenchmarkCases)
	}
	declaredSources := map[string]struct{}{}
	for i := range ds.Sources {
		source := &ds.Sources[i]
		source.Name = strings.TrimSpace(source.Name)
		source.URL = strings.TrimSpace(source.URL)
		source.License = strings.TrimSpace(source.License)
		source.Version = strings.TrimSpace(source.Version)
		if source.Name == "" {
			return fmt.Errorf("benchmark source %d has no name", i+1)
		}
		if _, exists := declaredSources[source.Name]; exists {
			return fmt.Errorf("duplicate benchmark source %q", source.Name)
		}
		declaredSources[source.Name] = struct{}{}
	}
	seen := map[string]struct{}{}
	for i := range ds.Cases {
		c := &ds.Cases[i]
		c.ID = strings.TrimSpace(c.ID)
		if c.ID == "" {
			return fmt.Errorf("benchmark case %d has no id", i+1)
		}
		if _, exists := seen[c.ID]; exists {
			return fmt.Errorf("duplicate benchmark case id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		c.Source = strings.TrimSpace(c.Source)
		if c.Source != "" {
			if _, exists := declaredSources[c.Source]; !exists {
				return fmt.Errorf("benchmark case %q references undeclared source %q", c.ID, c.Source)
			}
		}
		c.Split = strings.ToLower(strings.TrimSpace(c.Split))
		if c.Split != "" && c.Split != "train" && c.Split != "dev" && c.Split != "test" {
			return fmt.Errorf("benchmark case %q has invalid split %q", c.ID, c.Split)
		}
		if !validCategory(c.Expected.Category) {
			return fmt.Errorf("benchmark case %q has invalid expected category %q", c.ID, c.Expected.Category)
		}
		if c.Expected.Attribution != "" && !validAttribution(c.Expected.Attribution) {
			return fmt.Errorf("benchmark case %q has invalid expected attribution %q", c.ID, c.Expected.Attribution)
		}
		if len(c.Input.Log) > maxBenchmarkLogLen {
			return fmt.Errorf("benchmark case %q inline log exceeds %d bytes", c.ID, maxBenchmarkLogLen)
		}
	}
	return nil
}

func categoryMetrics(labels map[model.Category]struct{}, confusion map[string]map[string]int) []ClassMetrics {
	ordered := make([]model.Category, 0, len(labels))
	for label := range labels {
		if label == model.CategoryUnknown {
			continue
		}
		ordered = append(ordered, label)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	out := make([]ClassMetrics, 0, len(ordered))
	for _, label := range ordered {
		m := ClassMetrics{Label: label}
		for expected, row := range confusion {
			for predicted, n := range row {
				if expected == string(label) {
					m.Support += n
				}
				if expected == string(label) && predicted == string(label) {
					m.TruePos += n
				} else if expected != string(label) && predicted == string(label) {
					m.FalsePos += n
				} else if expected == string(label) && predicted != string(label) {
					m.FalseNeg += n
				}
			}
		}
		m.Precision = ratio(m.TruePos, m.TruePos+m.FalsePos)
		m.Recall = ratio(m.TruePos, m.TruePos+m.FalseNeg)
		if m.Precision+m.Recall > 0 {
			m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
		}
		out = append(out, m)
	}
	return out
}

func wilson95(successes, total int) (float64, float64) {
	if total <= 0 {
		return 0, 0
	}
	const z = 1.959963984540054
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	denominator := 1 + z2/n
	center := (p + z2/(2*n)) / denominator
	margin := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / denominator
	low := center - margin
	high := center + margin
	if low < 0 {
		low = 0
	}
	if high > 1 {
		high = 1
	}
	return low, high
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func equalText(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func commonSplit(cases []Case) string {
	if len(cases) == 0 {
		return ""
	}
	value := strings.ToLower(strings.TrimSpace(cases[0].Split))
	if value == "" {
		return ""
	}
	for _, c := range cases[1:] {
		if strings.ToLower(strings.TrimSpace(c.Split)) != value {
			return ""
		}
	}
	return value
}

func validCategory(v model.Category) bool {
	switch v {
	case model.CategoryCodeFailure,
		model.CategoryTestFlake,
		model.CategoryDependencyRegistry,
		model.CategoryNetworkFailure,
		model.CategoryRunnerFailure,
		model.CategoryRunnerImageDrift,
		model.CategoryCacheFailure,
		model.CategoryResourceExhaustion,
		model.CategoryProviderIncident,
		model.CategoryConcurrencyConflict,
		model.CategoryToolchainFailure,
		model.CategoryUnknown:
		return true
	default:
		return false
	}
}

func validAttribution(v model.Attribution) bool {
	switch v {
	case model.AttributionExternal, model.AttributionCode, model.AttributionMixed, model.AttributionToolchain, model.AttributionUnknown:
		return true
	default:
		return false
	}
}

func ensureSingleJSONValue(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode benchmark dataset trailing content: %w", err)
	}
	return errors.New("benchmark dataset contains multiple JSON values")
}

func datasetPath(base, rel string) (string, error) {
	rel = filepath.Clean(strings.TrimSpace(rel))
	if rel == "." || filepath.IsAbs(rel) {
		return "", errors.New("log_file must be a relative path inside the dataset directory")
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(filepath.Join(baseAbs, rel))
	if err != nil {
		return "", err
	}
	inside, err := filepath.Rel(baseAbs, fullAbs)
	if err != nil {
		return "", err
	}
	if inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", errors.New("log_file escapes the dataset directory")
	}
	baseReal, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return "", err
	}
	fullReal, err := filepath.EvalSymlinks(fullAbs)
	if err != nil {
		return "", err
	}
	inside, err = filepath.Rel(baseReal, fullReal)
	if err != nil {
		return "", err
	}
	if inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", errors.New("log_file resolves outside the dataset directory")
	}
	return fullReal, nil
}

func consumeBenchmarkLogBudget(current, added int64) (int64, error) {
	if current < 0 || added < 0 || added > maxBenchmarkResolvedLogLen-current {
		return current, fmt.Errorf("benchmark resolved logs exceed %d bytes", maxBenchmarkResolvedLogLen)
	}
	return current + added, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return body, nil
}
