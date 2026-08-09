package analyzer

import (
	"strings"

	"github.com/Bluezly/CIRadar/internal/model"
)

type staticcheckRuleGroup struct {
	family         string
	recommendation string
	codes          []string
}

type staticcheckRuleOverride struct {
	family         string
	summary        string
	recommendation string
	weight         int
}

func catalogStaticcheckRules() []catalogRuleSpec {
	groups := []staticcheckRuleGroup{
		{family: "stdlib-misuse", recommendation: "Correct the standard-library API misuse identified by Staticcheck and rerun the same check.", codes: []string{
			"SA1000", "SA1001", "SA1002", "SA1003", "SA1004", "SA1005", "SA1006", "SA1007", "SA1008",
			"SA1010", "SA1011", "SA1012", "SA1013", "SA1014", "SA1015", "SA1016", "SA1017", "SA1018", "SA1019",
			"SA1020", "SA1021", "SA1023", "SA1024", "SA1025", "SA1026", "SA1027", "SA1028", "SA1029", "SA1030", "SA1031", "SA1032",
		}},
		{family: "concurrency-bug", recommendation: "Correct the synchronization or goroutine misuse identified by Staticcheck before retrying CI.", codes: []string{
			"SA2000", "SA2001", "SA2002", "SA2003",
		}},
		{family: "test-bug", recommendation: "Correct the test or benchmark misuse identified by Staticcheck and rerun the affected test package.", codes: []string{
			"SA3000", "SA3001",
		}},
		{family: "ineffective-code", recommendation: "Remove or correct the ineffective code path identified by Staticcheck, then rerun static analysis.", codes: []string{
			"SA4000", "SA4001", "SA4003", "SA4004", "SA4005", "SA4006", "SA4008", "SA4009", "SA4010", "SA4011", "SA4012",
			"SA4013", "SA4014", "SA4015", "SA4016", "SA4017", "SA4018", "SA4019", "SA4020", "SA4021", "SA4022", "SA4023",
			"SA4024", "SA4025", "SA4026", "SA4027", "SA4028", "SA4029", "SA4030", "SA4031", "SA4032",
		}},
		{family: "correctness-bug", recommendation: "Fix the correctness issue identified by Staticcheck before rerunning CI.", codes: []string{
			"SA5000", "SA5001", "SA5002", "SA5003", "SA5004", "SA5005", "SA5007", "SA5008", "SA5009", "SA5010", "SA5012",
		}},
		{family: "performance-issue", recommendation: "Apply the targeted performance fix suggested by Staticcheck and confirm behavior remains unchanged.", codes: []string{
			"SA6000", "SA6001", "SA6002", "SA6003", "SA6005", "SA6006",
		}},
		{family: "suspicious-code", recommendation: "Review and correct the suspicious construct identified by Staticcheck rather than suppressing it without justification.", codes: []string{
			"SA9001", "SA9002", "SA9003", "SA9004", "SA9005", "SA9006", "SA9007", "SA9008", "SA9009", "SA9010",
		}},
		{family: "code-simplification", recommendation: "Apply the simplification reported by Staticcheck or document a deliberate exception in project lint policy.", codes: []string{
			"S1000", "S1001", "S1002", "S1003", "S1004", "S1005", "S1006", "S1007", "S1008", "S1009", "S1010", "S1011", "S1012",
			"S1016", "S1017", "S1018", "S1019", "S1020", "S1021", "S1023", "S1024", "S1025", "S1028", "S1029", "S1030", "S1031",
			"S1032", "S1033", "S1034", "S1035", "S1036", "S1037", "S1038", "S1039", "S1040",
		}},
		{family: "style-issue", recommendation: "Fix the style issue reported by Staticcheck or explicitly configure the project style policy.", codes: []string{
			"ST1000", "ST1001", "ST1003", "ST1005", "ST1006", "ST1008", "ST1011", "ST1012", "ST1013", "ST1015", "ST1016", "ST1017", "ST1018", "ST1019", "ST1020", "ST1021", "ST1022", "ST1023",
		}},
		{family: "quickfix", recommendation: "Apply or review the Staticcheck quick-fix refactoring and rerun the same check.", codes: []string{
			"QF1001", "QF1002", "QF1003", "QF1004", "QF1005", "QF1006", "QF1007", "QF1008", "QF1009", "QF1010", "QF1011", "QF1012",
		}},
		{family: "unused-code", recommendation: "Remove the unused declaration or make its intended use explicit; account for build tags before suppressing U1000.", codes: []string{
			"U1000",
		}},
	}

	overrides := map[string]staticcheckRuleOverride{
		"SA1000": {family: "invalid-regular-expression", summary: "Staticcheck SA1000 detected an invalid regular expression"},
		"SA1001": {family: "invalid-template", summary: "Staticcheck SA1001 detected an invalid template"},
		"SA1002": {family: "invalid-time-format", summary: "Staticcheck SA1002 detected an invalid time.Parse layout"},
		"SA1005": {family: "invalid-exec-command", summary: "Staticcheck SA1005 detected an invalid exec.Command invocation"},
		"SA1006": {family: "printf-format", summary: "Staticcheck SA1006 detected a dynamic Printf format misuse"},
		"SA1007": {family: "invalid-url", summary: "Staticcheck SA1007 detected an invalid URL"},
		"SA1012": {family: "nil-context", summary: "Staticcheck SA1012 detected a nil context.Context argument"},
		"SA1015": {family: "ticker-leak", summary: "Staticcheck SA1015 detected a time.Tick resource leak pattern"},
		"SA1019": {family: "deprecated-api", summary: "Staticcheck SA1019 detected use of a deprecated API"},
		"SA1027": {family: "atomic-alignment", summary: "Staticcheck SA1027 detected an unsafe 64-bit atomic alignment"},
		"SA1029": {family: "context-key", summary: "Staticcheck SA1029 detected an inappropriate context.WithValue key"},
		"SA1032": {family: "errors-is-order", summary: "Staticcheck SA1032 detected reversed errors.Is arguments"},
		"SA2000": {family: "waitgroup-race", summary: "Staticcheck SA2000 detected WaitGroup.Add inside a goroutine"},
		"SA2001": {family: "empty-critical-section", summary: "Staticcheck SA2001 detected an empty critical section"},
		"SA2002": {family: "test-control-in-goroutine", summary: "Staticcheck SA2002 detected test termination from a goroutine"},
		"SA2003": {family: "deferred-lock", summary: "Staticcheck SA2003 detected a deferred Lock where Unlock was likely intended"},
		"SA3000": {family: "testmain-exit", summary: "Staticcheck SA3000 detected TestMain that can hide test failures"},
		"SA4006": {family: "unused-assignment", summary: "Staticcheck SA4006 detected a value overwritten before it was read"},
		"SA4010": {family: "discarded-append", summary: "Staticcheck SA4010 detected an append result that is never observed"},
		"SA4011": {family: "ineffective-break", summary: "Staticcheck SA4011 detected a break statement with no effect"},
		"SA4017": {family: "ignored-pure-result", summary: "Staticcheck SA4017 detected a discarded result from a side-effect-free function"},
		"SA4020": {family: "unreachable-type-switch-case", summary: "Staticcheck SA4020 detected an unreachable type-switch case"},
		"SA4023": {family: "impossible-nil-comparison", summary: "Staticcheck SA4023 detected an impossible interface comparison with nil"},
		"SA4032": {family: "impossible-platform-comparison", summary: "Staticcheck SA4032 detected an impossible GOOS or GOARCH comparison"},
		"SA5000": {family: "nil-map-assignment", summary: "Staticcheck SA5000 detected assignment to a nil map"},
		"SA5001": {family: "defer-close-before-error-check", summary: "Staticcheck SA5001 detected Close being deferred before checking the open error"},
		"SA5002": {family: "busy-loop", summary: "Staticcheck SA5002 detected an empty loop that can spin"},
		"SA5003": {family: "defer-in-infinite-loop", summary: "Staticcheck SA5003 detected a defer that cannot run inside an infinite loop"},
		"SA5004": {family: "busy-select-loop", summary: "Staticcheck SA5004 detected a select loop that can spin"},
		"SA5005": {family: "finalizer-reference-cycle", summary: "Staticcheck SA5005 detected a finalizer retaining the finalized object"},
		"SA5007": {family: "infinite-recursion", summary: "Staticcheck SA5007 detected an infinite recursive call"},
		"SA5008": {family: "invalid-struct-tag", summary: "Staticcheck SA5008 detected an invalid struct tag"},
		"SA5009": {family: "printf-format", summary: "Staticcheck SA5009 detected an invalid Printf call"},
		"SA5010": {family: "impossible-type-assertion", summary: "Staticcheck SA5010 detected an impossible type assertion"},
		"SA5012": {family: "invalid-slice-size", summary: "Staticcheck SA5012 detected an odd-sized slice passed to an even-size API"},
		"SA6000": {family: "regexp-in-loop", summary: "Staticcheck SA6000 detected repeated regular-expression compilation in a loop"},
		"SA6002": {family: "sync-pool-allocation", summary: "Staticcheck SA6002 detected allocation-prone values stored in sync.Pool"},
		"SA9003": {family: "empty-branch", summary: "Staticcheck SA9003 detected an empty conditional branch"},
		"SA9007": {family: "dangerous-directory-delete", summary: "Staticcheck SA9007 detected deletion of a directory that should not be removed"},
		"SA9009": {family: "ineffective-go-directive", summary: "Staticcheck SA9009 detected an ineffectual Go compiler directive"},
		"S1039":  {family: "unnecessary-fmt-sprint", summary: "Staticcheck S1039 detected an unnecessary fmt.Sprint"},
		"ST1005": {family: "error-string-style", summary: "Staticcheck ST1005 detected an incorrectly formatted error string"},
		"ST1018": {family: "zero-width-character", summary: "Staticcheck ST1018 detected zero-width or control characters in a string literal"},
		"U1000":  {family: "unused-code", summary: "Staticcheck U1000 detected unused code", weight: -94},
	}

	rules := make([]catalogRuleSpec, 0, 161)
	for _, group := range groups {
		for _, code := range group.codes {
			family := group.family
			summary := "Staticcheck " + code + " reported a " + strings.ReplaceAll(group.family, "-", " ") + " diagnostic"
			recommendation := group.recommendation
			weight := -86
			if override, ok := overrides[code]; ok {
				if override.family != "" {
					family = override.family
				}
				if override.summary != "" {
					summary = override.summary
				}
				if override.recommendation != "" {
					recommendation = override.recommendation
				}
				if override.weight != 0 {
					weight = override.weight
				}
			}
			rules = append(rules, catalogRuleSpec{
				id:             "staticcheck-" + strings.ToLower(code),
				category:       model.CategoryCodeFailure,
				provider:       "Staticcheck",
				operation:      "static-analysis",
				errorFamily:    family,
				weight:         weight,
				signalGroup:    "static-analysis",
				summary:        summary,
				recommendation: recommendation,
				pattern:        `(?m)^[^\n]*\.go:\d+:\d+:[^\n]*\(` + code + `\)|^\s*\(\d+,\s*\d+\)\s+` + code + `\s+[^\n]+$`,
			})
		}
	}
	return rules
}
