package testintelligence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"ciradar/internal/model"
)

func ParseReport(format string, r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "", "junit", "xml":
		return ParseJUnit(r, meta)
	case "playwright", "playwright-json":
		return parsePlaywright(r, meta)
	case "jest", "jest-json":
		return parseJest(r, meta)
	case "pytest", "pytest-json", "pytest-json-report":
		return parsePytest(r, meta)
	case "cypress", "cypress-json", "mocha", "mocha-json":
		return parseCypress(r, meta)
	default:
		return nil, fmt.Errorf("unsupported test report format %q", format)
	}
}

func normalizeMeta(meta Metadata, framework string) (Metadata, error) {
	if strings.TrimSpace(meta.Repository) == "" {
		return meta, errors.New("repository is required")
	}
	if meta.OccurredAt.IsZero() {
		meta.OccurredAt = time.Now().UTC()
	}
	if meta.Framework == "" {
		meta.Framework = framework
	}
	return meta, nil
}

func observation(meta Metadata, suite, className, file, name, status string, durationMS int64, message, details string) model.TestObservation {
	base, params := splitParameters(name)
	return model.TestObservation{TenantID: meta.TenantID, Repository: meta.Repository, Workflow: meta.Workflow, Job: meta.Job, RunID: meta.RunID, CommitSHA: meta.CommitSHA, Branch: meta.Branch, Framework: meta.Framework, Suite: suite, ClassName: className, File: filepath.ToSlash(file), Name: base, Parameters: params, Status: normalizeTestStatus(status), DurationMS: durationMS, Message: truncate(strings.TrimSpace(message), 1000), Details: truncate(strings.TrimSpace(details), 8000), Environment: meta.Environment, OccurredAt: meta.OccurredAt}
}

func normalizeTestStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "passed", "pass", "success", "expected":
		return "passed"
	case "failed", "failure", "fail", "unexpected", "timedout", "timed_out":
		return "failed"
	case "error", "broken":
		return "error"
	case "skipped", "skip", "pending", "disabled", "todo", "flaky":
		return "skipped"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func parsePlaywright(r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	meta, err := normalizeMeta(meta, "playwright")
	if err != nil {
		return nil, err
	}
	var root struct {
		Suites []playwrightSuite `json:"suites"`
		Errors []struct {
			Message string `json:"message"`
			Stack   string `json:"stack"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 128<<20)).Decode(&root); err != nil {
		return nil, err
	}
	out := []model.TestObservation{}
	var walk func(playwrightSuite, []string)
	walk = func(s playwrightSuite, parents []string) {
		path := append(append([]string{}, parents...), s.Title)
		for _, sp := range s.Specs {
			for _, t := range sp.Tests {
				status := t.Status
				var duration int64
				var msgs []string
				for _, rr := range t.Results {
					duration += rr.Duration
					if rr.Error.Message != "" {
						msgs = append(msgs, rr.Error.Message)
					}
					if rr.Error.Stack != "" {
						msgs = append(msgs, rr.Error.Stack)
					}
				}
				out = append(out, observation(meta, strings.Join(nonEmpty(path), " / "), t.ProjectName, firstNonEmptyLocal(sp.File, s.File), sp.Title, status, duration, strings.Join(msgs, "\n"), strings.Join(msgs, "\n")))
			}
		}
		for _, child := range s.Suites {
			walk(child, path)
		}
	}
	for _, s := range root.Suites {
		walk(s, nil)
	}
	if len(out) == 0 {
		return nil, errors.New("no test cases found in Playwright report")
	}
	return out, nil
}

type playwrightSuite struct {
	Title  string            `json:"title"`
	File   string            `json:"file"`
	Suites []playwrightSuite `json:"suites"`
	Specs  []struct {
		Title string `json:"title"`
		File  string `json:"file"`
		Tests []struct {
			Status      string `json:"status"`
			ProjectName string `json:"projectName"`
			Results     []struct {
				Duration int64 `json:"duration"`
				Error    struct {
					Message string `json:"message"`
					Stack   string `json:"stack"`
				} `json:"error"`
			} `json:"results"`
		} `json:"tests"`
	} `json:"specs"`
}

func parseJest(r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	meta, err := normalizeMeta(meta, "jest")
	if err != nil {
		return nil, err
	}
	var root struct {
		TestResults []struct {
			Name             string `json:"name"`
			Message          string `json:"message"`
			AssertionResults []struct {
				AncestorTitles  []string `json:"ancestorTitles"`
				FullName        string   `json:"fullName"`
				Title           string   `json:"title"`
				Status          string   `json:"status"`
				Duration        *int64   `json:"duration"`
				FailureMessages []string `json:"failureMessages"`
			} `json:"assertionResults"`
		} `json:"testResults"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 128<<20)).Decode(&root); err != nil {
		return nil, err
	}
	out := []model.TestObservation{}
	for _, f := range root.TestResults {
		for _, a := range f.AssertionResults {
			d := int64(0)
			if a.Duration != nil {
				d = *a.Duration
			}
			name := firstNonEmptyLocal(a.Title, a.FullName)
			out = append(out, observation(meta, strings.Join(a.AncestorTitles, " / "), "", f.Name, name, a.Status, d, strings.Join(a.FailureMessages, "\n"), strings.Join(a.FailureMessages, "\n")))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no test cases found in Jest report")
	}
	return out, nil
}

func parsePytest(r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	meta, err := normalizeMeta(meta, "pytest")
	if err != nil {
		return nil, err
	}
	var root struct {
		Tests []struct {
			NodeID   string  `json:"nodeid"`
			Outcome  string  `json:"outcome"`
			Duration float64 `json:"duration"`
			Call     struct {
				Duration float64 `json:"duration"`
				Crash    struct {
					Message string `json:"message"`
					Path    string `json:"path"`
					LineNo  int    `json:"lineno"`
				} `json:"crash"`
				LongRepr string `json:"longrepr"`
			} `json:"call"`
			Setup struct {
				LongRepr string `json:"longrepr"`
			} `json:"setup"`
			Teardown struct {
				LongRepr string `json:"longrepr"`
			} `json:"teardown"`
		} `json:"tests"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 128<<20)).Decode(&root); err != nil {
		return nil, err
	}
	out := []model.TestObservation{}
	for _, t := range root.Tests {
		parts := strings.Split(t.NodeID, "::")
		file := ""
		name := t.NodeID
		suite := ""
		if len(parts) > 0 {
			file = parts[0]
		}
		if len(parts) > 1 {
			name = parts[len(parts)-1]
			suite = strings.Join(parts[1:len(parts)-1], " / ")
		}
		dur := t.Duration
		if t.Call.Duration > 0 {
			dur = t.Call.Duration
		}
		details := firstNonEmptyLocal(t.Call.LongRepr, t.Setup.LongRepr)
		details = firstNonEmptyLocal(details, t.Teardown.LongRepr)
		out = append(out, observation(meta, suite, "", file, name, t.Outcome, int64(dur*1000), t.Call.Crash.Message, details))
	}
	if len(out) == 0 {
		return nil, errors.New("no test cases found in pytest report")
	}
	return out, nil
}

func parseCypress(r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	meta, err := normalizeMeta(meta, "cypress")
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := json.NewDecoder(io.LimitReader(r, 128<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	var cy struct {
		Results []struct {
			Spec struct {
				Name     string `json:"name"`
				Relative string `json:"relative"`
			} `json:"spec"`
			Tests []struct {
				Title        []string `json:"title"`
				State        string   `json:"state"`
				DisplayError string   `json:"displayError"`
				Attempts     []struct {
					State string `json:"state"`
					Error struct {
						Message string `json:"message"`
						Stack   string `json:"stack"`
					} `json:"error"`
					Timings struct {
						Duration int64 `json:"duration"`
					} `json:"timings"`
				} `json:"attempts"`
			} `json:"tests"`
		} `json:"results"`
	}
	if json.Unmarshal(raw, &cy) == nil && len(cy.Results) > 0 {
		out := []model.TestObservation{}
		for _, run := range cy.Results {
			for _, t := range run.Tests {
				name := ""
				suite := ""
				if len(t.Title) > 0 {
					name = t.Title[len(t.Title)-1]
					suite = strings.Join(t.Title[:len(t.Title)-1], " / ")
				}
				var d int64
				var errs []string
				state := t.State
				for _, a := range t.Attempts {
					d += a.Timings.Duration
					if a.State != "" {
						state = a.State
					}
					errs = append(errs, a.Error.Message, a.Error.Stack)
				}
				out = append(out, observation(meta, suite, "", firstNonEmptyLocal(run.Spec.Relative, run.Spec.Name), name, state, d, firstNonEmptyLocal(t.DisplayError, strings.Join(nonEmpty(errs), "\n")), strings.Join(nonEmpty(errs), "\n")))
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	var mocha struct {
		Tests    []mochaTest `json:"tests"`
		Passes   []mochaTest `json:"passes"`
		Failures []mochaTest `json:"failures"`
		Pending  []mochaTest `json:"pending"`
	}
	if err := json.Unmarshal(raw, &mocha); err != nil {
		return nil, err
	}
	out := []model.TestObservation{}
	add := func(items []mochaTest, status string) {
		for _, t := range items {
			st := status
			if t.State != "" {
				st = t.State
			}
			out = append(out, observation(meta, t.FullTitle, "", t.File, firstNonEmptyLocal(t.Title, t.FullTitle), st, t.Duration, t.Err.Message, firstNonEmptyLocal(t.Err.Stack, t.Err.Message)))
		}
	}
	if len(mocha.Tests) > 0 {
		add(mocha.Tests, "")
	} else {
		add(mocha.Passes, "passed")
		add(mocha.Failures, "failed")
		add(mocha.Pending, "skipped")
	}
	if len(out) == 0 {
		return nil, errors.New("no test cases found in Cypress/Mocha report")
	}
	return out, nil
}

type mochaTest struct {
	Title     string `json:"title"`
	FullTitle string `json:"fullTitle"`
	File      string `json:"file"`
	State     string `json:"state"`
	Duration  int64  `json:"duration"`
	Err       struct {
		Message string `json:"message"`
		Stack   string `json:"stack"`
	} `json:"err"`
}

func InferFlakeCause(o model.TestObservation) (string, float64) {
	v := strings.ToLower(strings.Join([]string{o.Message, o.Details, o.Name, o.File}, "\n"))
	patterns := []struct {
		cause string
		terms []string
	}{
		{"selector", []string{"selector", "element not found", "locator", "detached from dom", "stale element", "not visible", "strict mode violation"}},
		{"timing", []string{"timeout", "timed out", "deadline exceeded", "waitfor", "eventually", "race condition", "too slow"}},
		{"network", []string{"econnreset", "socket hang up", "connection refused", "dns", "name resolution", "network", "http 502", "http 503", "http 504"}},
		{"environment", []string{"works locally", "runner", "browser version", "timezone", "locale", "display", "xvfb", "certificate", "architecture"}},
		{"resource", []string{"out of memory", "oom", "no space left", "cannot allocate memory", "too many open files", "cpu"}},
		{"order_state", []string{"test order", "shared state", "database locked", "already exists", "leftover", "cleanup", "global state", "random seed"}},
		{"concurrency", []string{"deadlock", "concurrent", "parallel", "mutex", "lock timeout", "data race"}},
		{"data", []string{"fixture", "seed data", "snapshot mismatch", "generated data", "random data"}},
	}
	best, score := "unknown", 0
	for _, p := range patterns {
		n := 0
		for _, term := range p.terms {
			if strings.Contains(v, term) {
				n++
			}
		}
		if n > score {
			best = p.cause
			score = n
		}
	}
	if score == 0 {
		return best, 0
	}
	confidence := 0.45 + float64(score-1)*0.15
	if confidence > 0.95 {
		confidence = 0.95
	}
	return best, confidence
}

func nonEmpty(v []string) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		if strings.TrimSpace(x) != "" {
			out = append(out, x)
		}
	}
	return out
}
func firstNonEmptyLocal(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
