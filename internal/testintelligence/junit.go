package testintelligence

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
)

type Metadata struct {
	TenantID    string
	Repository  string
	Workflow    string
	Job         string
	RunID       int64
	CommitSHA   string
	Branch      string
	Framework   string
	Environment model.Environment
	OccurredAt  time.Time
}

type testCaseXML struct {
	Name      string     `xml:"name,attr"`
	ClassName string     `xml:"classname,attr"`
	Time      string     `xml:"time,attr"`
	File      string     `xml:"file,attr"`
	Failure   *resultXML `xml:"failure"`
	Error     *resultXML `xml:"error"`
	Skipped   *resultXML `xml:"skipped"`
	SystemOut string     `xml:"system-out"`
	SystemErr string     `xml:"system-err"`
}
type resultXML struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type suiteFrame struct{ Name string }

func ParseJUnit(r io.Reader, meta Metadata) ([]model.TestObservation, error) {
	if strings.TrimSpace(meta.Repository) == "" {
		return nil, errors.New("repository is required")
	}
	if meta.OccurredAt.IsZero() {
		meta.OccurredAt = time.Now().UTC()
	}
	dec := xml.NewDecoder(io.LimitReader(r, 128<<20))
	frames := []suiteFrame{}
	out := make([]model.TestObservation, 0, 128)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse JUnit XML: %w", err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			switch x.Name.Local {
			case "testsuite":
				var name string
				for _, a := range x.Attr {
					if a.Name.Local == "name" {
						name = a.Value
					}
				}
				frames = append(frames, suiteFrame{Name: name})
			case "testcase":
				if len(out) >= 100000 {
					return nil, errors.New("JUnit report exceeds 100000 test cases")
				}
				var tc testCaseXML
				if err := dec.DecodeElement(&tc, &x); err != nil {
					return nil, err
				}
				suite := ""
				if len(frames) > 0 {
					suite = frames[len(frames)-1].Name
				}
				out = append(out, toObservation(meta, suite, tc))
			}
		case xml.EndElement:
			if x.Name.Local == "testsuite" && len(frames) > 0 {
				frames = frames[:len(frames)-1]
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no test cases found in JUnit report")
	}
	return out, nil
}
func toObservation(m Metadata, suite string, t testCaseXML) model.TestObservation {
	status := "passed"
	message, details := "", ""
	if t.Failure != nil {
		status = "failed"
		message = first(t.Failure.Message, t.Failure.Type)
		details = t.Failure.Body
	}
	if t.Error != nil {
		status = "error"
		message = first(t.Error.Message, t.Error.Type)
		details = t.Error.Body
	}
	if t.Skipped != nil {
		status = "skipped"
		message = first(t.Skipped.Message, t.Skipped.Type)
		details = t.Skipped.Body
	}
	if details == "" {
		details = first(t.SystemErr, t.SystemOut)
	}
	secs, _ := strconv.ParseFloat(strings.TrimSpace(t.Time), 64)
	name, params := splitParameters(t.Name)
	return model.TestObservation{TenantID: m.TenantID, Repository: m.Repository, Workflow: m.Workflow, Job: m.Job, RunID: m.RunID, CommitSHA: m.CommitSHA, Branch: m.Branch, Framework: m.Framework, Suite: suite, ClassName: t.ClassName, Name: name, Parameters: params, Status: status, DurationMS: int64(secs * 1000), Message: truncate(message, 1000), Details: truncate(strings.TrimSpace(details), 8000), Environment: m.Environment, OccurredAt: m.OccurredAt}
}
func splitParameters(v string) (string, string) {
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "["); i > 0 && strings.HasSuffix(v, "]") {
		return strings.TrimSpace(v[:i]), v[i:]
	}
	return v, ""
}
func first(v ...string) string {
	for _, x := range v {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}
func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n] + "…"
}
