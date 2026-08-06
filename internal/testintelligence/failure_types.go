package testintelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"ciradar/internal/model"
)

var (
	failureANSI       = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	failureTimestamp  = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b`)
	failureHex        = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{8,}\b`)
	failureUUID       = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b`)
	failureNumber     = regexp.MustCompile(`\b\d{3,}\b`)
	failureLineNumber = regexp.MustCompile(`([A-Za-z0-9_./\\-]+):\d+(?::\d+)?`)
	failureSpace      = regexp.MustCompile(`\s+`)
)

func GroupFailureTypes(observations []model.TestObservation, limit int) []model.TestFailureType {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	grouped := map[string]model.TestFailureType{}
	for _, observation := range observations {
		if observation.Status != "failed" && observation.Status != "error" {
			continue
		}
		message := firstFailureLine(observation.Message, observation.Details)
		normalized := normalizeFailureText(message)
		if normalized == "" {
			normalized = "failure without message"
		}
		digest := sha256.Sum256([]byte(normalized))
		signature := hex.EncodeToString(digest[:8])
		entry := grouped[signature]
		if entry.Signature == "" {
			entry = model.TestFailureType{
				Signature:      signature,
				Message:        message,
				FirstSeenAt:    observation.OccurredAt,
				LastSeenAt:     observation.OccurredAt,
				ExampleDetails: truncateFailureDetails(observation.Details, 1200),
			}
		}
		entry.Count++
		if entry.FirstSeenAt.IsZero() || observation.OccurredAt.Before(entry.FirstSeenAt) {
			entry.FirstSeenAt = observation.OccurredAt
		}
		if entry.LastSeenAt.IsZero() || observation.OccurredAt.After(entry.LastSeenAt) {
			entry.LastSeenAt = observation.OccurredAt
			entry.Message = message
			entry.ExampleDetails = truncateFailureDetails(observation.Details, 1200)
		}
		grouped[signature] = entry
	}
	out := make([]model.TestFailureType, 0, len(grouped))
	for _, entry := range grouped {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func firstFailureLine(values ...string) string {
	for _, value := range values {
		value = failureANSI.ReplaceAllString(value, "")
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				return truncateFailureDetails(line, 320)
			}
		}
	}
	return "Failure without message"
}

func normalizeFailureText(value string) string {
	value = strings.ToLower(failureANSI.ReplaceAllString(value, ""))
	value = failureTimestamp.ReplaceAllString(value, "<time>")
	value = failureUUID.ReplaceAllString(value, "<uuid>")
	value = failureLineNumber.ReplaceAllString(value, "$1:<line>")
	value = failureHex.ReplaceAllString(value, "<hex>")
	value = failureNumber.ReplaceAllString(value, "<number>")
	return strings.TrimSpace(failureSpace.ReplaceAllString(value, " "))
}

func truncateFailureDetails(value string, limit int) string {
	value = strings.TrimSpace(failureANSI.ReplaceAllString(value, ""))
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func FailureTypeWindow(observations []model.TestObservation) (time.Time, time.Time) {
	var first, last time.Time
	for _, observation := range observations {
		if first.IsZero() || observation.OccurredAt.Before(first) {
			first = observation.OccurredAt
		}
		if last.IsZero() || observation.OccurredAt.After(last) {
			last = observation.OccurredAt
		}
	}
	return first, last
}
