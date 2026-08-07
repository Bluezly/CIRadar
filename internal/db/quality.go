package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"ciradar/internal/model"
	"ciradar/internal/testintelligence"
)

func feedbackKey(tenantID, analysisID, actor string) string {
	return normalizeTenant(tenantID) + "|" + strings.TrimSpace(analysisID) + "|" + strings.ToLower(strings.TrimSpace(actor))
}

func testStatsKey(tenantID, testKey string) string  { return normalizeTenant(tenantID) + "|" + testKey }
func quarantineKey(tenantID, testKey string) string { return normalizeTenant(tenantID) + "|" + testKey }

func TestKey(o model.TestObservation) string {
	parts := []string{strings.ToLower(strings.TrimSpace(o.Repository)), strings.ToLower(strings.TrimSpace(o.Framework)), strings.TrimSpace(o.Suite), strings.TrimSpace(o.ClassName), strings.TrimSpace(o.Name), strings.TrimSpace(o.Parameters)}
	if variant := strings.ToLower(strings.TrimSpace(o.Variant)); variant != "" {
		parts = append(parts, variant)
	}
	material := strings.Join(parts, "\x00")
	h := sha256.Sum256([]byte(material))
	return hex.EncodeToString(h[:16])
}

func (s *Store) UpsertDiagnosisFeedback(ctx context.Context, f model.DiagnosisFeedback) (model.DiagnosisFeedback, error) {
	_ = ctx
	f.TenantID = normalizeTenant(f.TenantID)
	f.AnalysisID = strings.TrimSpace(f.AnalysisID)
	f.Actor = strings.TrimSpace(f.Actor)
	f.Verdict = strings.ToLower(strings.TrimSpace(f.Verdict))
	if f.AnalysisID == "" || f.Actor == "" {
		return model.DiagnosisFeedback{}, fmt.Errorf("analysis_id and actor are required")
	}
	if f.Verdict != "correct" && f.Verdict != "partial" && f.Verdict != "incorrect" {
		return model.DiagnosisFeedback{}, fmt.Errorf("verdict must be correct, partial, or incorrect")
	}
	if len(f.Comment) > 2000 {
		return model.DiagnosisFeedback{}, fmt.Errorf("comment is too long")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Analyses[f.AnalysisID]
	if !ok || normalizeTenant(rec.TenantID) != f.TenantID {
		return model.DiagnosisFeedback{}, fmt.Errorf("analysis not found")
	}
	key := feedbackKey(f.TenantID, f.AnalysisID, f.Actor)
	if old, ok := s.state.DiagnosisFeedback[key]; ok {
		f.ID = old.ID
		f.CreatedAt = old.CreatedAt
	} else {
		id, err := randomText(12)
		if err != nil {
			return model.DiagnosisFeedback{}, fmt.Errorf("generate feedback ID: %w", err)
		}
		f.ID = "feedback_" + id
		f.CreatedAt = now
	}
	f.UpdatedAt = now
	s.state.DiagnosisFeedback[key] = f
	if err := s.persistLocked(); err != nil {
		return model.DiagnosisFeedback{}, err
	}
	return f, nil
}

func (s *Store) ListDiagnosisFeedback(ctx context.Context, tenantID string, limit int) ([]model.DiagnosisFeedback, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	if limit < 1 || limit > 5000 {
		limit = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []model.DiagnosisFeedback{}
	for _, f := range s.state.DiagnosisFeedback {
		if f.TenantID == tenantID {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) FeedbackMetrics(ctx context.Context, tenantID string) (model.FeedbackMetrics, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := model.FeedbackMetrics{}
	externalTotal, externalCorrect := 0, 0
	for _, f := range s.state.DiagnosisFeedback {
		if f.TenantID != tenantID {
			continue
		}
		m.Total++
		switch f.Verdict {
		case "correct":
			m.Correct++
		case "partial":
			m.Partial++
		case "incorrect":
			m.Incorrect++
		}
		if rec, ok := s.state.Analyses[f.AnalysisID]; ok && rec.Result.Attribution == model.AttributionExternal {
			externalTotal++
			if f.Verdict == "correct" {
				externalCorrect++
			}
		}
	}
	if m.Total > 0 {
		m.PrecisionPercent = (float64(m.Correct) + 0.5*float64(m.Partial)) * 100 / float64(m.Total)
	}
	if externalTotal > 0 {
		m.ExternalPrecision = float64(externalCorrect) * 100 / float64(externalTotal)
	}
	return m, nil
}

func (s *Store) RecordTestObservations(ctx context.Context, tenantID string, observations []model.TestObservation) ([]model.TestCaseStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	observations = normalizeTestObservations(tenantID, observations)
	sort.SliceStable(observations, func(i, j int) bool {
		if observations[i].OccurredAt.Equal(observations[j].OccurredAt) {
			return observations[i].ID < observations[j].ID
		}
		return observations[i].OccurredAt.Before(observations[j].OccurredAt)
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	updated := map[string]model.TestCaseStats{}
	for _, o := range observations {
		if _, exists := s.state.TestObservations[o.ID]; exists {
			continue
		}
		key := TestKey(o)
		sk := testStatsKey(tenantID, key)
		stats := s.state.TestCaseStats[sk]
		if stats.TestKey == "" {
			stats = model.TestCaseStats{TenantID: tenantID, TestKey: key, Repository: o.Repository, Framework: o.Framework, Variant: o.Variant, Suite: o.Suite, ClassName: o.ClassName, File: o.File, Name: o.Name, Parameters: o.Parameters, FirstSeenAt: o.OccurredAt, CauseCounts: map[string]int{}}
		}
		if stats.ExecutedRuns == 0 && stats.Passes+stats.Failures > 0 {
			stats.ExecutedRuns = stats.Passes + stats.Failures
		}
		chronological := stats.LastSeenAt.IsZero() || !o.OccurredAt.Before(stats.LastSeenAt)
		executed := o.Status != "skipped"
		previousStatus := stats.LastStatus
		previousCommit := stats.LastCommitSHA
		previousRunID := stats.LastRunID
		previousDurationMS := stats.LastDurationMS
		if executed && chronological {
			if previousStatus != "" && previousStatus != o.Status && ((previousStatus == "passed" && (o.Status == "failed" || o.Status == "error")) || ((previousStatus == "failed" || previousStatus == "error") && o.Status == "passed")) {
				stats.Transitions++
			}
			if (previousStatus == "failed" || previousStatus == "error") && o.Status == "passed" && sameTestExecutionContext(previousCommit, o.CommitSHA, previousRunID, o.RunID) {
				stats.RerunRecoveries++
				stats.EstimatedComputeMinutesLost += float64(maxInt64(0, previousDurationMS)+maxInt64(0, o.DurationMS)) / 60000
			}
		}

		stats.TotalRuns++
		switch o.Status {
		case "passed":
			stats.Passes++
			stats.ExecutedRuns++
		case "skipped":
			stats.Skipped++
		default:
			stats.Failures++
			stats.ExecutedRuns++
		}
		if executed {
			stats.TotalDurationMS += maxInt64(0, o.DurationMS)
			if stats.ExecutedRuns > 0 {
				stats.AverageDurationMS = stats.TotalDurationMS / int64(stats.ExecutedRuns)
			}
		}
		if executed && chronological {
			stats.LastStatus = o.Status
			stats.LastCommitSHA = strings.TrimSpace(o.CommitSHA)
			stats.LastRunID = o.RunID
			stats.LastDurationMS = maxInt64(0, o.DurationMS)
		}
		if stats.File == "" {
			stats.File = o.File
		}
		if stats.CauseCounts == nil {
			stats.CauseCounts = map[string]int{}
		}
		if o.Status == "failed" || o.Status == "error" {
			cause, confidence := testintelligence.InferFlakeCause(o)
			stats.CauseCounts[cause]++
			if stats.PrimaryFlakeCause == "" || stats.CauseCounts[cause] >= stats.CauseCounts[stats.PrimaryFlakeCause] {
				stats.PrimaryFlakeCause = cause
				stats.CauseConfidence = confidence
			}
		}
		if o.Status == "failed" || o.Status == "error" {
			if o.PullRequestNumber > 0 {
				stats.ImpactedPullRequests = appendUniqueInt(stats.ImpactedPullRequests, o.PullRequestNumber)
				stats.PullRequestsImpacted = len(stats.ImpactedPullRequests)
			}
			if q, ok := s.state.TestQuarantines[quarantineKey(tenantID, key)]; ok && quarantineActiveAt(q, o.OccurredAt) {
				stats.QuarantinedFailures++
			}
		}
		if stats.FirstSeenAt.IsZero() || o.OccurredAt.Before(stats.FirstSeenAt) {
			stats.FirstSeenAt = o.OccurredAt
		}
		if stats.LastSeenAt.IsZero() || o.OccurredAt.After(stats.LastSeenAt) {
			stats.LastSeenAt = o.OccurredAt
		}
		stats.FailureRate = safeRatio(stats.Failures, stats.ExecutedRuns)
		stats.TransitionRate = safeRatio(stats.Transitions, maxInt(1, stats.ExecutedRuns-1))
		stats.FailureRateLow, stats.FailureRateHigh = wilsonInterval(stats.Failures, stats.ExecutedRuns, 1.96)
		stats.HistoryConfidence = clampFloat(1-math.Exp(-float64(stats.ExecutedRuns)/12), 0, 1)
		balance := 1 - math.Abs(0.5-stats.FailureRate)*2
		rawFlake := clampFloat((0.6*stats.TransitionRate+0.4*balance)*100, 0, 100)
		stats.FlakeScore = rawFlake
		stats.FlakeProbability = rawFlake * stats.HistoryConfidence
		stats.ColdStart = stats.ExecutedRuns < 10
		stats.EstimatedEngineeringMinutesLost = stats.EstimatedComputeMinutesLost + float64(stats.RerunRecoveries)*5
		switch {
		case stats.ExecutedRuns == 0:
			stats.Classification = "not_executed"
		case stats.ExecutedRuns < 5:
			stats.Classification = "warming_up"
		case stats.Failures == stats.ExecutedRuns:
			stats.Classification = "consistently_failing"
		case stats.Passes == stats.ExecutedRuns:
			stats.Classification = "stable"
		case stats.Passes > 0 && stats.Failures > 0 && rawFlake >= 35 && stats.ExecutedRuns >= 10 && stats.HistoryConfidence >= .55:
			stats.Classification = "flaky"
		case stats.Passes > 0 && stats.Failures > 0 && rawFlake >= 25:
			stats.Classification = "suspected_flaky"
		default:
			stats.Classification = "mixed"
		}
		if q, ok := s.state.TestQuarantines[quarantineKey(tenantID, key)]; ok && q.Active && q.ExpiresAt.After(time.Now().UTC()) {
			stats.Quarantined = true
			stats.QuarantineUntil = q.ExpiresAt
			stats.Owner = q.Owner
		} else {
			stats.Quarantined = false
			stats.QuarantineUntil = time.Time{}
		}
		s.state.TestObservations[o.ID] = o
		s.state.TestObservationOrder = append(s.state.TestObservationOrder, o.ID)
		s.state.TestCaseStats[sk] = stats
		updated[key] = stats
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	out := make([]model.TestCaseStats, 0, len(updated))
	for _, v := range updated {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EstimatedEngineeringMinutesLost == out[j].EstimatedEngineeringMinutesLost {
			return out[i].FlakeScore > out[j].FlakeScore
		}
		return out[i].EstimatedEngineeringMinutesLost > out[j].EstimatedEngineeringMinutesLost
	})
	return out, nil
}

func (s *Store) ListTestCaseStats(ctx context.Context, tenantID, repository, classification string, limit int) ([]model.TestCaseStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	if limit < 1 || limit > 5000 {
		limit = 200
	}
	repository = strings.ToLower(strings.TrimSpace(repository))
	classification = strings.ToLower(strings.TrimSpace(classification))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := []model.TestCaseStats{}
	for key, st := range s.state.TestCaseStats {
		if st.TenantID != tenantID {
			continue
		}
		if repository != "" && strings.ToLower(st.Repository) != repository {
			continue
		}
		if classification != "" && st.Classification != classification {
			continue
		}
		if q, ok := s.state.TestQuarantines[quarantineKey(tenantID, st.TestKey)]; ok && q.Active && q.ExpiresAt.After(now) {
			st.Quarantined = true
			st.QuarantineUntil = q.ExpiresAt
			st.Owner = q.Owner
		} else {
			st.Quarantined = false
		}
		s.state.TestCaseStats[key] = st
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Critical != out[j].Critical {
			return out[i].Critical
		}
		if out[i].EstimatedEngineeringMinutesLost != out[j].EstimatedEngineeringMinutesLost {
			return out[i].EstimatedEngineeringMinutesLost > out[j].EstimatedEngineeringMinutesLost
		}
		if out[i].PullRequestsImpacted != out[j].PullRequestsImpacted {
			return out[i].PullRequestsImpacted > out[j].PullRequestsImpacted
		}
		if out[i].FlakeScore == out[j].FlakeScore {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		return out[i].FlakeScore > out[j].FlakeScore
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) GetTestCaseStats(ctx context.Context, tenantID, testKey string) (*model.TestCaseStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	testKey = strings.TrimSpace(testKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	stats, ok := s.state.TestCaseStats[testStatsKey(tenantID, testKey)]
	if !ok {
		return nil, nil
	}
	if q, exists := s.state.TestQuarantines[quarantineKey(tenantID, testKey)]; exists && q.Active && q.ExpiresAt.After(time.Now().UTC()) {
		stats.Quarantined = true
		stats.QuarantineUntil = q.ExpiresAt
		stats.Owner = q.Owner
	} else {
		stats.Quarantined = false
		stats.QuarantineUntil = time.Time{}
	}
	return &stats, nil
}

func (s *Store) ListTestObservations(ctx context.Context, tenantID, testKey string, limit int) ([]model.TestObservation, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	testKey = strings.TrimSpace(testKey)
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.TestObservation, 0, minInt(limit, len(s.state.TestObservationOrder)))
	for i := len(s.state.TestObservationOrder) - 1; i >= 0 && len(out) < limit; i-- {
		o, ok := s.state.TestObservations[s.state.TestObservationOrder[i]]
		if !ok || o.TenantID != tenantID || TestKey(o) != testKey {
			continue
		}
		out = append(out, o)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out, nil
}

func (s *Store) SetTestCritical(ctx context.Context, tenantID, testKey string, critical bool) (*model.TestCaseStats, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	testKey = strings.TrimSpace(testKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := testStatsKey(tenantID, testKey)
	stats, ok := s.state.TestCaseStats[sk]
	if !ok {
		return nil, fmt.Errorf("test case not found")
	}
	stats.Critical = critical
	s.state.TestCaseStats[sk] = stats
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return &stats, nil
}

func (s *Store) SetTestQuarantine(ctx context.Context, q model.TestQuarantine) (model.TestQuarantine, error) {
	_ = ctx
	q.TenantID = normalizeTenant(q.TenantID)
	q.TestKey = strings.TrimSpace(q.TestKey)
	if q.TestKey == "" || q.Reason == "" || q.Owner == "" {
		return model.TestQuarantine{}, fmt.Errorf("test_key, reason, and owner are required")
	}
	now := time.Now().UTC()
	if q.ExpiresAt.IsZero() {
		q.ExpiresAt = now.Add(7 * 24 * time.Hour)
	}
	if !q.ExpiresAt.After(now) || q.ExpiresAt.After(now.Add(90*24*time.Hour)) {
		return model.TestQuarantine{}, fmt.Errorf("expires_at must be within 90 days")
	}
	q.CreatedAt = now
	q.Active = true
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := testStatsKey(q.TenantID, q.TestKey)
	if _, ok := s.state.TestCaseStats[sk]; !ok {
		return model.TestQuarantine{}, fmt.Errorf("test case not found")
	}
	s.state.TestQuarantines[quarantineKey(q.TenantID, q.TestKey)] = q
	st := s.state.TestCaseStats[sk]
	st.Quarantined = true
	st.QuarantineUntil = q.ExpiresAt
	st.Owner = q.Owner
	s.state.TestCaseStats[sk] = st
	if err := s.persistLocked(); err != nil {
		return model.TestQuarantine{}, err
	}
	return q, nil
}
func (s *Store) RemoveTestQuarantine(ctx context.Context, tenantID, testKey string) error {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.TestQuarantines, quarantineKey(tenantID, testKey))
	sk := testStatsKey(tenantID, testKey)
	if st, ok := s.state.TestCaseStats[sk]; ok {
		st.Quarantined = false
		st.QuarantineUntil = time.Time{}
		s.state.TestCaseStats[sk] = st
	}
	return s.persistLocked()
}
func (s *Store) ListTestQuarantines(ctx context.Context, tenantID string) ([]model.TestQuarantine, error) {
	_ = ctx
	tenantID = normalizeTenant(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	out := []model.TestQuarantine{}
	for k, q := range s.state.TestQuarantines {
		if q.TenantID != tenantID {
			continue
		}
		if q.Active && q.ExpiresAt.Before(now) {
			q.Active = false
			s.state.TestQuarantines[k] = q
		}
		if q.Active {
			out = append(out, q)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out, nil
}
func appendUniqueInt(values []int, value int) []int {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	sort.Ints(values)
	return values
}

func quarantineActiveAt(q model.TestQuarantine, at time.Time) bool {
	return q.Active && !at.Before(q.CreatedAt) && at.Before(q.ExpiresAt)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func clampFloat(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func normalizeTestObservations(tenantID string, observations []model.TestObservation) []model.TestObservation {
	tenantID = normalizeTenant(tenantID)
	now := time.Now().UTC()
	out := make([]model.TestObservation, 0, len(observations))
	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		observation.TenantID = tenantID
		observation.Status = strings.ToLower(strings.TrimSpace(observation.Status))
		switch observation.Status {
		case "passed", "failed", "skipped", "error":
		default:
			continue
		}
		if observation.OccurredAt.IsZero() {
			observation.OccurredAt = now
		} else {
			observation.OccurredAt = observation.OccurredAt.UTC()
		}
		if strings.TrimSpace(observation.ID) == "" {
			parts := []string{tenantID, TestKey(observation), strconv.FormatInt(observation.RunID, 10), strings.TrimSpace(observation.CommitSHA), observation.Status}
			if observation.RunID == 0 {
				parts = append(parts, observation.OccurredAt.Format(time.RFC3339Nano), strconv.FormatInt(observation.DurationMS, 10), observation.Message, observation.Details)
			}
			digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
			observation.ID = "testobs_" + hex.EncodeToString(digest[:12])
		}
		if _, duplicate := seen[observation.ID]; duplicate {
			continue
		}
		seen[observation.ID] = struct{}{}
		out = append(out, observation)
	}
	return out
}

func safeRatio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func wilsonInterval(successes, total int, z float64) (float64, float64) {
	if total <= 0 {
		return 0, 1
	}
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	denominator := 1 + z2/n
	center := (p + z2/(2*n)) / denominator
	margin := z * math.Sqrt((p*(1-p)+z2/(4*n))/n) / denominator
	return clampFloat(center-margin, 0, 1), clampFloat(center+margin, 0, 1)
}

func sameTestExecutionContext(previousCommit, currentCommit string, previousRunID, currentRunID int64) bool {
	previousCommit = strings.TrimSpace(previousCommit)
	currentCommit = strings.TrimSpace(currentCommit)
	if previousCommit != "" && currentCommit != "" {
		return previousCommit == currentCommit
	}
	return previousRunID != 0 && currentRunID != 0 && previousRunID == currentRunID
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
