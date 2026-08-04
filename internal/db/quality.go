package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"ciradar/internal/model"
)

func feedbackKey(tenantID, analysisID, actor string) string {
	return normalizeTenant(tenantID) + "|" + strings.TrimSpace(analysisID) + "|" + strings.ToLower(strings.TrimSpace(actor))
}

func testStatsKey(tenantID, testKey string) string  { return normalizeTenant(tenantID) + "|" + testKey }
func quarantineKey(tenantID, testKey string) string { return normalizeTenant(tenantID) + "|" + testKey }

func TestKey(o model.TestObservation) string {
	material := strings.Join([]string{strings.ToLower(strings.TrimSpace(o.Repository)), strings.ToLower(strings.TrimSpace(o.Framework)), strings.TrimSpace(o.Suite), strings.TrimSpace(o.ClassName), strings.TrimSpace(o.Name), strings.TrimSpace(o.Parameters)}, "\x00")
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
		id, _ := randomText(12)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := map[string]model.TestCaseStats{}
	for _, o := range observations {
		o.TenantID = tenantID
		o.Status = strings.ToLower(strings.TrimSpace(o.Status))
		if o.Status != "passed" && o.Status != "failed" && o.Status != "skipped" && o.Status != "error" {
			continue
		}
		if o.OccurredAt.IsZero() {
			o.OccurredAt = time.Now().UTC()
		}
		if o.ID == "" {
			id, _ := randomText(12)
			o.ID = "testobs_" + id
		}
		key := TestKey(o)
		sk := testStatsKey(tenantID, key)
		stats := s.state.TestCaseStats[sk]
		if stats.TestKey == "" {
			stats = model.TestCaseStats{TenantID: tenantID, TestKey: key, Repository: o.Repository, Framework: o.Framework, Suite: o.Suite, ClassName: o.ClassName, Name: o.Name, Parameters: o.Parameters, FirstSeenAt: o.OccurredAt}
		}
		if stats.LastStatus != "" && stats.LastStatus != o.Status && ((stats.LastStatus == "passed" && (o.Status == "failed" || o.Status == "error")) || ((stats.LastStatus == "failed" || stats.LastStatus == "error") && o.Status == "passed")) {
			stats.Transitions++
		}
		stats.TotalRuns++
		switch o.Status {
		case "passed":
			stats.Passes++
		case "skipped":
			stats.Skipped++
		default:
			stats.Failures++
		}
		stats.LastStatus = o.Status
		stats.LastSeenAt = o.OccurredAt
		if stats.TotalRuns >= 2 {
			failureRate := float64(stats.Failures) / float64(stats.TotalRuns)
			transitionRate := float64(stats.Transitions) / float64(maxInt(1, stats.TotalRuns-1))
			stats.FlakeScore = clampFloat((0.55*transitionRate+0.45*(1-absFloat(0.5-failureRate)*2))*100, 0, 100)
		}
		switch {
		case stats.TotalRuns < 3:
			stats.Classification = "insufficient_history"
		case stats.Passes > 0 && stats.Failures > 0 && stats.FlakeScore >= 35:
			stats.Classification = "flaky"
		case stats.Failures == stats.TotalRuns:
			stats.Classification = "consistently_failing"
		case stats.Passes == stats.TotalRuns:
			stats.Classification = "stable"
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
	sort.Slice(out, func(i, j int) bool { return out[i].FlakeScore > out[j].FlakeScore })
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
		if out[i].Quarantined != out[j].Quarantined {
			return out[i].Quarantined
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
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
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
