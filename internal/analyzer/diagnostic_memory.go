package analyzer

import (
	"strings"
	"sync"
	"time"

	"ciradar/internal/model"
)

type diagnosticMemoryEntry struct {
	category       model.Category
	attribution    model.Attribution
	provider       string
	errorFamily    string
	summary        string
	recommendation string
	authoritative  bool
	expiresAt      time.Time
	updatedAt      time.Time
}

type diagnosticMemory struct {
	mu           sync.Mutex
	entries      map[string]map[string]diagnosticMemoryEntry
	ttl          time.Duration
	maxPerTenant int
	now          func() time.Time
}

func newDiagnosticMemory() *diagnosticMemory {
	return &diagnosticMemory{entries: make(map[string]map[string]diagnosticMemoryEntry), ttl: 24 * time.Hour, maxPerTenant: 1024, now: time.Now}
}

func (m *diagnosticMemory) get(tenant, fingerprint string) (diagnosticMemoryEntry, bool) {
	if m == nil || strings.TrimSpace(fingerprint) == "" {
		return diagnosticMemoryEntry{}, false
	}
	tenant = tenantID(tenant)
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.entries[tenant]
	entry, ok := bucket[fingerprint]
	if !ok {
		return diagnosticMemoryEntry{}, false
	}
	if !entry.expiresAt.After(now) {
		delete(bucket, fingerprint)
		if len(bucket) == 0 {
			delete(m.entries, tenant)
		}
		return diagnosticMemoryEntry{}, false
	}
	return entry, true
}

func (m *diagnosticMemory) put(tenant, fingerprint string, entry diagnosticMemoryEntry) {
	if m == nil || strings.TrimSpace(fingerprint) == "" {
		return
	}
	tenant = tenantID(tenant)
	now := m.now().UTC()
	entry.updatedAt = now
	entry.expiresAt = now.Add(m.ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.entries[tenant]
	if bucket == nil {
		bucket = make(map[string]diagnosticMemoryEntry)
		m.entries[tenant] = bucket
	}
	for key, current := range bucket {
		if !current.expiresAt.After(now) {
			delete(bucket, key)
		}
	}
	if current, ok := bucket[fingerprint]; ok && current.authoritative && !entry.authoritative {
		current.expiresAt = entry.expiresAt
		current.updatedAt = now
		bucket[fingerprint] = current
		return
	}
	if len(bucket) >= m.maxPerTenant {
		oldestKey := ""
		var oldest time.Time
		for key, current := range bucket {
			if oldestKey == "" || current.updatedAt.Before(oldest) {
				oldestKey = key
				oldest = current.updatedAt
			}
		}
		if oldestKey != "" {
			delete(bucket, oldestKey)
		}
	}
	bucket[fingerprint] = entry
}

func (a *Analyzer) AnalyzeWithMemory(in model.AnalysisInput, ctx Context) model.AnalysisResult {
	result := a.Analyze(in, ctx)
	if a == nil || a.memory == nil {
		return result
	}
	if entry, ok := a.memory.get(result.TenantID, result.Fingerprint); ok && (entry.authoritative || result.Category == model.CategoryUnknown || result.Confidence == model.ConfidenceInsufficient) {
		result = applyDiagnosticMemory(result, entry)
	}
	if result.Category != model.CategoryUnknown && result.Confidence != model.ConfidenceInsufficient {
		a.memory.put(result.TenantID, result.Fingerprint, diagnosticMemoryEntry{category: result.Category, attribution: result.Attribution, provider: result.Provider, errorFamily: result.ErrorFamily, summary: result.Summary, recommendation: result.Recommendation})
	}
	return result
}

func (a *Analyzer) RememberFeedback(analysis model.AnalysisResult, feedback model.DiagnosisFeedback) {
	if a == nil || a.memory == nil || strings.TrimSpace(analysis.Fingerprint) == "" {
		return
	}
	verdict := strings.ToLower(strings.TrimSpace(feedback.Verdict))
	hasGroundTruth := feedback.ActualCategory != "" || feedback.ActualCause != "" || strings.TrimSpace(feedback.ActualProvider) != "" || strings.TrimSpace(feedback.ActualErrorFamily) != ""
	if verdict == "incorrect" && !hasGroundTruth {
		return
	}
	if verdict != "correct" && !hasGroundTruth {
		return
	}
	entry := diagnosticMemoryEntry{category: analysis.Category, attribution: analysis.Attribution, provider: analysis.Provider, errorFamily: analysis.ErrorFamily, summary: analysis.Summary, recommendation: analysis.Recommendation, authoritative: true}
	if feedback.ActualCategory != "" {
		entry.category = feedback.ActualCategory
	}
	if feedback.ActualCause != "" {
		entry.attribution = feedback.ActualCause
	}
	if strings.TrimSpace(feedback.ActualProvider) != "" {
		entry.provider = strings.TrimSpace(feedback.ActualProvider)
	}
	if strings.TrimSpace(feedback.ActualErrorFamily) != "" {
		entry.errorFamily = strings.TrimSpace(feedback.ActualErrorFamily)
	}
	if verdict != "correct" {
		entry.summary = "A recent tenant-confirmed diagnosis was recalled for the same failure fingerprint"
		entry.recommendation = "Use the confirmed tenant diagnosis and verify the same root cause before applying a change."
	}
	a.memory.put(analysis.TenantID, analysis.Fingerprint, entry)
}

func applyDiagnosticMemory(result model.AnalysisResult, entry diagnosticMemoryEntry) model.AnalysisResult {
	if entry.category != "" {
		result.Category = entry.category
	}
	if entry.attribution != "" {
		result.Attribution = entry.attribution
	}
	if entry.provider != "" {
		result.Provider = entry.provider
	}
	if entry.errorFamily != "" {
		result.ErrorFamily = entry.errorFamily
	}
	if entry.summary != "" {
		result.Summary = entry.summary
	}
	if entry.recommendation != "" {
		result.Recommendation = entry.recommendation
	}
	if result.Confidence == model.ConfidenceInsufficient {
		result.Confidence = model.ConfidenceModerate
	}
	result.Evidence = append(result.Evidence, model.Evidence{Kind: "tenant-memory", Description: "Recalled a recent tenant-isolated diagnosis for this fingerprint", Weight: 0})
	if result.DecisionReason == "" {
		result.DecisionReason = "A recent diagnosis for the same fingerprint was recalled from tenant-isolated memory."
	} else {
		result.DecisionReason += " A recent tenant-isolated diagnosis for the same fingerprint was also recalled."
	}
	return result
}
