package model

func EvidenceStrengthOf(r AnalysisResult) int {
	if r.EvidenceStrength > 0 {
		return clampEvidence(r.EvidenceStrength)
	}
	external := ExternalEvidenceScoreOf(r)
	code := CodeEvidenceScoreOf(r)
	if code > external {
		return code
	}
	return external
}

func ExternalEvidenceScoreOf(r AnalysisResult) int {
	if r.ExternalEvidenceScore > 0 {
		return clampEvidence(r.ExternalEvidenceScore)
	}
	if r.PositiveScore > 0 {
		return clampEvidence(r.PositiveScore)
	}
	if r.Score > 0 {
		return clampEvidence(r.Score)
	}
	return 0
}

func CodeEvidenceScoreOf(r AnalysisResult) int {
	if r.CodeEvidenceScore > 0 {
		return clampEvidence(r.CodeEvidenceScore)
	}
	if r.NegativeScore < 0 {
		return clampEvidence(-r.NegativeScore)
	}
	if r.Score < 0 {
		return clampEvidence(-r.Score)
	}
	return 0
}

func ExternalityScoreOf(r AnalysisResult) int {
	if r.ExternalityScore != 0 {
		return r.ExternalityScore
	}
	return r.Score
}

func clampEvidence(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func NotificationEvidenceStrength(ev NotificationEvent) int {
	if ev.EvidenceStrength > 0 {
		return clampEvidence(ev.EvidenceStrength)
	}
	if ev.ExternalEvidenceScore > 0 || ev.CodeEvidenceScore > 0 {
		external := clampEvidence(ev.ExternalEvidenceScore)
		code := clampEvidence(ev.CodeEvidenceScore)
		if code > external {
			return code
		}
		return external
	}
	if ev.Score < 0 {
		return clampEvidence(-ev.Score)
	}
	return clampEvidence(ev.Score)
}

func NotificationExternalityScore(ev NotificationEvent) int {
	if ev.ExternalityScore != 0 {
		return ev.ExternalityScore
	}
	return ev.Score
}
