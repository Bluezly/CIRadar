package model

import "testing"

func TestLegacySignedScoresRemainUsable(t *testing.T) {
	code := AnalysisResult{Score: -62, NegativeScore: -62}
	if EvidenceStrengthOf(code) != 62 || CodeEvidenceScoreOf(code) != 62 || ExternalEvidenceScoreOf(code) != 0 || ExternalityScoreOf(code) != -62 {
		t.Fatalf("code scores are wrong")
	}
	external := AnalysisResult{Score: 70, PositiveScore: 70}
	if EvidenceStrengthOf(external) != 70 || ExternalEvidenceScoreOf(external) != 70 || CodeEvidenceScoreOf(external) != 0 || ExternalityScoreOf(external) != 70 {
		t.Fatalf("external scores are wrong")
	}
}

func TestExplicitEvidenceFieldsWin(t *testing.T) {
	r := AnalysisResult{Score: -10, ExternalityScore: -40, EvidenceStrength: 88, ExternalEvidenceScore: 20, CodeEvidenceScore: 88}
	if EvidenceStrengthOf(r) != 88 || ExternalityScoreOf(r) != -40 || ExternalEvidenceScoreOf(r) != 20 || CodeEvidenceScoreOf(r) != 88 {
		t.Fatalf("explicit fields were not preserved")
	}
}
